"""TLS interception: the proxy ends the client's TLS with a certificate it mints.

A CONNECT whose route is :attr:`~netproxy.Action.TLS` is intercepted: the
proxy connects to the destination first (with the route's client credential),
answers ``200``, then completes the client's handshake with a leaf issued by
its CA for the CONNECT host, and relays the plaintext between the two TLS
connections. Clients must trust the CA (:attr:`CertificateAuthority.certificate`).

Create the CA with :func:`create_ca` so it is name-constrained to exactly the
hosts the TLS rules intercept: a leaked key then cannot vouch for anything
else.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import threading
from collections import OrderedDict
from typing import Any, List, Optional

from sslcontext import create_context
from sslcontext.issuing import CertificateAuthority

from ._connection import Connection
from ._route import Action, Route, Router
from ._streams import close_stream, start_tls
from .exceptions import NetProxyError
from .rules import AllOf, AnyOf, Host, Network

__all__ = ["Interceptor", "create_ca", "permitted_names"]

_log = logging.getLogger("netproxy")


class Interceptor:
    """Server-side TLS for intercepted hosts, from ``ca``.

    Leaves (one per host, valid ``leaf_days``) are cached, at most
    ``cache_size`` of them, least recently used first out.
    """

    def __init__(
        self, ca: CertificateAuthority, *, cache_size: int = 256, leaf_days: float = 7
    ) -> None:
        if not isinstance(ca, CertificateAuthority):
            raise TypeError("ca must be an sslcontext.issuing.CertificateAuthority")
        self.ca = ca
        self.cache_size = cache_size
        self.leaf_days = leaf_days
        self.keylog: Optional[str] = None
        """Where minted contexts log TLS secrets (set by the server's ``keylog``)."""
        self._contexts: "OrderedDict[str, ssl.SSLContext]" = OrderedDict()
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"Interceptor({self.ca!r})"

    def server_context(self, host: str) -> ssl.SSLContext:
        """The context presenting a leaf for ``host`` (minted on first use)."""
        with self._lock:
            context = self._contexts.get(host)
            if context is not None:
                self._contexts.move_to_end(host)
                return context
        context = create_context("server")
        context.set_alpn_protocols(["http/1.1"])
        if self.keylog is not None:
            context.keylog_filename = self.keylog
        self.ca.issue([host], days=self.leaf_days).load_into(context)
        with self._lock:
            self._contexts[host] = context
            while len(self._contexts) > self.cache_size:
                self._contexts.popitem(last=False)
        return context

    async def intercept(
        self,
        server: Any,
        connection: Connection,
        route: Route,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Serve one intercepted CONNECT (the request head already read)."""
        from ._http import _fail, _respond

        try:
            upstream = await server.open_upstream(connection, route)
        except (NetProxyError, OSError, asyncio.TimeoutError) as error:
            await _fail(writer, error, connection.authority)
            return
        try:
            if reader._buffer:  # type: ignore[attr-defined]
                # Bytes sent before our 200 would bypass the TLS handshake.
                await _respond(writer, 400, "Bad Request", "data sent before 200\n")
                return
            context = await asyncio.to_thread(self.server_context, connection.host)
            # The client sends its ClientHello as soon as it reads the 200; stop
            # reading plaintext first, or it lands in the stream's buffer where
            # the TLS layer never sees it.
            writer.transport.pause_reading()
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await start_tls(
                reader, writer, context, server_side=True, timeout=server.timeout
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as error:
            _log.info(
                "netproxy: client TLS for %s failed: %s", connection.authority, error
            )
            await close_stream(upstream.writer)
            return
        await server.relay_session(connection, route, reader, writer, upstream)


def _names(matcher: Any) -> Optional[List[str]]:
    if isinstance(matcher, Host):
        return list(matcher.patterns)
    if isinstance(matcher, Network):
        return [str(n) for n in matcher.networks]
    if isinstance(matcher, AnyOf):
        parts = [_names(m) for m in matcher.matchers]
        if any(p is None for p in parts):
            return None
        return [n for part in parts for n in part]  # type: ignore[union-attr]
    if isinstance(matcher, AllOf):
        # Every branch must hold, so any one bounding branch bounds the rule.
        for part in matcher.matchers:
            names = _names(part)
            if names is not None:
                return names
    return None


def permitted_names(router: Router) -> Optional[List[str]]:
    """The hosts and networks ``router``'s TLS routes can intercept, or
    ``None`` when some TLS rule (or the default) is not bounded by
    ``Host``/``Network`` matchers and no name constraint can cover it."""
    if router.default.action is Action.TLS:
        return None
    names: List[str] = []
    for rule in router.rules:
        if rule.route.action is not Action.TLS:
            continue
        found = _names(rule.match)
        if found is None:
            return None
        names += [n for n in found if n not in names]
    return names


def create_ca(
    router: Router,
    common_name: str = "netproxy local CA",
    *,
    days: float = 3650,
    constrain: bool = True,
) -> CertificateAuthority:
    """A new CA for intercepting ``router``'s TLS routes.

    With ``constrain`` (the default) it is name-constrained to
    :func:`permitted_names`; when the rules cannot be bounded that way this
    raises ``ValueError`` rather than create an unconstrained CA. Pass
    ``constrain=False`` to accept an unconstrained one knowingly.
    """
    permitted: List[str] = []
    if constrain:
        names = permitted_names(router)
        if names is None:
            raise ValueError(
                "some TLS rule is not bounded by Host/Network matchers, so the CA "
                "cannot be name-constrained; pass constrain=False to accept that"
            )
        permitted = [n.lstrip(".") if n.startswith(".") else n for n in names]
    return CertificateAuthority.create(common_name, permitted=permitted, days=days)
