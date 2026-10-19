"""Reaching a destination: directly or through upstream proxies, then TLS if the route says so.

Upstream proxies come from a proxylib ``ProxyMap`` (the route's ``upstream``,
else the server's ``egress``). Its answers are tried in order, so a PAC
result such as ``PROXY a:3128; DIRECT`` fails over. HTTP and HTTPS proxies
are supported (``CONNECT``, Basic credentials from the proxy URL).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from netimps import get_default_port, join_host

from ._connection import Connection
from ._credential import Credential
from ._route import Action, Route
from ._streams import close_stream, start_tls
from .exceptions import UpstreamError

__all__ = ["UpstreamStream", "connect", "resolve_upstream"]

_log = logging.getLogger("netproxy")

# proxylib promises thread safety for PAC scripts but not for the OS
# resolvers (WinHTTP, CFNetwork, libproxy), so lookups take turns.
_LOOKUP_LOCK = threading.Lock()

# RFC 8305's recommended delay before racing the next address: a name such as
# "localhost" with an unused ::1 would otherwise wait for that attempt to fail
# (about 2 s on Windows, which retries refused loopback connections).
_HAPPY_EYEBALLS = 0.25


@dataclass
class UpstreamStream:
    """An open connection to a destination."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    via: Optional[str]
    """``host:port`` of the upstream proxy used, or ``None`` for direct."""
    tls: bool
    """Whether the proxy made a TLS connection to the destination."""
    forward: bool = False
    """The stream reaches an upstream HTTP proxy without a tunnel: send it
    absolute-form requests (``forward_http=True`` and a proxy answer)."""
    proxy_authorization: Optional[str] = field(default=None, repr=False)
    """``Proxy-Authorization`` value for a ``forward`` stream, from the proxy
    URL's credentials."""


def _as_proxymap(upstream: Any) -> Any:
    if isinstance(upstream, str):
        from proxylib import ProxyMap

        return ProxyMap(upstream)  # a proxy URL, a PAC result or a PAC location
    return upstream


def _lookup(proxymap: Any, url: str) -> List[Any]:
    from proxylib import lookup

    with _LOOKUP_LOCK:
        try:
            return list(lookup(proxymap, url))
        except KeyError:  # no opinion
            return [None]


async def resolve_upstream(
    connection: Connection, route: Route, egress: Any = None
) -> List[Any]:
    """The upstream answers to try for ``connection``: proxylib ``Proxy``
    objects and ``None`` (direct), in order."""
    source = route.upstream if route.upstream is not None else egress
    if source is None:
        return [None]
    proxymap = _as_proxymap(source)
    return await asyncio.to_thread(_lookup, proxymap, connection.url)


def _describe(proxy: Any) -> str:
    # Never the credentials: only scheme, host and port.
    return f"{proxy.scheme}://{join_host(proxy.host, proxy.port)}"


async def _open_direct(
    connection: Connection, timeout: float
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(
        asyncio.open_connection(
            connection.host, connection.port, happy_eyeballs_delay=_HAPPY_EYEBALLS
        ),
        timeout,
    )


def _authorization(proxy: Any) -> Optional[str]:
    if not proxy.username:
        return None
    token = f"{proxy.username}:{proxy.password or ''}".encode()
    return f"Basic {base64.b64encode(token).decode()}"


async def _open_proxy(
    proxy: Any, timeout: float
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    scheme = (proxy.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise UpstreamError(f"{scheme} upstream proxies are not supported")
    proxy_tls = ssl.create_default_context() if scheme == "https" else None
    return await asyncio.wait_for(
        asyncio.open_connection(
            proxy.host,
            proxy.port or get_default_port(scheme),
            ssl=proxy_tls,
            server_hostname=proxy.host if proxy_tls else None,
            happy_eyeballs_delay=_HAPPY_EYEBALLS,
        ),
        timeout,
    )


async def _open_via_proxy(
    connection: Connection, proxy: Any, timeout: float
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await _open_proxy(proxy, timeout)
    try:
        head = [
            f"CONNECT {connection.authority} HTTP/1.1",
            f"Host: {connection.authority}",
        ]
        authorization = _authorization(proxy)
        if authorization:
            head.append(f"Proxy-Authorization: {authorization}")
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        status_line = response.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].startswith("2"):
            raise UpstreamError(
                f"{_describe(proxy)} refused CONNECT {connection.authority}: {status_line}"
            )
    except BaseException:
        await close_stream(writer)
        raise
    return reader, writer


async def _client_context(route: Route) -> ssl.SSLContext:
    if isinstance(route.tls, ssl.SSLContext):
        return route.tls
    assert isinstance(route.tls, Credential)
    return await asyncio.to_thread(route.tls.context)


async def connect(
    connection: Connection,
    route: Route,
    *,
    egress: Any = None,
    timeout: float = 30.0,
    forward_http: bool = False,
    keylog: Optional[str] = None,
) -> UpstreamStream:
    """Open the connection ``route`` describes to ``connection``'s destination.

    Raises :class:`~netproxy.exceptions.UpstreamError` when no upstream
    answer works (the message lists each attempt, never proxy credentials)
    and :class:`~netproxy.exceptions.CredentialUnavailableError` when a TLS
    route's credential cannot be loaded. A REJECT route is a ``ValueError``:
    the caller should not have asked.

    ``forward_http=True`` (a plain ``http://`` request being forwarded) makes
    a proxy answer return a stream to the proxy itself, flagged ``forward``,
    instead of a CONNECT tunnel: proxies commonly refuse CONNECT to port 80.
    ``keylog`` is set as the TLS context's ``keylog_filename``.
    """
    if route.action is Action.REJECT:
        raise ValueError("a REJECT route opens no connection")
    context = await _client_context(route) if route.action is Action.TLS else None
    if context is not None and keylog is not None:
        context.keylog_filename = keylog
    failures = []
    for answer in await resolve_upstream(connection, route, egress):
        where = "direct" if answer is None else _describe(answer)
        try:
            if answer is None:
                reader, writer = await _open_direct(connection, timeout)
            elif forward_http and context is None:
                reader, writer = await _open_proxy(answer, timeout)
                return UpstreamStream(
                    reader,
                    writer,
                    _describe(answer),
                    False,
                    forward=True,
                    proxy_authorization=_authorization(answer),
                )
            else:
                reader, writer = await _open_via_proxy(connection, answer, timeout)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            failures.append(f"{where}: {error or type(error).__name__}")
            _log.debug(
                "netproxy: %s via %s failed: %s", connection.authority, where, error
            )
            continue
        if context is not None:
            try:
                await start_tls(
                    reader,
                    writer,
                    context,
                    server_hostname=connection.host,
                    timeout=timeout,
                )
            except (OSError, ssl.SSLError, asyncio.TimeoutError) as error:
                await close_stream(writer)
                raise UpstreamError(
                    f"TLS to {connection.authority} via {where} failed: {error}"
                ) from error
        return UpstreamStream(
            reader,
            writer,
            None if answer is None else _describe(answer),
            context is not None,
        )
    raise UpstreamError(f"cannot reach {connection.authority}: " + "; ".join(failures))
