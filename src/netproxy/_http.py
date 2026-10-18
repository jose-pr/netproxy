"""The HTTP proxy front-end: CONNECT, forwarded requests, and the PAC file.

One request per client connection for forwarded HTTP: the proxy answers with
``Connection: close``, so clients open a new connection per request. Request
and response bodies are relayed as bytes, never parsed.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from netimps import get_default_port, join_host, split_host

from ._connection import Connection
from ._relay import relay
from ._route import Action, Route
from .exceptions import CredentialUnavailableError, NetProxyError
from .upstream import connect

__all__ = ["LISTENER", "handle_http_proxy"]

_log = logging.getLogger("netproxy")

LISTENER = "proxy"
"""The listener name connections through the HTTP proxy carry."""

_CRLF = b"\r\n"
_HEAD_END = b"\r\n\r\n"
# Hop-by-hop headers (RFC 9110 section 7.6.1) plus the proxy-only ones; the
# names a Connection header lists are dropped as well.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
}


class _Head:
    """A request or response head: first line and ordered headers."""

    def __init__(self, raw: bytes) -> None:
        lines = raw[: -len(_HEAD_END)].decode("latin-1").split("\r\n")
        self.first = lines[0]
        self.headers: List[Tuple[str, str]] = []
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if not sep or not name or name != name.strip():
                raise ValueError("malformed header line")
            self.headers.append((name, value.strip()))

    def get(self, name: str) -> Optional[str]:
        name = name.lower()
        return next((v for n, v in self.headers if n.lower() == name), None)

    def end_to_end(self) -> List[Tuple[str, str]]:
        listed = {
            token.strip().lower()
            for value in (self.get("connection") or "").split(",")
            for token in [value]
            if token.strip()
        }
        return [
            (n, v)
            for n, v in self.headers
            if n.lower() not in _HOP_BY_HOP and n.lower() not in listed
        ]


def _encode(first: str, headers: List[Tuple[str, str]]) -> bytes:
    lines = [first] + [f"{name}: {value}" for name, value in headers]
    return "\r\n".join(lines).encode("latin-1") + _HEAD_END


async def _respond(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    body: str = "",
    content_type: str = "text/plain; charset=utf-8",
) -> None:
    payload = body.encode("utf-8")
    writer.write(
        _encode(
            f"HTTP/1.1 {status} {reason}",
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(payload))),
                ("Connection", "close"),
            ],
        )
        + payload
    )
    try:
        await writer.drain()
    except OSError:
        pass


async def _read_head(reader: asyncio.StreamReader, timeout: float) -> Optional[_Head]:
    try:
        raw = await asyncio.wait_for(reader.readuntil(_HEAD_END), timeout)
    except asyncio.IncompleteReadError:
        return None
    return _Head(raw)


def _peer(writer: asyncio.StreamWriter) -> Optional[Tuple[str, int]]:
    peer = writer.get_extra_info("peername")
    return (peer[0], peer[1]) if peer else None


async def _fail(
    writer: asyncio.StreamWriter, error: BaseException, target: str
) -> None:
    if isinstance(error, asyncio.TimeoutError):
        await _respond(writer, 504, "Gateway Timeout", f"timed out reaching {target}\n")
    elif isinstance(error, CredentialUnavailableError):
        await _respond(
            writer, 502, "Bad Gateway", f"client credential unavailable: {error}\n"
        )
    else:
        await _respond(writer, 502, "Bad Gateway", f"{error}\n")


async def handle_http_proxy(
    server: Any, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Serve one client connection of the HTTP proxy listener."""
    try:
        head = await _read_head(reader, server.timeout)
    except (asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError):
        await _respond(writer, 400, "Bad Request", "malformed request head\n")
        return
    if head is None:
        return
    parts = head.first.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        await _respond(writer, 400, "Bad Request", "malformed request line\n")
        return
    method, target, version = parts
    if method.upper() == "CONNECT":
        await _connect(server, reader, writer, target)
    elif target.startswith("/"):
        await _local(server, writer, method, target)
    else:
        await _forward(server, reader, writer, head, method, target, version)


# ------------------------------------------------------------------ CONNECT


async def _connect(
    server: Any, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str
) -> None:
    try:
        host, port = split_host(target, default_port=443)
        connection = Connection(
            str(host), int(port), "https", client=_peer(writer), listener=LISTENER
        )
    except (ValueError, TypeError):
        await _respond(writer, 400, "Bad Request", "malformed CONNECT target\n")
        return
    route = server.router.route(connection)
    _log.info("netproxy: CONNECT %s -> %s", connection.authority, _describe(route))
    if route.action is Action.REJECT:
        await _respond(
            writer, 403, "Forbidden", f"{connection.authority} is not allowed\n"
        )
        return
    if route.action is Action.TLS:
        intercept = getattr(server, "_intercept", None)
        if intercept is None:
            await _respond(
                writer,
                502,
                "Bad Gateway",
                "this destination needs TLS interception, and the proxy has no CA\n",
            )
            return
        await intercept(connection, route, reader, writer)
        return
    try:
        upstream = await connect(
            connection, route, egress=server.egress, timeout=server.timeout
        )
    except (NetProxyError, OSError, asyncio.TimeoutError) as error:
        await _fail(writer, error, connection.authority)
        return
    writer.write(b"HTTP/1.1 200 Connection established" + _HEAD_END)
    await relay(
        reader,
        writer,
        upstream.reader,
        upstream.writer,
        idle_timeout=server.idle_timeout,
    )


# ---------------------------------------------------------- forwarded HTTP


_default_context: Optional[ssl.SSLContext] = None


def _verifying_context() -> ssl.SSLContext:
    global _default_context
    if _default_context is None:
        _default_context = ssl.create_default_context()
    return _default_context


async def _forward(
    server: Any,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    head: _Head,
    method: str,
    target: str,
    version: str,
) -> None:
    url = urlsplit(target)
    scheme = url.scheme.lower()
    try:
        port = url.port
    except ValueError:
        port = -1
    if scheme not in ("http", "https") or not url.hostname or port == -1:
        await _respond(writer, 400, "Bad Request", "expected an absolute http(s) URL\n")
        return
    path = (url.path or "/") + (f"?{url.query}" if url.query else "")
    connection = Connection(
        url.hostname,
        port or get_default_port(scheme),
        scheme,
        path=path,
        client=_peer(writer),
        listener=LISTENER,
    )
    route = server.router.route(connection)
    _log.info("netproxy: %s %s -> %s", method, target.split("?")[0], _describe(route))
    if route.action is Action.REJECT:
        await _respond(
            writer, 403, "Forbidden", f"{connection.authority} is not allowed\n"
        )
        return
    if scheme == "https" and route.action is Action.DIRECT:
        route = Route.with_tls(
            _verifying_context(), upstream=route.upstream, name=route.name
        )
    try:
        upstream = await connect(
            connection,
            route,
            egress=server.egress,
            timeout=server.timeout,
            forward_http=True,
        )
    except (NetProxyError, OSError, asyncio.TimeoutError) as error:
        await _fail(writer, error, connection.authority)
        return

    default_port = get_default_port("https" if upstream.tls else "http")
    authority = (
        connection.host if connection.port == default_port else connection.authority
    )
    if ":" in connection.host and connection.port == default_port:
        authority = f"[{connection.host}]"
    headers = [(n, v) for n, v in head.end_to_end() if n.lower() != "host"]
    headers.insert(0, ("Host", authority))
    upgrade = head.get("upgrade")
    if upgrade:
        headers += [("Connection", "Upgrade"), ("Upgrade", upgrade)]
    else:
        headers.append(("Connection", "close"))
    if upstream.forward:
        first = f"{method} http://{authority}{path} {version}"
        if upstream.proxy_authorization:
            headers.append(("Proxy-Authorization", upstream.proxy_authorization))
    else:
        first = f"{method} {path} HTTP/1.1"
    upstream.writer.write(_encode(first, headers))

    async def rewrite_response() -> None:
        # 1xx interim responses pass through; the final head is told to close.
        while True:
            raw = await asyncio.wait_for(
                upstream.reader.readuntil(_HEAD_END), server.timeout
            )
            response = _Head(raw)
            status = response.first.split(" ", 2)[1] if " " in response.first else ""
            if status.startswith("1") and status != "101":
                writer.write(raw)
                continue
            if status == "101":
                writer.write(raw)
            else:
                writer.write(
                    _encode(
                        response.first,
                        response.end_to_end() + [("Connection", "close")],
                    )
                )
            await writer.drain()
            return

    await relay(
        reader,
        writer,
        upstream.reader,
        upstream.writer,
        idle_timeout=server.idle_timeout,
        before_server=rewrite_response,
    )


# ------------------------------------------------------------- local pages


async def _local(
    server: Any, writer: asyncio.StreamWriter, method: str, path: str
) -> None:
    if method.upper() not in ("GET", "HEAD") or path.split("?")[0] != "/proxy.pac":
        await _respond(writer, 404, "Not Found", "only /proxy.pac is served here\n")
        return
    from .pac import generate_pac

    local = writer.get_extra_info("sockname")
    script = generate_pac(
        server.router, join_host(local[0], local[1]), egress=server.egress
    )
    await _respond(
        writer,
        200,
        "OK",
        script if method.upper() == "GET" else "",
        "application/x-ns-proxy-autoconfig",
    )


def _describe(route: Route) -> str:
    label = f" ({route.name})" if route.name else ""
    return f"{route.action.value}{label}"
