"""The server: listeners, per-connection tasks, lifecycle (async and sync)."""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Set, Tuple

from netimps import bind, is_wildcard, join_host, parse_listen, split_host

from ._connection import Connection
from ._relay import relay
from ._route import Action, Route, Router, Routing
from .exceptions import NetProxyError
from .upstream import connect

__all__ = ["AsyncProxyServer", "ProxyServer", "Tunnel"]

_log = logging.getLogger("netproxy")

DEFAULT_LISTEN = "127.0.0.1:0"


@dataclass(frozen=True)
class Tunnel:
    """A local port whose connections go to one fixed ``target``.

    ``listen`` is where to accept (``"127.0.0.1:15432"``); ``target`` is
    ``host:port``. Each connection is routed as a ``Connection`` with scheme
    ``"tcp"`` and listener ``name`` (default ``"tunnel:<target>"``); ``route``
    overrides the router for this tunnel.
    """

    listen: str
    target: str
    route: Optional[Route] = None
    name: str = ""

    def __post_init__(self) -> None:
        host, port = split_host(self.target)
        if port is None:
            raise ValueError(f"tunnel target needs a port: {self.target!r}")
        if not self.name:
            object.__setattr__(self, "name", f"tunnel:{self.target}")

    @property
    def target_host_port(self) -> Tuple[str, int]:
        host, port = split_host(self.target)
        return str(host), int(port)  # type: ignore[arg-type]


def _listen_sockets(listen: Any, allow_remote: bool) -> List[socket.socket]:
    addresses = parse_listen(listen if listen is not None else DEFAULT_LISTEN, 0)
    if not allow_remote:
        for address in addresses:
            if is_wildcard(address.address) or not address.address.is_loopback:
                raise ValueError(
                    f"refusing to listen on {join_host(str(address.address), address.port)}: "
                    "a proxy holding client credentials should only accept local "
                    "connections; pass allow_remote=True to listen beyond loopback"
                )
    sockets: List[socket.socket] = []
    try:
        for address in addresses:
            sock = bind(
                str(address.address),
                address.port,
                kind=socket.SOCK_STREAM,
                listen=128,
                reuse_address=True,
            )
            sock.setblocking(False)
            sockets.append(sock)
    except BaseException:
        for sock in sockets:
            sock.close()
        raise
    return sockets


class AsyncProxyServer:
    """A proxy server on the running event loop.

    ``router`` decides every connection (default: everything direct).
    ``listen`` is where the HTTP proxy accepts, in ``netimps.parse_listen``
    syntax (``"127.0.0.1:3128"``, a list of such); ``None`` means
    ``127.0.0.1`` on a free port, ``()`` no HTTP proxy listener at all.
    ``egress`` is a proxylib ``ProxyMap`` (or proxy URL string) for routes
    that set no upstream. ``tunnels`` are extra :class:`Tunnel` listeners.
    ``timeout`` bounds each connection attempt and handshake, ``idle_timeout``
    ends a relayed direction that stays silent that long. Listening beyond
    loopback needs ``allow_remote=True``.

    The constructor does no I/O; :meth:`start` binds, :meth:`aclose` stops
    and waits for every connection to end.
    """

    def __init__(
        self,
        router: Optional[Routing] = None,
        *,
        listen: Any = None,
        egress: Any = None,
        tunnels: Iterable[Tunnel] = (),
        timeout: float = 30.0,
        idle_timeout: Optional[float] = None,
        allow_remote: bool = False,
    ) -> None:
        self.router: Routing = router if router is not None else Router()
        self.listen = listen
        self.egress = egress
        self.tunnels = tuple(tunnels)
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.allow_remote = allow_remote
        self._servers: List[asyncio.AbstractServer] = []
        self._proxy_servers: List[asyncio.AbstractServer] = []
        self._tasks: Set["asyncio.Task[Any]"] = set()
        self._closed = False

    def __repr__(self) -> str:
        return f"<AsyncProxyServer addresses={self.addresses}>"

    async def __aenter__(self) -> "AsyncProxyServer":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------ binding

    async def start(self) -> None:
        """Bind every listener. Raises ``OSError`` (address in use) or
        ``ValueError`` (a remote address without ``allow_remote``)."""
        if self._servers:
            return
        try:
            if self.listen != ():
                for sock in _listen_sockets(self.listen, self.allow_remote):
                    server = await asyncio.start_server(self._accept_proxy, sock=sock)
                    self._servers.append(server)
                    self._proxy_servers.append(server)
            for tunnel in self.tunnels:
                for sock in _listen_sockets(tunnel.listen, self.allow_remote):
                    server = await asyncio.start_server(
                        lambda r, w, t=tunnel: self._accept_tunnel(t, r, w), sock=sock
                    )
                    self._servers.append(server)
        except BaseException:
            await self.aclose()
            raise

    @property
    def addresses(self) -> List[Tuple[str, int]]:
        """``(host, port)`` the HTTP proxy listens on, ports read back."""
        return [
            sock.getsockname()[:2]
            for server in self._proxy_servers
            for sock in server.sockets
        ]

    @property
    def port(self) -> int:
        """The HTTP proxy's first port (the free one picked for port 0)."""
        if not self._proxy_servers:
            raise RuntimeError("the server is not listening; call start() first")
        return self.addresses[0][1]

    def tunnel_address(self, tunnel: Tunnel) -> Tuple[str, int]:
        """Where ``tunnel`` (one of ``tunnels``) listens, port read back."""
        index = self.tunnels.index(tunnel)
        offset = len(self._proxy_servers)
        return self._servers[offset + index].sockets[0].getsockname()[:2]

    async def serve_forever(self) -> None:
        """Start if needed, then wait until :meth:`aclose` (or cancellation)."""
        await self.start()
        await asyncio.gather(*(s.serve_forever() for s in self._servers))

    async def aclose(self) -> None:
        """Stop listening, end every relayed connection and wait for them."""
        self._closed = True
        for server in self._servers:
            server.close()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for server in self._servers:
            await server.wait_closed()
        self._servers.clear()
        self._proxy_servers.clear()

    # ------------------------------------------------------- connections

    def _track(self) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _accept_proxy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._track()
        try:
            from ._http import handle_http_proxy

            await handle_http_proxy(self, reader, writer)
        finally:
            writer.close()

    async def _accept_tunnel(
        self,
        tunnel: Tunnel,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._track()
        host, port = tunnel.target_host_port
        connection = Connection(
            host,
            port,
            scheme="tcp",
            client=writer.get_extra_info("peername"),
            listener=tunnel.name,
        )
        try:
            route = tunnel.route or self.router.route(connection)
            if route.action is Action.REJECT:
                _log.info(
                    "netproxy: rejected %s (%s)", connection.authority, route.name
                )
                return
            upstream = await connect(
                connection, route, egress=self.egress, timeout=self.timeout
            )
            await relay(
                reader,
                writer,
                upstream.reader,
                upstream.writer,
                idle_timeout=self.idle_timeout,
            )
        except (NetProxyError, OSError) as error:
            _log.warning(
                "netproxy: %s via %s: %s", connection.authority, tunnel.name, error
            )
        finally:
            writer.close()


class ProxyServer:
    """:class:`AsyncProxyServer` for synchronous code: the server runs on its
    own event loop in a daemon thread. Same arguments.

    :meth:`start` returns once every listener is bound (or raises what
    binding raised); :meth:`close` stops the server and joins the thread.
    """

    def __init__(self, router: Optional[Routing] = None, **options: Any) -> None:
        self._server = AsyncProxyServer(router, **options)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def __repr__(self) -> str:
        return f"<ProxyServer addresses={self.addresses}>"

    def __enter__(self) -> "ProxyServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def server(self) -> AsyncProxyServer:
        return self._server

    @property
    def addresses(self) -> List[Tuple[str, int]]:
        return self._server.addresses

    @property
    def port(self) -> int:
        return self._server.port

    def tunnel_address(self, tunnel: Tunnel) -> Tuple[str, int]:
        return self._server.tunnel_address(tunnel)

    def start(self) -> None:
        if self._thread is not None:
            return
        started = threading.Event()
        failure: List[BaseException] = []

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            try:
                loop.run_until_complete(self._server.start())
            except BaseException as error:  # noqa: BLE001 - re-raised in start()
                failure.append(error)
                started.set()
                loop.close()
                return
            started.set()
            loop.run_forever()
            loop.run_until_complete(self._server.aclose())
            loop.close()

        self._thread = threading.Thread(target=run, name="netproxy", daemon=True)
        self._thread.start()
        started.wait()
        if failure:
            self._thread.join()
            self._thread = None
            raise failure[0]

    def close(self) -> None:
        if self._thread is None:
            return
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(30)
        self._thread = None
