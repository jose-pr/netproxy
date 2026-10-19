from __future__ import annotations

import asyncio
import socket
import ssl

import pytest

from conftest import DATA, EchoServer, data
from netproxy import (
    AsyncProxyServer,
    Credential,
    ProxyServer,
    Route,
    Router,
    Tunnel,
)
from netproxy.rules import Listener


def credential(name: str = "client-ec") -> Credential:
    return Credential.from_pem(
        data(f"{name}.pem"), data(f"{name}.key"), cafile=str(DATA / "ca.pem")
    )


def talk(address, payload: bytes = b"", half_close: bool = True) -> bytes:
    with socket.create_connection(address, timeout=10) as sock:
        if payload:
            sock.sendall(payload)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        reply = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return reply
            reply += chunk


def test_tunnel_gives_a_plain_tcp_client_mutual_tls(tls_server):
    tunnel = Tunnel(
        "127.0.0.1:0",
        f"localhost:{tls_server.port}",
        route=Route.with_tls(credential("client-rsa")),
    )
    with ProxyServer(listen=(), tunnels=[tunnel]) as server:
        reply = talk(server.tunnel_address(tunnel), half_close=False)
    newest = "TLSv1.3" if ssl.HAS_TLSv1_3 else "TLSv1.2"
    assert reply.decode().split("\n") == ["client-rsa", newest]


def test_tunnel_connections_are_routed_by_listener_name(tls_server):
    tunnel = Tunnel("127.0.0.1:0", f"localhost:{tls_server.port}", name="corp-db")
    router = Router([(Listener("corp-db"), Route.with_tls(credential()))])
    with ProxyServer(router, listen=(), tunnels=[tunnel]) as server:
        reply = talk(server.tunnel_address(tunnel), half_close=False)
    assert reply.startswith(b"client-ec\n")


def test_direct_tunnel_relays_both_ways_and_half_closes():
    with EchoServer() as echo:
        tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}")
        with ProxyServer(listen=(), tunnels=[tunnel]) as server:
            payload = b"x" * 300_000
            assert talk(server.tunnel_address(tunnel), payload) == payload


def test_rejected_tunnel_closes_the_connection():
    with EchoServer() as echo:
        tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}", route=Route.reject())
        with ProxyServer(listen=(), tunnels=[tunnel]) as server:
            # Closed without a reply. Windows reports the unread request as a
            # reset, and Linux may refuse the half-close of a socket already shut.
            try:
                assert talk(server.tunnel_address(tunnel), b"hello") == b""
            except OSError:
                pass


def test_listening_beyond_loopback_needs_allow_remote():
    with pytest.raises(ValueError, match="allow_remote"):
        ProxyServer(listen="0.0.0.0:0").start()


def test_http_listener_port_is_read_back_and_lifecycle_is_idempotent():
    server = ProxyServer()
    server.start()
    server.start()
    assert server.port > 0 and server.addresses[0][0] == "127.0.0.1"
    server.close()
    server.close()


def test_async_server_closes_with_a_connection_open():
    async def scenario():
        with EchoServer() as echo:
            tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}")
            async with AsyncProxyServer(listen=(), tunnels=[tunnel]) as server:
                host, port = server.tunnel_address(tunnel)
                reader, writer = await asyncio.open_connection(host, port)
                writer.write(b"ping")
                assert await reader.readexactly(4) == b"ping"
            # aclose() ended the relay: the client sees end of stream.
            assert await asyncio.wait_for(reader.read(), 5) == b""
            writer.close()

    asyncio.run(scenario())


def test_tunnel_target_needs_a_port():
    with pytest.raises(ValueError):
        Tunnel("127.0.0.1:0", "db.example")
