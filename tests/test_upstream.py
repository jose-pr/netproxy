from __future__ import annotations

import asyncio
import base64

import pytest
from proxylib import SimpleProxyMap

import netproxy
from netimps import get_free_port

from conftest import DATA, EchoServer, TLSServer, UpstreamProxy, data
from netproxy import Connection, Credential, Route
from netproxy.upstream import connect


def run(coroutine):
    return asyncio.run(coroutine)


def echo_via(connection, route, **kw):
    """Connect, send b"ping" and return (stream.via, the echoed bytes)."""

    async def scenario():
        stream = await connect(connection, route, **kw)
        return stream.via, await echo_round_trip(stream)

    return run(scenario())


async def echo_round_trip(stream, payload=b"ping") -> bytes:
    stream.writer.write(payload)
    await stream.writer.drain()
    reply = await asyncio.wait_for(stream.reader.readexactly(len(payload)), 5)
    stream.writer.close()
    return reply


async def tls_reply(stream) -> str:
    reply = await asyncio.wait_for(stream.reader.read(), 5)
    stream.writer.close()
    return reply.decode()


def credential(name="client-ec") -> Credential:
    return Credential.from_pem(
        data(f"{name}.pem"), data(f"{name}.key"), cafile=str(DATA / "ca.pem")
    )


def test_direct_route_reaches_the_destination():
    with EchoServer() as echo:
        assert echo_via(Connection("127.0.0.1", echo.port), Route.direct()) == (
            None,
            b"ping",
        )


def test_tls_route_presents_the_client_certificate(tls_server):
    route = Route.with_tls(credential("client-rsa"))

    async def scenario():
        stream = await connect(Connection("localhost", tls_server.port), route)
        assert stream.tls
        return await tls_reply(stream)

    assert run(scenario()).startswith("client-rsa\n")


def test_route_upstream_proxy_with_credentials_is_used(tls_server):
    with UpstreamProxy() as upstream:
        proxy_url = f"http://alice:s3cret@127.0.0.1:{upstream.port}"
        route = Route.with_tls(credential(), upstream=proxy_url)

        async def scenario():
            stream = await connect(Connection("localhost", tls_server.port), route)
            assert stream.via == f"http://127.0.0.1:{upstream.port}"
            return await tls_reply(stream)

        assert run(scenario()).startswith("client-ec\n")
    target, auth = upstream.requests[0]
    assert target == f"localhost:{tls_server.port}"
    assert auth == "Basic " + base64.b64encode(b"alice:s3cret").decode()


def test_server_egress_proxymap_applies_when_the_route_has_no_upstream():
    with EchoServer() as echo, UpstreamProxy() as upstream:
        via, reply = echo_via(
            Connection("127.0.0.1", echo.port),
            Route.direct(),
            egress=SimpleProxyMap(upstream.url),
        )
        assert reply == b"ping" and via == upstream.url
    assert upstream.requests == [(f"127.0.0.1:{echo.port}", None)]


def test_route_direct_overrides_the_egress():
    with EchoServer() as echo, UpstreamProxy() as upstream:
        via, reply = echo_via(
            Connection("127.0.0.1", echo.port),
            Route.direct(upstream="direct"),
            egress=SimpleProxyMap(upstream.url),
        )
        assert (via, reply) == (None, b"ping")
    assert upstream.requests == []


def test_answers_fail_over_in_order():
    with EchoServer() as echo:
        pac = f"PROXY 127.0.0.1:{get_free_port()}; DIRECT"
        via, reply = echo_via(
            Connection("127.0.0.1", echo.port), Route.direct(upstream=pac)
        )
        assert (via, reply) == (None, b"ping")


def test_a_refusing_upstream_is_reported_without_credentials():
    with UpstreamProxy(refuse=True) as upstream:
        route = Route.direct(upstream=f"http://bob:hunter2@127.0.0.1:{upstream.port}")
        with pytest.raises(netproxy.UpstreamError) as caught:
            run(connect(Connection("example.invalid", 443), route))
    message = str(caught.value)
    assert "403" in message and "hunter2" not in message and "bob" not in message


def test_unreachable_destination_is_an_upstream_error():
    with pytest.raises(netproxy.UpstreamError, match="cannot reach"):
        run(
            connect(Connection("127.0.0.1", get_free_port()), Route.direct(), timeout=5)
        )


def test_tls_failure_is_an_upstream_error():
    # The test server's certificate is not trusted by a default context.
    with TLSServer() as server:
        route = Route.with_tls(
            netproxy.Credential.from_pem(data("client-ec.pem"), data("client-ec.key"))
        )
        with pytest.raises(netproxy.UpstreamError, match="TLS"):
            run(connect(Connection("localhost", server.port), route, timeout=5))


def test_reject_routes_open_nothing():
    with pytest.raises(ValueError):
        run(connect(Connection("x.example", 443), Route.reject()))
