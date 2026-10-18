from __future__ import annotations

import base64
import http.client
import json
import ssl

import pytest

from conftest import DATA, UpstreamProxy, data
from netimps import get_free_port
from netproxy import Credential, ProxyServer, Route, Router
from netproxy.rules import Host, Path
from origins import Origin


def credential(name: str = "client-ec") -> Credential:
    return Credential.from_pem(
        data(f"{name}.pem"), data(f"{name}.key"), cafile=str(DATA / "ca.pem")
    )


def via_proxy(server, method, url, body=None, headers=None):
    """Send one absolute-form request through the proxy; (status, headers, body)."""
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        connection.request(method, url, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_forwards_plain_http_in_origin_form():
    with Origin() as origin, ProxyServer() as server:
        status, headers, body = via_proxy(
            server,
            "GET",
            f"http://127.0.0.1:{origin.port}/a/b?x=1",
            headers={"Proxy-Connection": "keep-alive", "X-Test": "yes"},
        )
    seen = json.loads(body)
    assert status == 200 and headers["Connection"] == "close"
    assert seen["path"] == "/a/b?x=1" and seen["method"] == "GET"
    assert seen["headers"]["host"] == f"127.0.0.1:{origin.port}"
    assert seen["headers"]["x-test"] == "yes"
    assert "proxy-connection" not in seen["headers"]


@pytest.mark.parametrize("chunked", [False, True])
def test_forwards_request_bodies(chunked):
    payload = b"z" * 200_000

    def body():
        yield payload[:100_000]
        yield payload[100_000:]

    with Origin() as origin, ProxyServer() as server:
        status, _, raw = via_proxy(
            server,
            "POST",
            f"http://127.0.0.1:{origin.port}/upload",
            body=body() if chunked else payload,
            headers={} if chunked else {"Content-Length": str(len(payload))},
        )
    assert status == 200 and json.loads(raw)["body"] == payload.decode()


def test_plain_http_is_upgraded_to_mutual_tls_by_a_rule():
    router = Router([(Host("localhost"), Route.with_tls(credential("client-rsa")))])
    with Origin(tls=True) as origin, ProxyServer(router) as server:
        status, _, body = via_proxy(
            server, "GET", f"http://localhost:{origin.port}/api"
        )
    seen = json.loads(body)
    assert status == 200 and seen["tls"] and seen["client_cn"] == "client-rsa"
    assert seen["path"] == "/api"


def test_path_rules_pick_the_credential():
    router = Router(
        [
            (
                Host("localhost") & Path("/admin"),
                Route.with_tls(credential("client-rsa")),
            ),
            (Host("localhost"), Route.with_tls(credential("client-ec"))),
        ]
    )
    with Origin(tls=True) as origin, ProxyServer(router) as server:
        base = f"http://localhost:{origin.port}"
        admin = json.loads(via_proxy(server, "GET", base + "/admin/x")[2])
        other = json.loads(via_proxy(server, "GET", base + "/public")[2])
    assert (admin["client_cn"], other["client_cn"]) == ("client-rsa", "client-ec")


def test_connect_tunnels_directly():
    with Origin(tls=True) as origin, ProxyServer() as server:
        context = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
        context.load_cert_chain(DATA / "client-ec.pem", DATA / "client-ec.key")
        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=context, timeout=10
        )
        connection.set_tunnel("localhost", origin.port)
        connection.request("GET", "/through-tunnel")
        seen = json.loads(connection.getresponse().read())
        connection.close()
    assert seen["client_cn"] == "client-ec" and seen["path"] == "/through-tunnel"


def test_connect_to_a_tls_route_without_a_ca_is_refused_clearly():
    router = Router([(Host("localhost"), Route.with_tls(credential()))])
    with Origin(tls=True) as origin, ProxyServer(router) as server:
        connection = http.client.HTTPSConnection("127.0.0.1", server.port, timeout=10)
        connection.set_tunnel("localhost", origin.port)
        with pytest.raises(OSError, match="502"):
            connection.request("GET", "/")
        connection.close()


def test_rejected_destinations_get_403():
    router = Router([("*.blocked.example", Route.reject(name="policy"))])
    with ProxyServer(router) as server:
        status, _, _ = via_proxy(server, "GET", "http://a.blocked.example/")
        connection = http.client.HTTPSConnection("127.0.0.1", server.port, timeout=10)
        connection.set_tunnel("a.blocked.example", 443)
        with pytest.raises(OSError, match="403"):
            connection.request("GET", "/")
        connection.close()
    assert status == 403


def test_unreachable_destination_is_502():
    with ProxyServer() as server:
        status, _, body = via_proxy(
            server, "GET", f"http://127.0.0.1:{get_free_port()}/"
        )
    assert status == 502 and b"cannot reach" in body


def test_plain_http_goes_to_an_upstream_proxy_in_absolute_form():
    with Origin() as origin, UpstreamProxy() as upstream:
        egress = f"http://carol:pw@127.0.0.1:{upstream.port}"
        with ProxyServer(egress=egress) as server:
            status, _, body = via_proxy(
                server, "GET", f"http://127.0.0.1:{origin.port}/via-upstream"
            )
    assert status == 200 and json.loads(body)["path"] == "/via-upstream"
    target, auth = upstream.requests[0]
    assert target == f"http://127.0.0.1:{origin.port}/via-upstream"
    assert auth == "Basic " + base64.b64encode(b"carol:pw").decode()


def test_serves_a_pac_file_from_its_rules():
    router = Router(
        [
            ("*.corp.example", Route.with_tls(credential())),
            ("intranet.example", Route.direct(upstream="direct")),
        ]
    )
    with ProxyServer(router) as server:
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        connection.request("GET", "/proxy.pac")
        response = connection.getresponse()
        script = response.read().decode()
        connection.close()
        port = server.port
    assert response.status == 200
    assert response.getheader("Content-Type") == "application/x-ns-proxy-autoconfig"
    proxy = f"PROXY 127.0.0.1:{port}"
    assert f'if ((shExpMatch(host, "*.corp.example"))) return "{proxy}";' in script
    assert script.rstrip().endswith('return "DIRECT";\n}'.rstrip())


def test_unknown_local_paths_are_404():
    with ProxyServer() as server:
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        connection.request("GET", "/status")
        assert connection.getresponse().status == 404
        connection.close()
