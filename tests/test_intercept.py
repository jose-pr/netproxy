from __future__ import annotations

import http.client
import json
import ssl

import pytest
from sslcontext.issuing import CertificateAuthority

from conftest import DATA, data
from netproxy import Credential, ProxyServer, Route, Router
from netproxy.intercept import create_ca, permitted_names
from netproxy.rules import Host, HostRegex, Network, Path, Port
from origins import Origin


def credential(name: str = "client-rsa") -> Credential:
    return Credential.from_pem(
        data(f"{name}.pem"), data(f"{name}.key"), cafile=str(DATA / "ca.pem")
    )


def https_via(server, host, port, path, trust: bytes):
    """GET ``https://host:port/path`` through the proxy, trusting ``trust``."""
    context = ssl.create_default_context(cadata=trust.decode())
    connection = http.client.HTTPSConnection(
        "127.0.0.1", server.port, context=context, timeout=10
    )
    try:
        connection.set_tunnel(host, port)
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


ROUTER = Router([(Host("localhost"), Route.with_tls(credential()))])


def test_https_client_gets_mutual_tls_through_interception():
    ca = create_ca(ROUTER)
    with Origin(tls=True) as origin, ProxyServer(ROUTER, ca=ca) as server:
        status, seen = https_via(server, "localhost", origin.port, "/x", ca.certificate)
        # A second request reuses the cached leaf.
        again = https_via(server, "localhost", origin.port, "/y", ca.certificate)[1]
    assert status == 200 and seen["client_cn"] == "client-rsa" and seen["tls"]
    assert seen["path"] == "/x" and again["path"] == "/y"


def test_clients_refuse_a_leaf_outside_the_ca_name_constraints():
    ca = CertificateAuthority.create("elsewhere only", permitted=["other.example"])
    with Origin(tls=True) as origin, ProxyServer(ROUTER, ca=ca) as server:
        with pytest.raises(ssl.SSLCertVerificationError):
            https_via(server, "localhost", origin.port, "/", ca.certificate)


def test_unreachable_intercepted_destination_is_502_before_any_tls():
    from netimps import get_free_port

    ca = create_ca(ROUTER)
    with ProxyServer(ROUTER, ca=ca) as server:
        with pytest.raises(OSError, match="502"):
            https_via(server, "localhost", get_free_port(), "/", ca.certificate)


def test_permitted_names_follow_the_tls_rules():
    tls = Route.with_tls(ssl.create_default_context())
    router = Router(
        [
            (Host("*.corp.example") & ~Port(80), tls),
            (Network("10.0.0.0/8") | Host(".lab.example"), tls),
            (Host("www.example"), Route.direct()),
        ]
    )
    assert permitted_names(router) == ["*.corp.example", "10.0.0.0/8", ".lab.example"]
    assert permitted_names(Router([(HostRegex("x"), tls)])) is None
    assert permitted_names(Router([(Path("/a"), tls)])) is None
    assert permitted_names(Router(default=tls)) is None


def test_create_ca_refuses_to_be_unconstrained_by_accident():
    tls = Route.with_tls(ssl.create_default_context())
    with pytest.raises(ValueError, match="constrain=False"):
        create_ca(Router([(HostRegex("x"), tls)]))
    assert create_ca(Router([(HostRegex("x"), tls)]), constrain=False)
