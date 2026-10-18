from __future__ import annotations

import ssl

import pytest

import netproxy
from conftest import DATA, data
from netproxy import Connection, Credential, Route, Router, Rule
from netproxy.rules import (
    ALL,
    Host,
    HostRegex,
    Listener,
    Network,
    Path,
    Port,
    Scheme,
    parse_matcher,
)


def conn(host="api.corp.example", port=443, **kw) -> Connection:
    return Connection(host, port, **kw)


@pytest.mark.parametrize(
    "pattern, host, expected",
    [
        ("*.corp.example", "api.corp.example", True),
        ("*.corp.example", "corp.example", False),
        (".corp.example", "corp.example", True),
        (".corp.example", "a.b.corp.example", True),
        ("API.CORP.EXAMPLE", "api.corp.example", True),
        ("api?.corp.example", "api1.corp.example", True),
        ("[ab].example", "a.example", False),
        ("[ab].example", "[ab].example", True),
    ],
)
def test_host_globs(pattern, host, expected):
    assert Host(pattern)(conn(host)) is expected


def test_host_regex_matches_the_whole_host():
    assert HostRegex(r"api\d+\.corp\.example")(conn("API7.corp.example"))
    assert not HostRegex(r"api")(conn("api.corp.example"))


def test_network_matches_address_literals_only():
    rule = Network("10.0.0.0/8", "fd00::/8")
    assert rule(conn("10.1.2.3")) and rule(conn("[fd00::1]"))
    assert not rule(conn("192.168.1.1")) and not rule(conn("ten.example"))


def test_port_scheme_path_listener():
    assert Port(443, range(8000, 9000))(conn(port=8443))
    assert Scheme("http")(conn(scheme="http")) and not Scheme("http")(conn())
    assert Path(r"/api/")(conn(scheme="http", path="/api/v1"))
    assert not Path(r"/api/")(conn())
    assert Listener("corp")(conn(listener="corp"))


def test_matchers_combine():
    rule = (Host("*.corp.example") & ~Port(80)) | Network("10.0.0.0/8")
    assert rule(conn())
    assert not rule(conn(port=80))
    assert rule(conn("10.9.9.9", 80))
    assert ALL(conn("anything.example"))


@pytest.mark.parametrize(
    "text, expected",
    [
        ("*.corp.example", Host("*.corp.example")),
        ("10.0.0.0/8", Network("10.0.0.0/8")),
        ("fd00::/8", Network("fd00::/8")),
        ("*", ALL),
        ("re:api\\d+", HostRegex("api\\d+")),
        ("*.corp.example:8443", Host("*.corp.example") & Port(8443)),
    ],
)
def test_parse_matcher(text, expected):
    assert parse_matcher(text) == expected


def test_matchers_are_hashable_values():
    assert len({Host("a.example"), Host("a.example"), Port(1)}) == 2
    assert "Host('a.example')" == repr(Host("a.example"))


def test_router_first_match_wins_then_default():
    mtls = Route.with_tls(ssl.create_default_context(), name="corp")
    router = Router(
        [
            ("blocked.corp.example", Route.reject(name="block")),
            Rule("*.corp.example", mtls),
        ],
        default=Route.direct(name="rest"),
    )
    assert router.route(conn("blocked.corp.example")).name == "block"
    assert router.route(conn()).name == "corp"
    rule, route = router.explain(conn("www.example"))
    assert rule is None and route.name == "rest"


def test_route_validates_its_tls_source():
    with pytest.raises(ValueError):
        Route(netproxy.Action.TLS)
    with pytest.raises(ValueError):
        Route(netproxy.Action.DIRECT, tls=ssl.create_default_context())
    with pytest.raises(TypeError):
        Route.with_tls("not a context")


def test_connection_normalises_and_builds_the_lookup_url():
    c = Connection("[FD00::1].", 8443, scheme="tcp")
    assert c.host == "fd00::1"
    assert c.url == "https://[fd00::1]:8443/"
    with pytest.raises(ValueError):
        Connection("x.example", 0)


def test_pem_credential_builds_an_authenticating_context(tls_server):
    credential = Credential.from_pem(
        data("client-ec.pem"), data("client-ec.key"), cafile=str(DATA / "ca.pem")
    )
    context = credential.context()
    assert credential.context() is context  # cached
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_identity_credential(tls_server):
    from sslcontext.testing import software_identity

    identity = software_identity(data("client-rsa.pem"), data("client-rsa.key"))
    credential = Credential(identity, cafile=str(DATA / "ca.pem"))
    assert tls_server.handshake(credential.context()).client_cn == "client-rsa"


def test_unresolvable_credential_raises_and_is_retried():
    credential = Credential(
        backend="pkcs11", options={"module": "/nonexistent/module.so"}, query={}
    )
    for _ in range(2):
        with pytest.raises(netproxy.CredentialUnavailableError):
            credential.context()


def test_credential_needs_exactly_one_source():
    with pytest.raises(ValueError):
        Credential()
    with pytest.raises(ValueError):
        Credential(backend="no-such-backend")
