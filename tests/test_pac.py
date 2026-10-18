"""Generated PAC scripts, executed by proxylib's PAC engine."""

from __future__ import annotations

import ssl

import pytest

from netproxy import Route, Router
from netproxy.pac import generate_pac
from netproxy.rules import Host, HostRegex, Network, Path, Port

pytest.importorskip("dukpy")
from proxylib.pac import load  # noqa: E402

PROXY = "127.0.0.1:3128"
TLS = Route.with_tls(ssl.create_default_context())


def evaluate(router: Router, url: str, **options) -> str:
    answers = list(load(generate_pac(router, PROXY, **options))[url])
    first = answers[0]
    return "DIRECT" if first is None else f"{first.host}:{first.port}"


ROUTER = Router(
    [
        (Host("*.corp.example") & ~Port(80), TLS),
        (Network("10.0.0.0/8"), Route.direct(upstream="direct")),
        (HostRegex(r"api\d+\.example"), TLS),
        (".intra.example", Route.reject()),
    ]
)


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://a.corp.example/", PROXY),
        ("http://a.corp.example/", "DIRECT"),
        ("http://10.1.2.3/", "DIRECT"),
        ("https://API7.example/", PROXY),
        ("http://intra.example/", PROXY),
        ("http://x.intra.example/", PROXY),
        ("http://other.example/", "DIRECT"),
    ],
)
def test_script_routes_like_the_router(url, expected):
    assert evaluate(ROUTER, url) == expected


def test_with_an_egress_even_direct_routes_use_the_proxy():
    assert evaluate(ROUTER, "http://other.example/", egress="http://up:8080") == PROXY
    assert evaluate(ROUTER, "http://10.1.2.3/", egress="http://up:8080") == "DIRECT"


def test_a_rule_pac_cannot_express_sends_the_rest_to_the_proxy():
    router = Router(
        [
            ("*.corp.example", TLS),
            (Path("/admin"), Route.reject()),
            ("late.example", Route.direct(upstream="direct")),
        ]
    )
    script = generate_pac(router, PROXY)
    assert "a rule PAC cannot express" in script
    assert evaluate(router, "http://late.example/") == PROXY
    assert evaluate(router, "https://a.corp.example/") == PROXY


def test_ipv6_networks_are_left_to_the_proxy():
    router = Router([(Network("fd00::/8"), Route.direct(upstream="direct"))])
    assert evaluate(router, "http://any.example/") == PROXY
