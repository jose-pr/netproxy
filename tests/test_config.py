from __future__ import annotations

import json
import shutil

import pytest

import netproxy
from conftest import DATA
from netproxy._server import KEYLOG_SUPPORTED
from netproxy import Action, Connection, ProxyServer
from netproxy.config import build_router, build_server, load_server, loads
from test_http_proxy import via_proxy
from origins import Origin

DOCUMENT = """
[server]
listen = "127.0.0.1:0"
timeout = 10

[credentials.work]
backend = "pem"
certificate = "client-rsa.pem"
key = "client-rsa.key"
cafile = "ca.pem"

[[rules]]
match = ["localhost", "*.corp.example"]
action = "tls"
credential = "work"
name = "corp"

[[rules]]
match = "*.blocked.example"
action = "reject"

[default]
action = "direct"
"""


@pytest.fixture
def config_dir(tmp_path):
    for name in ("client-rsa.pem", "client-rsa.key", "ca.pem"):
        shutil.copy(DATA / name, tmp_path / name)
    (tmp_path / "netproxy.toml").write_text(DOCUMENT, encoding="utf-8")
    return tmp_path


def test_loads_returns_plain_data():
    data = loads(DOCUMENT)
    assert data["rules"][0]["match"] == ["localhost", "*.corp.example"]
    assert data["server"]["timeout"] == 10


@pytest.mark.parametrize("text", ['[server\nlisten = "x"', "a = 1\na = 2\n"])
def test_malformed_documents_report_a_position_not_the_content(text):
    with pytest.raises(netproxy.ConfigError) as caught:
        loads(text, path="bad.toml")
    error = caught.value
    assert error.path == "bad.toml" and error.lineno is not None
    assert "listen" not in str(error)


def test_a_config_file_drives_the_server(config_dir):
    server = load_server(config_dir / "netproxy.toml")
    with Origin(tls=True) as origin, ProxyServer(server=server) as running:
        status, _, body = via_proxy(running, "GET", f"http://localhost:{origin.port}/c")
        blocked = via_proxy(running, "GET", "http://a.blocked.example/")[0]
    assert status == 200 and json.loads(body)["client_cn"] == "client-rsa"
    assert blocked == 403


def test_router_alone_can_be_built(config_dir):
    router = build_router(loads(DOCUMENT), base_dir=config_dir)
    rule, route = router.explain(Connection("api.corp.example", 443))
    assert route.action is Action.TLS and route.name == "corp"


@pytest.mark.parametrize(
    "extra, message",
    [
        ("[server]\nbogus = 1\n", "unknown key"),
        (
            '[[rules]]\nmatch = "x"\naction = "tls"\ncredential = "nope"\n',
            "unknown credential",
        ),
        ('[[rules]]\nmatch = "x"\naction = "teleport"\n', "action must be"),
        ('[credentials.c]\nbackend = "cng"\npin = "1234"\n', "pin_env"),
        ('[credentials.c]\nbackend = "nosuch"\n', "unknown backend"),
        ("[surprise]\n", "unknown table"),
        ('[[rules]]\nmatch = "x"\nport = "443"\n', "port must be"),
    ],
)
def test_configuration_errors_name_the_place(extra, message):
    with pytest.raises(netproxy.ConfigError, match=message):
        build_server(loads(extra))


def test_pin_comes_from_the_environment_when_used(monkeypatch):
    document = loads(
        '[credentials.card]\nbackend = "pkcs11"\npin_env = "TEST_CARD_PIN"\n'
        'options = { module = "/missing.so" }\n'
        '[[rules]]\nmatch = "x"\naction = "tls"\ncredential = "card"\n'
    )
    router = build_router(document)
    credential = router.rules[0].route.tls
    pin = credential.options["pin"]
    monkeypatch.setenv("TEST_CARD_PIN", "4321")
    assert pin(None) == "4321"
    monkeypatch.delenv("TEST_CARD_PIN")
    assert pin(None) is None


def test_tunnels_with_a_credential_are_tls(config_dir):
    document = loads(
        DOCUMENT
        + '\n[[tunnels]]\nlisten = "127.0.0.1:0"\ntarget = "db.corp.example:5432"\n'
        'credential = "work"\n'
    )
    server = build_server(document, base_dir=config_dir)
    (tunnel,) = server.tunnels
    assert tunnel.route is not None and tunnel.route.action is Action.TLS


def test_recording_settings_build_owned_recorders(config_dir):
    keylog = 'keylog = "keys.log"\n' if KEYLOG_SUPPORTED else ""
    document = loads(
        DOCUMENT.replace(
            "timeout = 10\n",
            'timeout = 10\nrecord = "out/proxy.pcapng"\n'
            + keylog
            + "log_traffic = true\n",
        )
    )
    (config_dir / "out").mkdir()
    server = build_server(document, base_dir=config_dir)
    kinds = sorted(type(r).__name__ for r in server.recorders)
    assert kinds == ["LogRecorder", "PcapRecorder"]
    if KEYLOG_SUPPORTED:
        assert server.keylog == str(config_dir / "keys.log")
    with Origin(tls=True) as origin, ProxyServer(server=server) as running:
        via_proxy(running, "GET", f"http://localhost:{origin.port}/rec")
    assert (config_dir / "out" / "proxy.pcapng").stat().st_size > 0
    assert server.recorders[1]._writer._closed  # closed by the server's aclose
    assert not server._owned


def test_keylog_where_the_tls_library_cannot_names_the_key(config_dir, monkeypatch):
    from netproxy import _server

    monkeypatch.setattr(_server, "KEYLOG_SUPPORTED", False)
    document = loads(DOCUMENT.replace("timeout = 10\n", 'timeout = 10\nkeylog = "k"\n'))
    with pytest.raises(netproxy.ConfigError, match="server.keylog"):
        build_server(document, base_dir=config_dir)


def test_a_pac_egress_the_configuration_built_is_closed_with_the_server(config_dir):
    pytest.importorskip("dukpy")
    script = config_dir / "proxy.pac"
    script.write_text('function FindProxyForURL(url, host) { return "DIRECT"; }\n')
    document = loads(
        DOCUMENT.replace(
            "timeout = 10\n", f'timeout = 10\negress = "pac:{script.as_uri()}"\n'
        )
    )
    server = build_server(document, base_dir=config_dir)
    with Origin() as origin, ProxyServer(server=server) as running:
        via_proxy(running, "GET", f"http://127.0.0.1:{origin.port}/x")
    process = server.egress.script._runner._proc
    assert process.poll() is not None  # the helper has ended
    assert not server._owned
