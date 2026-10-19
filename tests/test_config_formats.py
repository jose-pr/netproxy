"""Which format a configuration file is read as, and INI's shape."""

from __future__ import annotations

import json

import pytest

import netproxy
from netproxy import config
from netproxy.config import build_server, load, loads
from test_config import DOCUMENT

EXPECTED = loads(DOCUMENT)

YAML = """#!yaml
server:
  listen: 127.0.0.1:0
  timeout: 10
credentials:
  work:
    backend: pem
    certificate: client-rsa.pem
    key: client-rsa.key
    cafile: ca.pem
rules:
  - match: [localhost, "*.corp.example"]
    action: tls
    credential: work
    name: corp
  - match: "*.blocked.example"
    action: reject
default:
  action: direct
"""

INI = """
[server]
listen = 127.0.0.1:0
timeout = 10

[credentials.work]
backend = pem
certificate = client-rsa.pem
key = client-rsa.key
cafile = ca.pem

[rules.corp]
match = ["localhost", "*.corp.example"]
action = tls
credential = work

[rules.blocked]
match = *.blocked.example
action = reject

[default]
action = direct
"""


def blocked_named(data):
    # INI names every rule after its section; TOML's second rule has no name.
    data = json.loads(json.dumps(data))
    data["rules"][1]["name"] = "blocked"
    return data


def test_a_cfg_file_without_a_shebang_is_toml(tmp_path):
    path = tmp_path / "netproxy.cfg"
    path.write_text(DOCUMENT, encoding="utf-8")
    assert load(path) == EXPECTED


@pytest.mark.parametrize(
    "text",
    [
        "#!toml\n" + DOCUMENT,
        YAML,
        "#!json\n" + json.dumps(EXPECTED),
        "#!/usr/bin/env json\n" + json.dumps(EXPECTED),
    ],
    ids=["toml", "yaml", "json", "env-json"],
)
def test_the_first_line_names_the_format(tmp_path, text):
    path = tmp_path / "netproxy.cfg"
    path.write_text(text, encoding="utf-8")
    assert load(path) == EXPECTED


def test_ini_has_the_same_shape(tmp_path):
    path = tmp_path / "netproxy.cfg"
    path.write_text("#!ini\n" + INI, encoding="utf-8")
    assert load(path) == blocked_named(EXPECTED)


def test_a_known_suffix_names_the_format(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(EXPECTED), encoding="utf-8")
    assert load(path) == EXPECTED
    assert loads(json.dumps(EXPECTED), format="json") == EXPECTED


def test_an_ini_document_builds_a_server(tmp_path):
    import shutil

    from conftest import DATA

    for name in ("client-rsa.pem", "client-rsa.key", "ca.pem"):
        shutil.copy(DATA / name, tmp_path / name)
    server = build_server(loads("#!ini\n" + INI), base_dir=tmp_path)
    assert [r.route.name for r in server.router.rules] == ["corp", "blocked"]


@pytest.mark.parametrize(
    "value, typed",
    [
        ("true", True),
        ("Off", False),
        ("10", 10),
        ("-2.5", -2.5),
        ('["a", 1]', ["a", 1]),
        ('{"store": "MY"}', {"store": "MY"}),
        ('"10"', "10"),
        ("127.0.0.1:0", "127.0.0.1:0"),
        ("[not json", "[not json"),
    ],
)
def test_ini_values_are_typed(value, typed):
    data = loads(f"#!ini\n[server]\nx = {value}\n")
    assert data["server"]["x"] == typed


def test_ini_nested_sections_and_bad_list_sections():
    data = loads("#!ini\n[server.ca]\ncertificate = ca.pem\n[server]\ntimeout = 5\n")
    assert data["server"] == {"ca": {"certificate": "ca.pem"}, "timeout": 5}
    with pytest.raises(netproxy.ConfigError, match=r"\[rules\.<name>\]"):
        loads("#!ini\n[rules]\naction = tls\n")


def test_errors_are_config_errors_with_a_position():
    with pytest.raises(netproxy.ConfigError) as caught:
        loads('#!json\n{"server": ', path="netproxy.cfg")
    assert caught.value.path == "netproxy.cfg" and caught.value.lineno
    with pytest.raises(netproxy.ConfigError, match="nosuch"):
        loads("#!nosuch\nx = 1\n")
    with pytest.raises(netproxy.ConfigError, match="not a table"):
        loads("#!json\n[1, 2]\n")


def test_the_default_file_is_netproxy_cfg(monkeypatch):
    monkeypatch.delenv("NETPROXY_CONFIG", raising=False)
    assert config.default_path().name == "netproxy.cfg"
    assert config.default_path().parent.name == "netproxy"
