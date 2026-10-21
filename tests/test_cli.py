from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from conftest import DATA
from netproxy.cli import main
from origins import Origin
from test_http_proxy import via_proxy

CONFIG = """
[server]
listen = "127.0.0.1:0"
ca = { certificate = "ca/ca.pem", key = "ca/ca.key" }

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
"""


@pytest.fixture
def config(tmp_path):
    for name in ("client-rsa.pem", "client-rsa.key", "ca.pem"):
        shutil.copy(DATA / name, tmp_path / name)
    path = tmp_path / "netproxy.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def test_check_explains_the_route(config, capsys):
    assert main(["check", "-c", str(config), "https://api.corp.example/x"]) == 0
    line = capsys.readouterr().out.strip()
    assert (
        line
        == "destination=https://api.corp.example/x rule=corp action=tls credential=work"
    )


def test_check_json_for_the_default(config, capsys):
    assert main(["check", "-c", str(config), "--json", "www.example:443"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["rule"] == "default" and result["action"] == "direct"


def test_pac_prints_a_script_for_the_rules(config, capsys):
    assert main(["pac", "-c", str(config), "--proxy", "127.0.0.1:3128"]) == 0
    script = capsys.readouterr().out
    assert "FindProxyForURL" in script and "PROXY 127.0.0.1:3128" in script


def test_ca_init_then_show_and_no_silent_overwrite(config, capsys):
    assert main(["ca", "init", "-c", str(config)]) == 0
    created = capsys.readouterr().out.strip()
    assert created.endswith("ca.pem")
    assert main(["ca", "show", "-c", str(config)]) == 0
    assert capsys.readouterr().out.startswith("-----BEGIN CERTIFICATE-----")
    assert main(["ca", "init", "-c", str(config)]) == 1
    assert "--force" in capsys.readouterr().err


def test_configuration_errors_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[server]\nbogus = 1\n", encoding="utf-8")
    assert (
        main(["check", "-c", str(bad), "x.example:443"]) == 0
    )  # check reads rules only
    assert main(["run", "-c", str(bad)]) == 2
    assert "unknown key" in capsys.readouterr().err


def test_run_serves_until_stopped(config):
    assert main(["ca", "init", "-c", str(config)]) == 0
    process = subprocess.Popen(
        [sys.executable, "-m", "netproxy", "run", "-c", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = process.stdout.readline().strip()
        assert line.startswith("proxy http://127.0.0.1:"), process.stderr.read()
        port = int(line.rsplit(":", 1)[1])

        class Running:
            pass

        running = Running()
        running.port = port
        with Origin(tls=True) as origin:
            status, _, body = via_proxy(
                running, "GET", f"http://localhost:{origin.port}/cli"
            )
        assert status == 200 and json.loads(body)["client_cn"] == "client-rsa"
    finally:
        process.terminate()
        process.wait(10)
        process.stdout.close()
        process.stderr.close()


def test_help_and_a_usage_error_raise_system_exit():
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    with pytest.raises(SystemExit) as caught:
        main(["check"])
    assert caught.value.code == 2


def test_ctrl_c_stops_run_with_status_0(config, monkeypatch):
    import netproxy.cli.run as run_module

    def interrupted(coroutine):
        coroutine.close()
        raise KeyboardInterrupt

    assert main(["ca", "init", "-c", str(config)]) == 0
    monkeypatch.setattr(run_module.asyncio, "run", interrupted)
    assert main(["run", "-c", str(config)]) == 0


@pytest.mark.parametrize(
    "raised, status", [(KeyboardInterrupt, 130), (BrokenPipeError, 1)]
)
def test_ctrl_c_elsewhere_and_a_closed_pipe_end_quietly(
    config, monkeypatch, capsys, raised, status
):
    from netproxy.cli.check import Check

    def fail(self):
        raise raised

    monkeypatch.setattr(Check, "__call__", fail)
    assert main(["check", "-c", str(config), "www.example:443"]) == status
    assert "Traceback" not in capsys.readouterr().err
