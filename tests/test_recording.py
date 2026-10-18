from __future__ import annotations

import logging
import socket
import sys

import pytest

from conftest import DATA, EchoServer, data
from netproxy import Credential, ProxyServer, Route, Router, Tunnel
from netproxy.intercept import create_ca
from netproxy.recording import LogRecorder, PcapRecorder
from origins import Origin
from test_http_proxy import via_proxy
from test_intercept import https_via


class ListRecorder:
    def __init__(self):
        self.events = []

    def opened(self, session):
        self.events.append(("opened", session.connection.authority))

    def data(self, session, sender, chunk):
        self.events.append(("data", sender, chunk))

    def ended(self, session, sender):
        self.events.append(("ended", sender))

    def closed(self, session):
        self.events.append(("closed",))

    def sent(self, sender):
        return b"".join(e[2] for e in self.events if e[0] == "data" and e[1] == sender)


class FailingRecorder(ListRecorder):
    def data(self, session, sender, chunk):
        raise RuntimeError("disk full")


def credential() -> Credential:
    return Credential.from_pem(
        data("client-rsa.pem"), data("client-rsa.key"), cafile=str(DATA / "ca.pem")
    )


def tunnel_round_trip(server, tunnel, payload):
    with socket.create_connection(server.tunnel_address(tunnel), timeout=10) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        reply = b""
        while chunk := sock.recv(65536):
            reply += chunk
    return reply


def test_recorders_see_every_octet_both_ways_and_each_end():
    recorder = ListRecorder()
    with EchoServer() as echo:
        tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}")
        with ProxyServer(listen=(), tunnels=[tunnel], recorders=[recorder]) as server:
            payload = b"0123456789" * 20_000
            assert tunnel_round_trip(server, tunnel, payload) == payload
    assert recorder.events[0] == ("opened", f"127.0.0.1:{echo.port}")
    assert recorder.events[-1] == ("closed",)
    assert recorder.sent("client") == payload == recorder.sent("server")
    assert {e for e in recorder.events if e[0] == "ended"} == {
        ("ended", "client"),
        ("ended", "server"),
    }


def test_a_failing_recorder_is_dropped_and_traffic_flows():
    good, bad = ListRecorder(), FailingRecorder()
    with EchoServer() as echo:
        tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}")
        with ProxyServer(listen=(), tunnels=[tunnel], recorders=[bad, good]) as server:
            assert tunnel_round_trip(server, tunnel, b"hello") == b"hello"
    assert good.sent("client") == b"hello"
    assert ("closed",) not in bad.events


def test_forwarded_requests_record_the_heads_as_rewritten():
    recorder = ListRecorder()
    with Origin() as origin, ProxyServer(recorders=[recorder]) as server:
        via_proxy(
            server,
            "GET",
            f"http://127.0.0.1:{origin.port}/rec",
            headers={"Proxy-Connection": "keep-alive"},
        )
    request = recorder.sent("client")
    response = recorder.sent("server")
    assert request.startswith(b"GET /rec HTTP/1.1\r\n")
    assert b"Proxy-Connection" not in request
    assert b"Connection: close" in response and b'"path": "/rec"' in response


def test_pcap_recorder_writes_the_plaintext_of_intercepted_mtls(tmp_path):
    pktcap = pytest.importorskip("pktcap")
    router = Router([("localhost", Route.with_tls(credential()))])
    ca = create_ca(router)
    capture = tmp_path / "proxy.pcap"
    with PcapRecorder(capture) as recorder:
        with Origin(tls=True) as origin:
            with ProxyServer(router, ca=ca, recorders=[recorder]) as server:
                status, seen = https_via(
                    server, "localhost", origin.port, "/recorded", ca.certificate
                )
    assert status == 200 and seen["client_cn"] == "client-rsa"
    directions = {}
    for item in pktcap.read_tcp_streams(str(capture)):
        directions.setdefault(item.source[1] == origin.port, b"")
        directions[item.source[1] == origin.port] += item.data
    assert directions[False].startswith(b"GET /recorded HTTP/1.1\r\n")
    assert b'"client_cn": "client-rsa"' in directions[True]


def test_keylog_receives_the_tls_secrets(tmp_path):
    router = Router([("localhost", Route.with_tls(credential()))])
    ca = create_ca(router)
    keylog = tmp_path / "keys.log"
    with Origin(tls=True) as origin:
        with ProxyServer(router, ca=ca, keylog=keylog) as server:
            https_via(server, "localhost", origin.port, "/", ca.certificate)
    lines = keylog.read_text().splitlines()
    labels = {
        line.split(" ", 1)[0] for line in lines if line and not line.startswith("#")
    }
    # Both TLS connections the proxy owns: the intercepted one and the mTLS one.
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in labels
    assert len([l for l in lines if l.startswith("CLIENT_TRAFFIC_SECRET_0")]) >= 2


def test_log_recorder_counts_octets(caplog):
    with EchoServer() as echo:
        tunnel = Tunnel("127.0.0.1:0", f"127.0.0.1:{echo.port}")
        with caplog.at_level(logging.INFO, logger="netproxy.traffic"):
            with ProxyServer(
                listen=(), tunnels=[tunnel], recorders=[LogRecorder()]
            ) as server:
                tunnel_round_trip(server, tunnel, b"x" * 1000)
    assert "1000 octets sent, 1000 received" in caplog.text


def test_pcap_recorder_without_the_extra_names_it(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "pktcap", None)
    with pytest.raises(ImportError, match=r"netproxy\[capture\]"):
        PcapRecorder(tmp_path / "x.pcap")
