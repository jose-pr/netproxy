"""Loopback HTTP(S) origin servers that report what they received, as JSON."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA = Path(__file__).parent / "data"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # keep test output clean
        pass

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if not size:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(length) if length else b""
        client_cn = None
        if isinstance(self.connection, ssl.SSLSocket):
            certificate = self.connection.getpeercert()
            if certificate:
                client_cn = dict(i[0] for i in certificate["subject"]).get("commonName")
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("latin-1"),
                "client_cn": client_cn,
                "tls": isinstance(self.connection, ssl.SSLSocket),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = _reply


class Origin:
    """``Origin()`` serves plain HTTP; ``Origin(tls=True)`` HTTPS with the test
    server certificate, requiring a client certificate from the test CA."""

    def __init__(self, tls: bool = False) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        if tls:
            context = ssl.create_default_context(
                ssl.Purpose.CLIENT_AUTH, cafile=str(DATA / "ca.pem")
            )
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(DATA / "server.pem", DATA / "server.key")
            self.server.socket = context.wrap_socket(
                self.server.socket, server_side=True
            )
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "Origin":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(5)
