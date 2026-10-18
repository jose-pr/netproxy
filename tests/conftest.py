from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path
from typing import Iterator, NamedTuple

import pytest

DATA = Path(__file__).parent / "data"


def data(name: str) -> bytes:
    return (DATA / name).read_bytes()


_SHORT = {"organizationName": "O", "organizationalUnitName": "OU", "countryName": "C"}


class Handshake(NamedTuple):
    client_cn: str
    version: str


class TLSServer:
    """A loopback TLS server that requires a client certificate from the test CA.

    For each connection it completes the handshake and answers with the
    client certificate's common name (its whole subject when it has none)
    and the negotiated protocol version.
    """

    def __init__(
        self, client_sigalgs: str | None = None, trust: bytes | None = None
    ) -> None:
        self.context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH, cafile=str(DATA / "ca.pem")
        )
        self.context.verify_mode = ssl.CERT_REQUIRED
        if trust is not None:
            # A self-signed client certificate is its own trust anchor; strict
            # X.509 checking (on by default from Python 3.13) refuses that.
            self.context.load_verify_locations(cadata=trust)
            self.context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        self.context.load_cert_chain(DATA / "server.pem", DATA / "server.key")
        if client_sigalgs:
            restrict_client_sigalgs(self.context, client_sigalgs)
        self.errors: list[BaseException] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> TLSServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(5)
        self._listener.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except socket.timeout:
                continue
            raw.settimeout(5)
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    subject = dict(item[0] for item in tls.getpeercert()["subject"])
                    name = subject.get("commonName") or ",".join(
                        f"{_SHORT.get(k, k)}={v}" for k, v in subject.items()
                    )
                    tls.sendall(f"{name}\n{tls.version()}".encode())
            except (OSError, ssl.SSLError) as error:
                self.errors.append(error)
                raw.close()

    def handshake(self, context: ssl.SSLContext) -> Handshake:
        """Connect with ``context`` and return what the server saw."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                reply = b""
                while True:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    reply += chunk
        cn, version = reply.decode().split("\n")
        return Handshake(cn, version)


def restrict_client_sigalgs(context: ssl.SSLContext, sigalgs: str) -> None:
    """Limit the signature algorithms a server accepts from client certificates.

    The stdlib has no API for it; this reaches OpenSSL directly
    (SSL_CTX_set1_client_sigalgs_list).
    """
    from sslcontext._openssl import openssl, ssl_ctx_pointer

    lib = openssl()
    ok = lib.SSL_CTX_ctrl(ssl_ctx_pointer(lib, context), 102, 0, sigalgs.encode())
    assert ok == 1, sigalgs


@pytest.fixture
def tls_server() -> Iterator[TLSServer]:
    with TLSServer() as server:
        yield server


@pytest.fixture
def client_context() -> ssl.SSLContext:
    """A client context trusting the test CA and holding no identity yet."""
    return ssl.create_default_context(cafile=str(DATA / "ca.pem"))
