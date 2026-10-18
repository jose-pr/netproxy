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


class EchoServer:
    """A loopback TCP server that echoes each connection's bytes back."""

    def __init__(self) -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "EchoServer":
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
            threading.Thread(target=self._echo, args=(raw,), daemon=True).start()

    @staticmethod
    def _echo(raw: socket.socket) -> None:
        with raw:
            raw.settimeout(5)
            try:
                while True:
                    chunk = raw.recv(65536)
                    if not chunk:
                        return
                    raw.sendall(chunk)
            except OSError:
                return


def _pump(source: socket.socket, target: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            target.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class UpstreamProxy:
    """A minimal loopback CONNECT proxy standing in for a corporate proxy.

    ``requests`` records each CONNECT target and its Proxy-Authorization
    header; ``refuse=True`` answers 403.
    """

    def __init__(self, refuse: bool = False) -> None:
        self.refuse = refuse
        self.requests: list[tuple[str, str | None]] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "UpstreamProxy":
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
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        client.settimeout(10)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(4096)
            if not chunk:
                client.close()
                return
            head += chunk
        lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        target = lines[0].split(" ")[1]
        auth = next(
            (
                l.split(":", 1)[1].strip()
                for l in lines[1:]
                if l.lower().startswith("proxy-authorization:")
            ),
            None,
        )
        self.requests.append((target, auth))
        if self.refuse:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            client.close()
            return
        host, port = target.rsplit(":", 1)
        try:
            # Test origins listen on 127.0.0.1 only; skip the unused ::1 attempt.
            host = "127.0.0.1" if host == "localhost" else host.strip("[]")
            origin = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            client.close()
            return
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        back = threading.Thread(target=_pump, args=(origin, client), daemon=True)
        back.start()
        _pump(client, origin)
        back.join(10)
        client.close()
        origin.close()
