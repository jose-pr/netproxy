"""Recording what passes through the proxy: a hook, a log, and pcap files.

A :class:`Recorder` sees each relayed connection as a :class:`Session`: when
it opens, every chunk each side sends, when each direction ends, and when it
closes. What it sees is what crossed the proxy: the plaintext of a TLS route
(the proxy made, or ended, that TLS) and of the request and response heads
it rewrote; the ciphertext of a tunnel it only relayed. Plaintext of an mTLS
session is as sensitive as the credentials that opened it; store it as such.

A recorder that raises is logged and stops receiving that session; traffic is
never affected.
"""

from __future__ import annotations

import itertools
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Union

from ._connection import Connection
from ._route import Route

__all__ = ["LogRecorder", "PcapRecorder", "Recorder", "Session"]

_log = logging.getLogger("netproxy")
_ids = itertools.count(1)


@dataclass(frozen=True)
class Session:
    """One relayed connection, as recorders see it."""

    id: int
    connection: Connection
    route: Route = field(repr=False)
    client: Optional[Tuple[str, int]]
    """The client's address."""
    server: Optional[Tuple[str, int]]
    """The address the proxy connected to: the destination, or the upstream
    proxy that tunnelled to it."""
    started: float
    """Seconds since the epoch."""


class Recorder(Protocol):
    """What the server calls for each relayed connection. Calls come from the
    event loop's thread, one session's in order; each must return quickly."""

    def opened(self, session: Session) -> None: ...

    def data(self, session: Session, sender: str, data: bytes) -> None:
        """``sender`` is ``"client"`` or ``"server"``."""

    def ended(self, session: Session, sender: str) -> None:
        """``sender``'s direction has no more data."""

    def closed(self, session: Session) -> None: ...


class LogRecorder:
    """Logs each session's opening and closing, with the octets each way, at
    ``level`` on ``logger`` (default ``netproxy.traffic``, INFO)."""

    def __init__(
        self,
        logger: Union[str, logging.Logger] = "netproxy.traffic",
        level: int = logging.INFO,
    ) -> None:
        self.logger = logging.getLogger(logger) if isinstance(logger, str) else logger
        self.level = level
        self._counts: Dict[int, List[int]] = {}

    def opened(self, session: Session) -> None:
        self._counts[session.id] = [0, 0]
        self.logger.log(
            self.level,
            "#%d open %s -> %s (%s)",
            session.id,
            session.client,
            session.connection.authority,
            session.route.action.value,
        )

    def data(self, session: Session, sender: str, data: bytes) -> None:
        counts = self._counts.get(session.id)
        if counts is not None:
            counts[0 if sender == "client" else 1] += len(data)

    def ended(self, session: Session, sender: str) -> None:
        pass

    def closed(self, session: Session) -> None:
        sent, received = self._counts.pop(session.id, [0, 0])
        self.logger.log(
            self.level,
            "#%d closed %s: %d octets sent, %d received",
            session.id,
            session.connection.authority,
            sent,
            received,
        )


class PcapRecorder:
    """Writes every session to a capture file as a TCP connection.

    Each session becomes one connection between the client's address and the
    address the proxy connected to, in the file at ``path`` (pcap, or pcapng
    when ``format="pcapng"``). The octets are those the proxy relayed, so a
    TLS route is recorded in plaintext on its TLS port: in Wireshark, *Decode
    As* HTTP. Needs the ``capture`` extra (pktcap). Thread-safe; close it
    (or use ``with``) to flush the file.
    """

    def __init__(
        self, path: Union[str, "os.PathLike[str]"], *, format: str = "pcap"
    ) -> None:
        try:
            import pktcap
        except ImportError:
            raise ImportError(
                'recording to a capture needs the "capture" extra: '
                'pip install "netproxy[capture]"'
            ) from None
        if format not in ("pcap", "pcapng"):
            raise ValueError(f"format must be 'pcap' or 'pcapng', not {format!r}")
        writer_class = pktcap.PcapWriter if format == "pcap" else pktcap.PcapngWriter
        self._pktcap = pktcap
        self._writer = writer_class(os.fspath(path))
        self._flows: Dict[int, Any] = {}
        self._lock = threading.Lock()

    def __enter__(self) -> "PcapRecorder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._flows.clear()
            self._writer.close()

    @staticmethod
    def _address(address: Optional[Tuple[str, int]], fallback: str) -> Tuple[str, int]:
        return (address[0], address[1]) if address else (fallback, 0)

    def opened(self, session: Session) -> None:
        flow = self._pktcap.TCPFlowWriter(
            self._writer,
            self._address(session.client, "127.0.0.1"),
            self._address(session.server, "0.0.0.0"),
        )
        with self._lock:
            flow.open(time.time())
            self._flows[session.id] = flow

    def data(self, session: Session, sender: str, data: bytes) -> None:
        with self._lock:
            flow = self._flows.get(session.id)
            if flow is not None:
                flow.send(time.time(), sender, data)

    def ended(self, session: Session, sender: str) -> None:
        with self._lock:
            flow = self._flows.get(session.id)
            if flow is not None:
                flow.close(time.time(), sender)

    def closed(self, session: Session) -> None:
        with self._lock:
            self._flows.pop(session.id, None)


class _Recording:
    """The server's side: fans one session out to its recorders."""

    def __init__(self, recorders: Iterable[Recorder], session: Session) -> None:
        self.session = session
        self._recorders = list(recorders)
        self._ended: set = set()
        self._each("opened")

    @classmethod
    def start(
        cls,
        recorders: Iterable[Recorder],
        connection: Connection,
        route: Route,
        client: Any,
        server: Any,
    ) -> "_Recording":
        session = Session(
            next(_ids),
            connection,
            route,
            (client[0], client[1]) if client else None,
            (server[0], server[1]) if server else None,
            time.time(),
        )
        return cls(recorders, session)

    def _each(self, method: str, *args: Any) -> None:
        for recorder in list(self._recorders):
            try:
                getattr(recorder, method)(self.session, *args)
            except Exception:  # noqa: BLE001 - a recorder must not break traffic
                _log.warning(
                    "netproxy: recorder %r failed in %s; it gets no more of session #%d",
                    recorder,
                    method,
                    self.session.id,
                    exc_info=True,
                )
                self._recorders.remove(recorder)

    def data(self, sender: str, data: bytes) -> None:
        if data:
            self._each("data", sender, data)

    def ended(self, sender: str) -> None:
        if sender not in self._ended:
            self._ended.add(sender)
            self._each("ended", sender)

    def closed(self) -> None:
        for sender in ("client", "server"):
            self.ended(sender)
        self._each("closed")
