"""What a rule sees about one incoming connection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from netimps import join_host

__all__ = ["Connection", "normalize_host"]


def normalize_host(host: str) -> str:
    """Lower case, no IPv6 brackets, no trailing root dot."""
    host = host.strip().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.lower()


@dataclass(frozen=True)
class Connection:
    """A connection the proxy is about to make, as rules see it.

    ``scheme`` is ``"https"`` for a CONNECT tunnel, ``"http"`` for a forwarded
    plain-HTTP request, ``"tcp"`` for a tunnel listener. ``path`` is set only
    for forwarded HTTP requests. ``client`` is the peer address, ``listener``
    the name of the listener that accepted it.
    """

    host: str
    port: int
    scheme: str = "https"
    path: Optional[str] = None
    client: Optional[Tuple[str, int]] = None
    listener: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", normalize_host(self.host))
        if not self.host:
            raise ValueError("a connection needs a host")
        if not 0 < self.port < 65536:
            raise ValueError(f"port out of range: {self.port}")

    @property
    def authority(self) -> str:
        """``host:port``, with IPv6 hosts bracketed."""
        return join_host(self.host, self.port)

    @property
    def url(self) -> str:
        """The destination as a URL, the key an upstream ``ProxyMap`` is asked."""
        scheme = "https" if self.scheme == "tcp" else self.scheme
        return f"{scheme}://{self.authority}{self.path or '/'}"
