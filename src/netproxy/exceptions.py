"""Errors raised by :mod:`netproxy`.

A caller's bad argument raises plain :class:`TypeError` or :class:`ValueError`;
everything here is a failure found at run time.
"""

from __future__ import annotations

__all__ = [
    "ConfigError",
    "CredentialUnavailableError",
    "NetProxyError",
    "RejectedError",
    "UpstreamError",
]


class NetProxyError(Exception):
    """Base class for every error this package raises."""


class UpstreamError(NetProxyError, OSError):
    """The destination, or an upstream proxy on the way to it, could not be
    reached or refused the connection."""


class RejectedError(NetProxyError):
    """A rule rejected the connection."""


class CredentialUnavailableError(NetProxyError):
    """A route's client credential could not be loaded (keystore entry
    missing, no PIN, keystore failure)."""


class ConfigError(NetProxyError, ValueError):
    """A configuration document is malformed or inconsistent.

    ``path``, ``lineno`` and ``colno`` locate the problem when known; the
    message never quotes the document.
    """

    def __init__(
        self,
        msg: str,
        path: str | None = None,
        lineno: int | None = None,
        colno: int | None = None,
    ) -> None:
        where = ":".join(str(p) for p in (path, lineno, colno) if p is not None)
        super().__init__(f"{where}: {msg}" if where else msg)
        self.msg = msg
        self.path = path
        self.lineno = lineno
        self.colno = colno
