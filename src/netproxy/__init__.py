"""A rule-routed asyncio proxy server with per-destination mTLS."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._connection import Connection
from ._credential import Credential
from ._route import Action, Route, Router, Routing, Rule, TLSSource, Upstream
from .exceptions import (
    ConfigError,
    CredentialUnavailableError,
    NetProxyError,
    RejectedError,
    UpstreamError,
)

try:
    __version__ = version("netproxy")
except PackageNotFoundError:  # running from a checkout without an install
    __version__ = "0+unknown"

__all__ = [
    "Action",
    "Connection",
    "Credential",
    "Route",
    "Router",
    "Routing",
    "Rule",
    "TLSSource",
    "Upstream",
    "ConfigError",
    "CredentialUnavailableError",
    "NetProxyError",
    "RejectedError",
    "UpstreamError",
    "__version__",
]
