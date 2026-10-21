"""The root command and its error handling."""

from __future__ import annotations

from typing import Optional, Sequence

from duho import AUTO, Cli, LoggingArgs, run

from ..exceptions import ConfigError, NetProxyError
from .ca import Ca
from .check import Check
from .pac import Pac
from .run import Run

__all__ = ["NetProxy", "execute"]


class NetProxy(LoggingArgs, Cli):
    """A local proxy server that gives HTTP clients, browsers and plain TCP tools mutual TLS with keystore certificates, by rule."""

    _parsername_ = "netproxy"
    _logger_name_ = "netproxy"
    _version_ = AUTO
    _distribution_ = "netproxy"
    _subcommands_ = [Run, Check, Pac, Ca]
    # A configuration mistake is a wrong invocation (2); anything else that
    # failed at run time is 1. Each is reported as one line.
    _errors_ = {ConfigError: 2, NetProxyError: 1, OSError: 1}


def execute(argv: Optional[Sequence[str]] = None) -> int:
    return run(NetProxy, list(argv) if argv is not None else None, exit="parse")
