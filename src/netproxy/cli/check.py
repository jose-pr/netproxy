"""``netproxy check``: which rule and route a destination gets."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from netimps import get_default_port, split_host

from ..config import build_router
from .._connection import Connection
from .._credential import Credential
from ._common import ConfigCommand

__all__ = ["Check"]


class Check(ConfigCommand):
    """Show the rule and route the configuration picks for a destination, without connecting."""

    _parsername_ = "check"

    target: str
    "A URL (https://host/path) or HOST:PORT (a CONNECT destination)"
    ("target",)

    listener: str = "proxy"
    "The listener the connection arrives on: proxy, or a tunnel's name"
    ("--listener",)

    json_output: bool = False
    "Print one JSON object instead of a line"
    ("--json",)

    def connection(self) -> Connection:
        if "://" in self.target:
            url = urlsplit(self.target)
            scheme = url.scheme.lower()
            path = (url.path or "/") + (f"?{url.query}" if url.query else "")
            port = url.port or get_default_port(scheme) or 443
            return Connection(
                url.hostname or "", port, scheme, path=path, listener=self.listener
            )
        host, port = split_host(self.target, default_port=443)
        return Connection(str(host), int(port), "https", listener=self.listener)

    def __call__(self) -> int:
        router = build_router(self.document(), base_dir=self.config_path().parent)
        connection = self.connection()
        rule, route = router.explain(connection)
        result = {
            "destination": connection.url,
            "rule": (rule.name or route.name or "matched") if rule else "default",
            "action": route.action.value,
            "credential": (
                route.tls.name
                if isinstance(route.tls, Credential)
                else ("context" if route.tls is not None else None)
            ),
            "upstream": route.upstream if isinstance(route.upstream, str) else None,
        }
        if self.json_output:
            print(json.dumps(result))
        else:
            print(" ".join(f"{k}={v}" for k, v in result.items() if v is not None))
        return 0
