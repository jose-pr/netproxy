"""``netproxy pac``: the PAC script the proxy would serve."""

from __future__ import annotations

from typing import Optional

from netimps import parse_listen, join_host

from ..config import build_router
from ..pac import generate_pac
from ._common import ConfigCommand

__all__ = ["Pac"]


class Pac(ConfigCommand):
    """Print the proxy auto-config (PAC) script generated from the configuration's rules."""

    _parsername_ = "pac"

    proxy: Optional[str] = None
    "The proxy address the script points at, HOST:PORT. Omitted: the configuration's first listen address"
    ("--proxy",)

    def proxy_address(self, document: dict) -> str:
        if self.proxy:
            return self.proxy
        listen = document.get("server", {}).get("listen") or "127.0.0.1:3128"
        first = parse_listen(listen, 3128)[0]
        return join_host(str(first.address), first.port)

    def __call__(self) -> int:
        document = self.document()
        router = build_router(document, base_dir=self.config_path().parent)
        egress = document.get("server", {}).get("egress")
        print(
            generate_pac(
                router,
                self.proxy_address(document),
                egress=None if egress in (None, "direct") else egress,
            ),
            end="",
        )
        return 0
