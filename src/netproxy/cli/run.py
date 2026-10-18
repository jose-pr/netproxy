"""``netproxy run``: serve until interrupted."""

from __future__ import annotations

import asyncio
import sys

from netimps import join_host

from ._common import ConfigCommand

__all__ = ["Run"]


class Run(ConfigCommand):
    """Start the proxy described by the configuration file and serve until Ctrl-C."""

    _parsername_ = "run"
    # A long-running server is not a tool call.
    _mcp_ = False

    def __call__(self) -> int:
        server = self.server()
        try:
            asyncio.run(self.serve(server))
        except KeyboardInterrupt:
            pass
        return 0

    async def serve(self, server) -> None:  # type: ignore[no-untyped-def]
        await server.start()
        for host, port in server.addresses:
            print(f"proxy http://{join_host(host, port)}", flush=True)
        for tunnel in server.tunnels:
            host, port = server.tunnel_address(tunnel)
            print(f"tunnel {join_host(host, port)} -> {tunnel.target}", flush=True)
        try:
            await server.serve_forever()
        finally:
            await server.aclose()
            print("stopped", file=sys.stderr)
