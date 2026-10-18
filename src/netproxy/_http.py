"""The HTTP proxy front-end (filled in by the next phase)."""

from __future__ import annotations

import asyncio
from typing import Any

__all__ = ["handle_http_proxy"]


async def handle_http_proxy(
    server: Any, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    writer.write(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
    await writer.drain()
