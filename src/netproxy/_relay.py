"""Copy bytes both ways between two streams until both directions end."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

__all__ = ["DataHook", "EndHook", "relay"]

DataHook = Callable[[str, bytes], None]
"""Called with ``"client"`` or ``"server"`` (who sent it) and the bytes."""

EndHook = Callable[[str], None]
"""Called with ``"client"`` or ``"server"`` when that side's direction ends."""

_CHUNK = 65536


async def _pump(
    source: asyncio.StreamReader,
    target: asyncio.StreamWriter,
    direction: str,
    idle_timeout: Optional[float],
    on_data: Optional[DataHook],
    before: Optional[Callable[[], Awaitable[None]]] = None,
    on_end: Optional[EndHook] = None,
) -> None:
    try:
        if before is not None:
            await before()
        while True:
            chunk = await asyncio.wait_for(source.read(_CHUNK), idle_timeout)
            if not chunk:
                break
            if on_data is not None:
                on_data(direction, chunk)
            target.write(chunk)
            await target.drain()
    finally:
        if on_end is not None:
            on_end(direction)
        # Pass the end on: half-close where the transport can (plain TCP),
        # otherwise (TLS) the whole connection ends with this direction.
        try:
            if target.can_write_eof():
                target.write_eof()
            else:
                target.close()
        except (OSError, RuntimeError):
            pass


async def relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    *,
    idle_timeout: Optional[float] = None,
    on_data: Optional[DataHook] = None,
    before_server: Optional[Callable[[], Awaitable[None]]] = None,
    on_end: Optional[EndHook] = None,
) -> None:
    """Relay until both directions have ended, then close both streams.

    ``idle_timeout`` (seconds) ends a direction that receives nothing for that
    long. ``before_server`` runs before server-to-client bytes flow (while the
    client's keep flowing), e.g. to rewrite a response head. ``on_data`` sees
    each chunk and ``on_end`` each direction's end. Connection errors end the
    relay quietly: either side going away is how a proxied connection
    normally finishes.
    """
    pumps = [
        asyncio.ensure_future(
            _pump(
                client_reader,
                server_writer,
                "client",
                idle_timeout,
                on_data,
                on_end=on_end,
            )
        ),
        asyncio.ensure_future(
            _pump(
                server_reader,
                client_writer,
                "server",
                idle_timeout,
                on_data,
                before_server,
                on_end,
            )
        ),
    ]
    try:
        results = await asyncio.gather(*pumps, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException) and not isinstance(
                result, (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError)
            ):
                raise result
    finally:
        for pump in pumps:
            pump.cancel()
        for writer in (client_writer, server_writer):
            writer.close()
        for writer in (client_writer, server_writer):
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
