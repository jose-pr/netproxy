"""Stream helpers the standard library lacks before Python 3.11."""

from __future__ import annotations

import asyncio
import ssl
from typing import Optional

__all__ = ["start_tls"]


async def start_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    context: ssl.SSLContext,
    *,
    server_side: bool = False,
    server_hostname: Optional[str] = None,
    timeout: Optional[float] = None,
) -> None:
    """Upgrade an open stream pair to TLS in place.

    ``StreamWriter.start_tls`` exists from Python 3.11; before that the same
    steps are done here: hand the transport to ``loop.start_tls`` and point
    the writer and the protocol at the TLS transport it returns. Bytes the
    reader already buffered are not part of the handshake, so the caller must
    not have read past the plaintext it expected.
    """
    await writer.drain()
    loop = asyncio.get_running_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    tls_transport = await loop.start_tls(
        transport,
        protocol,
        context,
        server_side=server_side,
        server_hostname=None if server_side else server_hostname,
        ssl_handshake_timeout=timeout,
    )
    if tls_transport is None:  # pragma: no cover - the loop closed it
        raise ConnectionError("TLS handshake did not complete")
    writer._transport = tls_transport  # type: ignore[attr-defined]
    if hasattr(protocol, "_replace_transport"):
        protocol._replace_transport(tls_transport)
    else:  # Python < 3.11
        protocol._transport = tls_transport
        protocol._over_ssl = True
