"""Out-of-band interaction server for blind SSRF / XXE / RCE verification.

Shaidra starts a tiny HTTP listener, injects unique callback URLs into request
parameters, and — after the requests have been sent — checks whether the target
(or a service it can reach) fetched any of them. A callback is strong proof of
server-side request forgery: the value can only arrive if the server itself
made the request.

The listener binds loopback by default, which is reachable from local/lab
targets. To test a remote target, set ``oob_host`` in the config to a host that
forwards to this port.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import socket

_REQUEST_LINE_RE: re.Pattern[str] = re.compile(r"^[A-Z]+\s+(\S+)\s+HTTP/", re.ASCII)
_READ_LIMIT: int = 64 * 1024
_OK_RESPONSE: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class InteractionServer:
    """A loopback HTTP listener that records tokens seen in request paths."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._port = port
        self._server: asyncio.AbstractServer | None = None
        self._hits: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def port(self) -> int:
        """Bound port, known after :meth:`start`."""
        return self._port

    @property
    def running(self) -> bool:
        """Whether the listener is currently accepting connections."""
        return self._server is not None

    async def start(self) -> None:
        """Bind the listener; picks a free port when constructed with port 0."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        bound: list[socket.socket] = list(self._server.sockets or [])
        if bound:
            self._port = int(bound[0].getsockname()[1])

    async def stop(self) -> None:
        """Stop accepting connections and release the socket."""
        if self._server is None:
            return
        self._server.close()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()
        self._server = None

    def new_token(self) -> str:
        """Return a fresh, collision-resistant callback token."""
        return f"shaidra{secrets.token_hex(6)}"

    def callback_url(self, token: str, host: str | None = None) -> str:
        """Build the URL that a vulnerable server is expected to fetch."""
        return f"http://{host or self._host}:{self._port}/{token}"

    def received(self, token: str) -> bool:
        """Whether ``token`` has been seen in any request path."""
        return token in self._hits

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = b""
        with contextlib.suppress(asyncio.TimeoutError, ConnectionError, OSError):
            data = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=5.0)
        with contextlib.suppress(OSError):
            writer.write(_OK_RESPONSE)
            await writer.drain()
        self._record(data)
        with contextlib.suppress(OSError):
            writer.close()

    def _record(self, data: bytes) -> None:
        if not data:
            return
        first_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        match = _REQUEST_LINE_RE.match(first_line)
        if match is None:
            return
        token = match.group(1).strip("/").split("?", 1)[0].split("/", 1)[0]
        if token:
            self._hits.add(token)
