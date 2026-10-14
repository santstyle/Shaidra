"""Tests for the out-of-band interaction server used to confirm blind SSRF.

Binds a real loopback listener on an ephemeral port and drives it with raw
HTTP client connections, exercising token recording end to end.
"""

from __future__ import annotations

import asyncio
import contextlib
import re

from shaidra.utils.oob import InteractionServer

_TOKEN_RE = re.compile(r"^shaidra[0-9a-f]{12}$")


async def _send(port: int, request: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        # server may never reply to garbage; we only care it survives
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(reader.read(64), timeout=2.0)
    finally:
        writer.close()


class TestLifecycle:
    def test_start_binds_ephemeral_port_and_stop_releases(self) -> None:
        async def _round_trip() -> int:
            server = InteractionServer()
            assert server.running is False
            await server.start()
            assert server.running is True
            assert server.port > 0
            port = server.port
            await server.stop()
            assert server.running is False
            return port

        assert asyncio.run(_round_trip()) > 0

    def test_start_is_idempotent(self) -> None:
        async def _scenario() -> int:
            server = InteractionServer()
            await server.start()
            first_port = server.port
            await server.start()
            assert server.port == first_port
            await server.stop()
            return first_port

        asyncio.run(_scenario())

    def test_stop_without_start_is_noop(self) -> None:
        asyncio.run(InteractionServer().stop())


class TestTokensAndUrls:
    def test_new_token_matches_expected_shape(self) -> None:
        server = InteractionServer()
        token = server.new_token()
        assert _TOKEN_RE.match(token), token

    def test_tokens_are_unique(self) -> None:
        server = InteractionServer()
        tokens = {server.new_token() for _ in range(50)}
        assert len(tokens) == 50

    def test_callback_url_defaults_to_bound_host(self) -> None:
        server = InteractionServer(host="127.0.0.1", port=9999)
        assert server.callback_url("tok") == "http://127.0.0.1:9999/tok"

    def test_callback_url_uses_override_host(self) -> None:
        server = InteractionServer(host="127.0.0.1", port=9999)
        assert server.callback_url("tok", host="oob.example") == "http://oob.example:9999/tok"


class TestCallbackRecording:
    def test_get_request_path_token_is_recorded(self) -> None:
        async def _scenario() -> bool:
            server = InteractionServer()
            await server.start()
            try:
                token = server.new_token()
                assert server.received(token) is False
                await _send(server.port, f"GET /{token} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                return server.received(token)
            finally:
                await server.stop()

        assert asyncio.run(_scenario()) is True

    def test_query_string_and_extra_path_segments_are_stripped(self) -> None:
        async def _scenario() -> bool:
            server = InteractionServer()
            await server.start()
            try:
                token = server.new_token()
                await _send(server.port, f"GET /{token}?x=1&y=2 HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                return server.received(token)
            finally:
                await server.stop()

        assert asyncio.run(_scenario()) is True

    def test_unknown_token_stays_unseen(self) -> None:
        async def _scenario() -> bool:
            server = InteractionServer()
            await server.start()
            try:
                await _send(server.port, b"GET /shaidra000000000000 HTTP/1.1\r\nHost: x\r\n\r\n")
                return server.received(server.new_token())
            finally:
                await server.stop()

        assert asyncio.run(_scenario()) is False

    def test_garbage_request_does_not_raise(self) -> None:
        async def _scenario() -> None:
            server = InteractionServer()
            await server.start()
            try:
                await _send(server.port, b"not an http request at all\r\n\r\n")
                await _send(server.port, b"")
            finally:
                await server.stop()

        asyncio.run(_scenario())

    def test_record_handles_empty_and_malformed_lines(self) -> None:
        server = InteractionServer()
        server._record(b"")
        server._record(b"garbage")
        assert server.received("anything") is False
