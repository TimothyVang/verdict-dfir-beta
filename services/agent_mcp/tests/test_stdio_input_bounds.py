"""Byte-level ingress limits for the Python custody MCP stdio transport."""

from __future__ import annotations

import pytest

from findevil_agent_mcp.server import BoundedStdin, JsonRpcFrameError


class _Bytes:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def readline(self, limit: int = -1) -> bytes:
        if not self._payload:
            return b""
        newline = self._payload.find(b"\n")
        available = len(self._payload) if newline < 0 else newline + 1
        size = available if limit < 0 else min(available, limit)
        chunk, self._payload = self._payload[:size], self._payload[size:]
        return chunk


async def _read_one(payload: bytes, limit: int) -> str:
    return await anext(BoundedStdin(_Bytes(payload), max_frame_bytes=limit))


@pytest.mark.asyncio
async def test_bounded_stdin_accepts_exact_wire_byte_ceiling() -> None:
    frame = b'{"jsonrpc":"2.0"}\n'

    assert await _read_one(frame, len(frame)) == frame.decode("utf-8")


@pytest.mark.asyncio
async def test_bounded_stdin_rejects_multibyte_frame_by_wire_bytes() -> None:
    frame = ('{"method":"' + "é" * 8 + '"}\n').encode("utf-8")
    character_count = len(frame.decode("utf-8"))
    assert len(frame) > character_count

    with pytest.raises(JsonRpcFrameError, match="frame limit"):
        await _read_one(frame, character_count)


@pytest.mark.asyncio
async def test_bounded_stdin_rejects_unterminated_frame() -> None:
    with pytest.raises(JsonRpcFrameError, match="unterminated"):
        await _read_one(b'{"jsonrpc":"2.0"}', 64)


@pytest.mark.asyncio
async def test_bounded_stdin_rejects_invalid_utf8() -> None:
    with pytest.raises(JsonRpcFrameError, match="valid UTF-8"):
        await _read_one(b'{"jsonrpc":"2.0","method":"\xff"}\n', 64)


@pytest.mark.asyncio
async def test_bounded_stdin_stops_cleanly_at_empty_eof() -> None:
    with pytest.raises(StopAsyncIteration):
        await anext(BoundedStdin(_Bytes(b""), max_frame_bytes=64))
