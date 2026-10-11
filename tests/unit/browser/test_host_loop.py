# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The host's read-answer loop over in-memory streams; no daemon is reachable here."""

from __future__ import annotations

import io
import json
import struct
from typing import TYPE_CHECKING, BinaryIO, cast, override

import pytest

from passwords_app.browser.daemon import DaemonClient
from passwords_app.browser.framing import MAX_PAYLOAD, encode_frame
from passwords_app.browser.native_host import Host, encode_response, serve

if TYPE_CHECKING:
    from pathlib import Path

    from passwords_app.browser.protocol import DaemonStatus

FAKE_PW = "fictional-Passw0rd-9"
URL = "https://accounts.example.com/login"


@pytest.fixture(autouse=True)
def no_bus(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Points at a socket that does not exist, so nothing can reach a real session bus.
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={tmp_path}/absent-bus")


def frame(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def request(message: dict[str, object]) -> bytes:
    return encode_frame(message)


def responses(data: bytes) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    while data:
        (length,) = struct.unpack("<I", data[:4])
        out.append(json.loads(data[4 : 4 + length]))
        data = data[4 + length :]
    return out


async def run(
    stdin_bytes: bytes, daemon: DaemonClient | None = None
) -> tuple[int, list[dict[str, object]]]:
    stdout = io.BytesIO()
    status = await serve(io.BytesIO(stdin_bytes), stdout, daemon or DaemonClient())
    return status, responses(stdout.getvalue())


def error(response: dict[str, object]) -> object:
    assert response["ok"] is False
    err = response["error"]
    assert isinstance(err, dict)
    return cast("dict[str, object]", err)["code"]


@pytest.mark.timeout(10)
async def test_eof_at_start_exits_zero_without_output() -> None:
    assert await run(b"") == (0, [])


@pytest.mark.timeout(10)
@pytest.mark.parametrize("tail", [b"\x10", b"\x10\x00\x00", struct.pack("<I", 50) + b'{"id":'])
async def test_eof_mid_frame_exits_zero_after_answering_earlier_requests(tail: bytes) -> None:
    status, out = await run(request({"id": 1, "cmd": "nope"}) + tail)
    assert status == 0
    assert len(out) == 1
    assert out[0]["id"] == 1


@pytest.mark.timeout(10)
async def test_eof_while_discarding_an_oversize_frame() -> None:
    status, out = await run(struct.pack("<I", MAX_PAYLOAD + 10) + b"x" * 100)
    assert (status, out) == (0, [])


@pytest.mark.timeout(10)
@pytest.mark.parametrize(
    "payload", [b"", b"\xff", b"{", b"[]", b"null", b"42", b'"s"', b'{"id":1,}', b"\xef\xbb\xbf{}"]
)
async def test_malformed_frames_answer_with_null_id(payload: bytes) -> None:
    _, out = await run(frame(payload))
    assert len(out) == 1
    assert out[0]["id"] is None
    assert error(out[0]) == "malformed"


@pytest.mark.timeout(10)
async def test_oversize_frame_then_valid_frame() -> None:
    data = frame(b" " * (MAX_PAYLOAD + 1)) + request({"id": 2, "cmd": "bogus"})
    _, out = await run(data)
    assert [r["id"] for r in out] == [None, 2]
    assert error(out[0]) == "too-large"
    assert error(out[1]) == "bad-request"


@pytest.mark.timeout(10)
async def test_every_request_gets_one_answer_in_order() -> None:
    frames = [
        request({"id": 1, "cmd": "match"}),
        frame(b"not json"),
        request({"id": "two", "cmd": "fill", "item_id": "X", "url": "ftp://example.com/"}),
        frame(b""),
        request({"id": 3, "cmd": "save", "url": URL, "username": "", "password": ""}),
        request({"id": True, "cmd": "status"}),
        request({"id": 4, "cmd": "status", "extra": 1}),
    ]
    status, out = await run(b"".join(frames))
    assert status == 0
    assert [r["id"] for r in out] == [1, None, "two", None, 3, None, 4]
    assert [error(r) for r in out] == [
        "bad-request",
        "malformed",
        "bad-request",
        "malformed",
        "bad-request",
        "bad-request",
        "bad-request",
    ]


@pytest.mark.timeout(10)
@pytest.mark.parametrize(
    "message",
    [
        {"id": 5, "cmd": "status"},
        {"id": 5, "cmd": "match", "url": URL},
        {"id": 5, "cmd": "fill", "item_id": "X", "url": URL},
        {"id": 5, "cmd": "code", "item_id": "X", "url": URL},
        {"id": 5, "cmd": "save", "url": URL, "username": "u", "password": FAKE_PW},
    ],
)
async def test_unreachable_bus_is_daemon_unavailable(message: dict[str, object]) -> None:
    _, out = await run(request(message))
    assert out[0]["id"] == 5
    assert error(out[0]) == "daemon-unavailable"


@pytest.mark.timeout(10)
async def test_secrets_never_reach_stderr_or_error_messages(
    capsys: pytest.CaptureFixture[str],
) -> None:
    frames = [
        request({"id": 1, "cmd": "save", "url": URL, "username": "u", "password": FAKE_PW}),
        request({"id": 2, "cmd": "save", "url": URL, "username": "u", "password": FAKE_PW, "x": 1}),
        request(
            {"id": 3, "cmd": "save", "url": "ftp://x.example", "username": "", "password": FAKE_PW}
        ),
        frame(json.dumps({"password": FAKE_PW}).encode() + b"!"),
    ]
    _, out = await run(b"".join(frames))
    assert len(out) == 4
    assert FAKE_PW not in json.dumps(out)
    assert FAKE_PW not in capsys.readouterr().err


@pytest.mark.timeout(10)
async def test_stderr_names_command_and_error_code(capsys: pytest.CaptureFixture[str]) -> None:
    await run(request({"id": 1, "cmd": "match", "url": URL}))
    assert capsys.readouterr().err == "passwords-app-native-host: match: daemon-unavailable\n"


class ExplodingDaemon(DaemonClient):
    @override
    async def status(self) -> DaemonStatus:
        msg = f"boom {FAKE_PW}"
        raise RuntimeError(msg)


@pytest.mark.timeout(10)
async def test_unexpected_exception_is_internal_and_secret_free(
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = request({"id": 9, "cmd": "status"}) + request({"id": 10, "cmd": "nope"})
    status, out = await run(data, ExplodingDaemon())
    assert status == 0
    assert [r["id"] for r in out] == [9, 10]
    assert error(out[0]) == "internal"
    err = capsys.readouterr().err
    assert "status: internal (RuntimeError)" in err
    assert FAKE_PW not in err
    assert FAKE_PW not in json.dumps(out)


class ClosedPipe:
    """stdout of a browser that already closed the port."""

    def write(self, _: bytes) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        pass


class FailingStdin:
    def read(self, _: int) -> bytes:
        raise OSError(5, "Input/output error")


def binary(stream: object) -> BinaryIO:
    # The host only calls read(n), write() and flush() on its streams.
    return cast("BinaryIO", stream)


@pytest.mark.timeout(10)
async def test_browser_gone_on_write_exits_zero() -> None:
    stdin = io.BytesIO(request({"id": 1, "cmd": "nope"}) * 3)
    assert await serve(stdin, binary(ClosedPipe()), DaemonClient()) == 0


@pytest.mark.timeout(10)
async def test_unreadable_stdin_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    assert await serve(binary(FailingStdin()), io.BytesIO(), DaemonClient()) == 1
    assert "cannot read from the browser (OSError)" in capsys.readouterr().err


@pytest.mark.timeout(10)
async def test_handle_accepts_raw_frames_directly() -> None:
    response = await Host(DaemonClient()).handle(b'{"id":"r","cmd":"status","x":1}')
    assert response["id"] == "r"
    assert error(response) == "bad-request"


def test_oversize_response_becomes_too_large_with_the_same_id() -> None:
    huge: dict[str, object] = {"id": 77, "ok": True, "result": {"items": ["x" * MAX_PAYLOAD]}}
    out = responses(encode_response(huge))
    assert len(out) == 1
    assert out[0]["id"] == 77
    assert error(out[0]) == "too-large"


def test_response_at_cap_is_sent_unchanged() -> None:
    overhead = len(encode_frame({"id": 1, "ok": True, "result": {"p": ""}})) - 4
    response: dict[str, object] = {
        "id": 1,
        "ok": True,
        "result": {"p": "x" * (MAX_PAYLOAD - overhead)},
    }
    assert responses(encode_response(response)) == [response]
