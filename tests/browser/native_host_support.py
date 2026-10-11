# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Drive a real `passwords-app-native-host` process the way a browser does, for tests.

Reads use `select` with a deadline so a host that stops answering fails the test instead of
hanging it.
"""

from __future__ import annotations

import json
import os
import select
import struct
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Self, cast

from passwords_app.browser.framing import encode_frame

if TYPE_CHECKING:
    from collections.abc import Mapping

HOST_MODULE = "passwords_app.browser.native_host"
DEFAULT_TIMEOUT = 15.0


class HostProcess:
    """One host subprocess; `env` must point it at a private bus."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv, our own interpreter
            [sys.executable, "-m", HOST_MODULE, "chrome-extension://test.example/"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
        )
        self.stderr = ""
        self.returncode: int | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def send_raw(self, data: bytes) -> None:
        stdin = self.proc.stdin
        assert stdin is not None
        stdin.write(data)
        stdin.flush()

    def send(self, message: Mapping[str, object]) -> None:
        self.send_raw(encode_frame(message))

    def _read_exact(self, size: int, deadline: float) -> bytes:
        stdout = self.proc.stdout
        assert stdout is not None
        fd = stdout.fileno()
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            left = deadline - time.monotonic()
            if left <= 0:
                msg = "the native host did not answer in time"
                raise TimeoutError(msg)
            ready, _, _ = select.select([fd], [], [], left)
            if not ready:
                continue
            chunk = os.read(fd, remaining)
            if not chunk:
                msg = "the native host closed stdout"
                raise EOFError(msg)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def receive(self, timeout: float = DEFAULT_TIMEOUT) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        (length,) = struct.unpack("<I", self._read_exact(4, deadline))
        value = json.loads(self._read_exact(length, deadline))
        assert isinstance(value, dict)
        return cast("dict[str, object]", value)

    def request(
        self, message: Mapping[str, object], timeout: float = DEFAULT_TIMEOUT
    ) -> dict[str, object]:
        self.send(message)
        return self.receive(timeout)

    def close(self, timeout: float = DEFAULT_TIMEOUT) -> int:
        """Close stdin like a browser closing the port; returns the exit status."""
        if self.returncode is not None:
            return self.returncode
        try:
            _, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        self.stderr = err.decode("utf-8", "replace")
        returncode = self.proc.wait()
        self.returncode = returncode
        return returncode


def result(response: Mapping[str, object]) -> dict[str, object]:
    """The `result` of a successful response (fails the test on an error response)."""
    assert response.get("ok") is True, response.get("error")
    value = response["result"]
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def error_code(response: Mapping[str, object]) -> str:
    assert response.get("ok") is False, "expected an error response"
    err = response["error"]
    assert isinstance(err, dict)
    code = cast("dict[str, object]", err)["code"]
    assert isinstance(code, str)
    return code


def candidates(response: Mapping[str, object]) -> list[dict[str, object]]:
    """The `items` of a successful `match` response."""
    items = result(response)["items"]
    assert isinstance(items, list)
    out: list[dict[str, object]] = []
    for item in cast("list[object]", items):
        assert isinstance(item, dict)
        out.append(cast("dict[str, object]", item))
    return out
