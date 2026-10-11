# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app-native-host`: the browser extension's bridge to `passwords-appd`.

The browser starts one host per extension port and talks to it over stdin/stdout (see
`extension/PROTOCOL.md`). The host keeps no state and no secrets between requests and only
ever releases a password or code for an item the daemon itself matched to the page's URL.
Stderr ends up in the browser's console, so it only ever receives command names, error codes
and exception class names.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING, BinaryIO, Final

from passwords_app.browser.daemon import DaemonClient
from passwords_app.browser.framing import (
    MAX_PAYLOAD,
    MalformedError,
    Oversize,
    TooLargeError,
    decode_message,
    encode_frame,
    read_frame,
    write_frame,
)
from passwords_app.browser.protocol import (
    Code,
    Command,
    Fill,
    Match,
    ProtocolError,
    RequestId,
    Save,
    Status,
    code_result,
    command_name,
    failure,
    fill_result,
    match_result,
    not_allowed,
    ok,
    origin,
    parse_request,
    request_id,
    save_result,
    status_result,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_PROGRAM: Final = "passwords-app-native-host"
# A request makes several daemon calls (a save without item_id reads every same-username
# candidate), so the deadline bounds the whole request, not a call count: it must end before
# the extension gives up on the answer (DEFAULT_TIMEOUT_MS = 15 s in
# extension/src/background/native.ts), or a late answer is dropped and every request queued
# behind it times out too.
REQUEST_DEADLINE: Final = 12.0


def _log(line: str) -> None:
    sys.stderr.write(f"{_PROGRAM}: {line}\n")
    sys.stderr.flush()


class Host:
    """Answers one decoded frame at a time; never raises for anything a peer can send."""

    def __init__(self, daemon: DaemonClient, deadline: float = REQUEST_DEADLINE) -> None:
        self._daemon = daemon
        self._deadline = deadline

    async def handle(self, frame: bytes | Oversize) -> dict[str, object]:
        if isinstance(frame, Oversize):
            _log("too-large")
            return failure(None, "too-large", f"frame of {frame.length} bytes is over 1 MiB")
        try:
            message = decode_message(frame)
        except MalformedError as e:
            _log("malformed")
            return failure(None, "malformed", str(e))
        rid = request_id(message)
        cmd = command_name(message) or "?"
        try:
            request = parse_request(message)
            async with asyncio.timeout(self._deadline):
                result = await self._dispatch(request.command)
        except TimeoutError:
            _log(f"{cmd}: daemon-unavailable (deadline)")
            return failure(rid, "daemon-unavailable", "the daemon did not answer in time")
        except ProtocolError as e:
            _log(f"{cmd}: {e.code}")
            return failure(rid, e.code, e.message)
        # Last line of defence: one bad request must not end the browser's port.
        except Exception as e:  # noqa: BLE001
            _log(f"{cmd}: internal ({type(e).__name__})")
            return failure(rid, "internal", "unexpected failure in the native host")
        return ok(rid, result)

    async def _dispatch(self, command: Command) -> Mapping[str, object]:
        match command:
            case Status():
                return status_result(await self._daemon.status())
            case Match(url=url):
                return match_result(await self._daemon.match(url))
            case Fill(item_id=item_id, url=url):
                await self._require_candidate(item_id, url)
                login = await self._daemon.login(item_id)
                await self._require_candidate(item_id, url)
                return fill_result(login)
            case Code(item_id=item_id, url=url):
                await self._require_candidate(item_id, url)
                return code_result(*await self._fresh_code(item_id, url))
            case Save():
                return await self._save(command)

    async def _fresh_code(self, item_id: str, url: str) -> tuple[str, int]:
        # The recheck after GetCode spends part of the code's lifetime; report what is left
        # and fetch again when the code expired meanwhile (the request deadline bounds this).
        while True:
            fetched = time.monotonic()
            code, seconds_left = await self._daemon.code(item_id)
            await self._require_candidate(item_id, url)
            remaining = seconds_left - int(time.monotonic() - fetched)
            if remaining > 0:
                return code, remaining

    async def _require_candidate(self, item_id: str, url: str) -> None:
        # The daemon contract has no conditional Get/Save, so callers check before AND after
        # a read (and right before a write): an item that sync or the app moved to another
        # site in between is refused instead of answered for the old one. The remaining
        # check-then-Save window needs a daemon-side precondition (issue #13).
        candidates = await self._daemon.match(url)
        if not any(c.id == item_id for c in candidates):
            raise not_allowed()

    async def _save(self, request: Save) -> Mapping[str, object]:
        targets = await self._save_targets(request)
        if not targets:
            return await self._create(request)
        for target in targets:
            login = await self._daemon.login(target)
            if login.username == request.username and login.password == request.password:
                await self._require_candidate(target, request.url)
                return save_result("none", target, saved=False)
        target = targets[0]
        if request.dry_run:
            return save_result("update", target, saved=False)
        await self._require_candidate(target, request.url)
        fields = {"id": target, "username": request.username, "password": request.password}
        return save_result("update", await self._daemon.save(fields), saved=True)

    async def _save_targets(self, request: Save) -> list[str]:
        candidates = await self._daemon.match(request.url)
        if request.item_id is not None:
            if not any(c.id == request.item_id for c in candidates):
                raise not_allowed()
            return [request.item_id]
        # Best match first; several items for one username happen after merges.
        return [c.id for c in candidates if c.username == request.username]

    async def _create(self, request: Save) -> Mapping[str, object]:
        if request.dry_run:
            return save_result("create", None, saved=False)
        fields = {
            "url": origin(request.url),
            "username": request.username,
            "password": request.password,
        }
        if request.title:
            fields["title"] = request.title
        return save_result("create", await self._daemon.save(fields), saved=True)


def encode_response(response: Mapping[str, object]) -> bytes:
    """Frame `response`, or a `too-large` error with the same id when it does not fit."""
    try:
        return encode_frame(response)
    except TooLargeError:
        rid = response.get("id")
        echo: RequestId | None = rid if isinstance(rid, int | str) else None
        _log("too-large response")
        return encode_frame(
            failure(echo, "too-large", f"the answer is over the {MAX_PAYLOAD}-byte cap")
        )


async def serve(stdin: BinaryIO, stdout: BinaryIO, daemon: DaemonClient) -> int:
    """Answer frames from `stdin` until it ends; returns the exit status."""
    host = Host(daemon)
    try:
        while True:
            # A thread keeps the event loop free while the browser is idle between requests.
            try:
                frame = await asyncio.to_thread(read_frame, stdin)
            except OSError as e:
                _log(f"cannot read from the browser ({type(e).__name__})")
                return 1
            if frame is None:
                return 0
            response = await host.handle(frame)
            try:
                write_frame(stdout, encode_response(response))
            except BrokenPipeError:
                return 0  # the browser closed the port; nobody is left to answer
    finally:
        await daemon.close()


def main() -> int:
    # Browsers append arguments (manifest path, extension id, parent window); none matter.
    return asyncio.run(serve(sys.stdin.buffer, sys.stdout.buffer, DaemonClient()))


if __name__ == "__main__":
    sys.exit(main())
