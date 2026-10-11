# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""An item edited (by sync or the app) between the host's site check and its read.

The daemon contract has no "Get only if it still matches this URL", so the host checks the
site both before and after reading a secret: a login that moved to another site between the
two calls never reaches the page that asked for the old one.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import override

import pytest

from passwords_app.browser.daemon import DaemonClient
from passwords_app.browser.native_host import REQUEST_DEADLINE, Host
from passwords_app.browser.protocol import Candidate, Login

OLD = "https://old.example.com/login"
ITEM = "item-1"
BANK_SECRET = "Bank-Fictional-7"


def _candidate() -> Candidate:
    return Candidate(
        id=ITEM,
        title="Old",
        username="alice",
        url="https://old.example.com",
        alt_urls=(),
        has_code=True,
    )


class MovingDaemon(DaemonClient):
    """The item matches `OLD` until the first read; the read moves it to another site."""

    def __init__(self) -> None:
        super().__init__()
        self.moved = False
        self.saved: list[dict[str, str]] = []

    @override
    async def match(self, url: str) -> list[Candidate]:
        return [] if self.moved else [_candidate()]

    @override
    async def login(self, item_id: str) -> Login:
        self.moved = True
        return Login("alice", BANK_SECRET)

    @override
    async def code(self, item_id: str) -> tuple[str, int]:
        self.moved = True
        return "123456", 20

    @override
    async def save(self, fields: dict[str, str]) -> str:  # type: ignore[override]
        self.saved.append(dict(fields))
        return ITEM


async def _ask(host: Host, **message: object) -> dict[str, object]:
    return await host.handle(json.dumps({"id": 1, "url": OLD, **message}).encode())


@pytest.mark.parametrize("cmd", ["fill", "code"])
async def test_secret_of_an_item_that_moved_mid_request_is_withheld(cmd: str) -> None:
    response = await _ask(Host(MovingDaemon()), cmd=cmd, item_id=ITEM)
    assert response["ok"] is False
    assert response["error"]["code"] == "not-allowed"  # type: ignore[index]
    assert BANK_SECRET not in json.dumps(response)
    assert "123456" not in json.dumps(response)


async def test_update_of_an_item_that_moved_after_the_comparison_is_refused() -> None:
    daemon = MovingDaemon()
    response = await Host(daemon).handle(
        json.dumps(
            {
                "id": 1,
                "cmd": "save",
                "url": OLD,
                "item_id": ITEM,
                "username": "alice",
                "password": "Page-Fictional-1",
            }
        ).encode()
    )
    assert response["ok"] is False
    assert daemon.saved == []


class SlowDaemon(MovingDaemon):
    """Every call takes `delay` seconds, each well inside the per-call D-Bus timeout."""

    def __init__(self, delay: float) -> None:
        super().__init__()
        self.delay = delay

    @override
    async def match(self, url: str) -> list[Candidate]:
        await asyncio.sleep(self.delay)
        return [_candidate()]

    @override
    async def login(self, item_id: str) -> Login:
        await asyncio.sleep(self.delay)
        return Login("alice", BANK_SECRET)


async def test_whole_request_is_bounded_below_the_extensions_timeout() -> None:
    # Three calls of 0.2 s each would answer after 0.6 s; the request deadline is 0.3 s.
    host = Host(SlowDaemon(0.2), deadline=0.3)
    started = time.monotonic()
    response = await _ask(host, cmd="fill", item_id=ITEM)
    assert time.monotonic() - started < 0.5
    assert response["ok"] is False
    assert response["error"]["code"] == "daemon-unavailable"  # type: ignore[index]
    assert BANK_SECRET not in json.dumps(response)


def test_default_deadline_leaves_the_extension_time_to_hear_the_answer() -> None:
    assert REQUEST_DEADLINE < 15.0  # extension/src/background/native.ts DEFAULT_TIMEOUT_MS


class ExpiringCodeDaemon(DaemonClient):
    """The first code has 1 s left and the recheck Match takes 1.1 s, so it expires."""

    def __init__(self) -> None:
        super().__init__()
        self.matches = 0
        self.codes = 0

    @override
    async def match(self, url: str) -> list[Candidate]:
        self.matches += 1
        if self.matches == 2:
            await asyncio.sleep(1.1)
        return [_candidate()]

    @override
    async def code(self, item_id: str) -> tuple[str, int]:
        self.codes += 1
        return ("111111", 1) if self.codes == 1 else ("222222", 30)


async def test_code_that_expired_during_the_recheck_is_fetched_again() -> None:
    daemon = ExpiringCodeDaemon()
    response = await _ask(Host(daemon, deadline=5.0), cmd="code", item_id=ITEM)
    assert response["ok"] is True
    result = response["result"]
    assert result["code"] == "222222"  # type: ignore[index]
    assert 0 < result["seconds_left"] <= 30  # type: ignore[index]
    assert daemon.codes == 2
