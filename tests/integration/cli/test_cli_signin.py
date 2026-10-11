# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app signin` end to end: terminal wizard -> D-Bus -> daemon -> account."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from tests.fakes.memory_stores import make_credential
from tests.integration.daemon.support import wait_for
from tests.unit.cli.terminal import ScriptedTerminal
from tests.unit.daemon.fakes import APPLE_ID, APPLE_PASSWORD, CODE, DEVICES, PASSCODE

from passwords_app.cli import main as cli
from passwords_app.cli.signin import CONFIRM_WORD

if TYPE_CHECKING:
    from tests.integration.daemon.support import RunningDaemon

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]


@pytest.fixture
def account_state() -> dict[str, bool]:
    return {"signed_in": False, "joined": False}


async def signin(
    running: RunningDaemon, answers: list[str], secrets: list[str], *argv: str
) -> tuple[int, ScriptedTerminal]:
    term = ScriptedTerminal(answers=answers, secrets=secrets)
    now = running.clock.now()
    ctx = cli.Context(terminal=term, now=lambda: now)
    code = await asyncio.to_thread(cli.main, ["signin", *argv], ctx=ctx)
    return code, term


async def test_complete_sign_in(running: RunningDaemon) -> None:
    running.remote.put(make_credential("FROM-IPHONE"))
    code, term = await signin(
        running, [APPLE_ID, CODE, "2", CONFIRM_WORD], [APPLE_PASSWORD, PASSCODE]
    )
    assert code == cli.EXIT_OK, term.output
    assert running.account.joined
    assert running.account.calls.count("join") == 1
    assert f"{DEVICES[1].name}" in term.output
    assert "escrow" not in term.everything.lower()
    await wait_for(lambda: "FROM-IPHONE" in running.local.items)


async def test_wrong_password_exits_with_sign_in_code(
    running: RunningDaemon, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = await signin(running, [APPLE_ID], ["not-it"])
    assert code == cli.EXIT_SIGN_IN
    assert "incorrect" in capsys.readouterr().err


async def test_declined_confirmation_sends_no_passcode(running: RunningDaemon) -> None:
    code, _ = await signin(running, [APPLE_ID, CODE, "1", "no"], [APPLE_PASSWORD])
    assert code == cli.EXIT_INTERRUPTED
    assert "join" not in running.account.calls
    assert running.daemon.status().state == "signin-required"


async def test_wrong_passcode_then_stop(running: RunningDaemon) -> None:
    code, term = await signin(
        running, [APPLE_ID, CODE, "1", CONFIRM_WORD, "n"], [APPLE_PASSWORD, "000000"]
    )
    assert code == cli.EXIT_INTERRUPTED
    assert "9 attempts left" in term.output
    assert running.account.attempts[DEVICES[0].id] == 9


async def test_apple_id_option(running: RunningDaemon) -> None:
    running.account.needs_code = False
    running.account.known_member = True
    code, term = await signin(running, [], [APPLE_PASSWORD], "--apple-id", APPLE_ID)
    assert code == cli.EXIT_OK
    assert term.prompts == []
