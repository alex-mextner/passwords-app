# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app` subcommands against the real daemon on a private session bus.

The CLI runs in a worker thread (it owns its own event loop, as in a terminal) while the
daemon keeps serving from the test's loop.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Protocol

import pytest
from tests.fakes.memory_stores import make_credential
from tests.unit.cli.terminal import ScriptedTerminal
from tests.unit.daemon.otp_fixtures import RFC_SEED, otpauth_uri

from passwords_app.cli import main as cli

if TYPE_CHECKING:
    from datetime import datetime

    from tests.integration.daemon.support import RunningDaemon

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

HIDDEN = "cli-test-hidden-value"


class CliRun(Protocol):
    async def __call__(self, *argv: str, answers: list[str] | None = None) -> Run: ...


class Run:
    def __init__(self, code: int, term: ScriptedTerminal, err: str) -> None:
        self.code = code
        self.term = term
        self.out = term.output
        self.err = err


@pytest.fixture
def cli_run(running: RunningDaemon, capsys: pytest.CaptureFixture[str]) -> CliRun:
    async def run(*argv: str, answers: list[str] | None = None) -> Run:
        term = ScriptedTerminal(answers=list(answers or []))
        now: datetime = running.clock.now()
        ctx = cli.Context(terminal=term, now=lambda: now)
        code = await asyncio.to_thread(cli.main, list(argv), ctx=ctx)
        return Run(code, term, capsys.readouterr().err)

    return run


@pytest.fixture
async def items(running: RunningDaemon) -> None:
    running.remote.put(
        make_credential("MAIL", url="https://mail.example.com", title="Mail", password=HIDDEN)
    )
    running.remote.put(
        make_credential(
            "SHOP", url="https://shop.example.com", otpauth=otpauth_uri(), username="bob"
        )
    )
    running.remote.put(make_credential("SHOP2", url="https://shop.example.org", username="bob"))
    await running.daemon.sync_now()


async def test_status(cli_run: CliRun, running: RunningDaemon) -> None:
    run = await cli_run("status")
    assert run.code == 0
    assert "Passwords:  Up to date" in run.out
    assert "Account:    alice@example.com" in run.out


async def test_status_json(cli_run: CliRun) -> None:
    run = await cli_run("status", "--json")
    data = json.loads(run.out)
    assert data["state"] == "idle"
    assert set(data) >= {"apple_id", "item_count", "last_sync", "pending_local_deletions"}


@pytest.mark.usefixtures("items")
async def test_list(cli_run: CliRun) -> None:
    run = await cli_run("list")
    assert run.code == 0
    assert [line.split()[-1] for line in run.out.splitlines()[1:]] == ["MAIL", "SHOP", "SHOP2"]
    assert HIDDEN not in run.out


@pytest.mark.usefixtures("items")
async def test_list_query_and_json(cli_run: CliRun) -> None:
    run = await cli_run("list", "shop", "--json")
    assert [i["id"] for i in json.loads(run.out)] == ["SHOP", "SHOP2"]
    assert HIDDEN not in run.out


@pytest.mark.usefixtures("items")
async def test_show_masks_by_default(cli_run: CliRun) -> None:
    run = await cli_run("show", "Mail")
    assert run.code == 0
    assert HIDDEN not in run.out
    assert "••••••••" in run.out


@pytest.mark.usefixtures("items")
async def test_show_password_on_request(cli_run: CliRun) -> None:
    run = await cli_run("show", "MAIL", "--password")
    assert f"Password:  {HIDDEN}" in run.out


@pytest.mark.usefixtures("items")
async def test_show_code_never_seed(cli_run: CliRun) -> None:
    run = await cli_run("show", "SHOP", "--json")
    data = json.loads(run.out)
    assert len(data["code"]) == 6
    assert 1 <= data["code_seconds_left"] <= 30
    assert "otpauth" not in data
    assert "password" not in data
    assert RFC_SEED not in run.out


@pytest.mark.usefixtures("items")
async def test_show_ambiguous(cli_run: CliRun) -> None:
    run = await cli_run("show", "bob")
    assert run.code == cli.EXIT_USAGE
    assert "2 passwords match" in run.err


@pytest.mark.usefixtures("items")
async def test_show_unknown(cli_run: CliRun) -> None:
    run = await cli_run("show", "nothing-like-this")
    assert run.code == cli.EXIT_NOT_FOUND


async def test_sync(cli_run: CliRun, running: RunningDaemon) -> None:
    running.remote.put(make_credential("NEW"))
    run = await cli_run("sync")
    assert run.code == 0
    assert "NEW" in running.local.items


async def test_sync_offline_needs_attention(cli_run: CliRun, running: RunningDaemon) -> None:
    running.remote.offline = True
    run = await cli_run("sync")
    assert run.code == cli.EXIT_FAILED
    assert "Offline" in run.out


@pytest.mark.usefixtures("items")
async def test_trash_restore_and_purge(cli_run: CliRun, running: RunningDaemon) -> None:
    await running.daemon.delete("MAIL")
    await running.daemon.delete("SHOP2")
    listing = await cli_run("trash")
    assert "deleted on this computer" in listing.out
    ids = [line.split()[-1] for line in listing.out.splitlines()[1:]]
    assert len(ids) == 2
    restored = await cli_run("trash", "restore", ids[0])
    assert restored.code == 0
    assert "Restored as" in restored.out
    kept = await cli_run("trash", "purge", ids[1], answers=["n"])
    assert "Kept." in kept.out
    assert len(running.daemon.trash()) == 1
    purged = await cli_run("trash", "purge", ids[1], "--yes")
    assert purged.code == 0
    assert running.daemon.trash() == []


async def test_trash_restore_unknown(cli_run: CliRun) -> None:
    run = await cli_run("trash", "restore", "f" * 32)
    assert run.code == cli.EXIT_NOT_FOUND


async def test_resolve_without_pause_is_invalid(cli_run: CliRun) -> None:
    run = await cli_run("resolve", "apply")
    assert run.code == cli.EXIT_INVALID
    assert "Nothing is waiting" in run.err


async def test_resolve_restore_after_pause(cli_run: CliRun, running: RunningDaemon) -> None:
    for i in range(6):
        running.remote.put(make_credential(f"P{i}"))
    await running.daemon.sync_now()
    for i in range(6):
        running.remote.remove(f"P{i}")
    paused = await cli_run("sync")
    assert paused.code == cli.EXIT_FAILED
    assert "passwords-app resolve" in paused.out
    run = await cli_run("resolve", "restore")
    assert run.code == 0
    assert len(running.remote.items) == 6


async def test_locked_keyring(cli_run: CliRun, running: RunningDaemon) -> None:
    running.local.put(make_credential("A"))
    running.local.lock()
    run = await cli_run("list")
    assert run.code == cli.EXIT_LOCKED
    assert "Seahorse" in run.err


async def test_signout_asks_first(cli_run: CliRun, running: RunningDaemon) -> None:
    run = await cli_run("signout", answers=[""])
    assert "Still signed in" in run.out
    assert running.daemon.status().state != "signed-out"
    run = await cli_run("signout", "--yes")
    assert run.code == 0
    assert running.daemon.status().state == "signed-out"
    after = await cli_run("sync")
    assert after.code == cli.EXIT_SIGN_IN


async def test_cli_output_never_mentions_escrow(cli_run: CliRun) -> None:
    for argv in (["status"], ["list"], ["trash"]):
        assert "escrow" not in (await cli_run(*argv)).out.lower()
