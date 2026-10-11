# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Known secret values never reach the logs, whatever path they travel through the daemon.

Every logger (ours, dbus-fast's, asyncio's) is captured at DEBUG while a session exercises
each place a secret enters or leaves: sign-in (password, code, passcode, right and wrong),
Save/Get of passwords and TOTP seeds, GetCode, sync cycles that fail, and a store error.
"""

from __future__ import annotations

import logging

import pytest
from dbus_fast import Variant
from tests.fakes.memory_stores import make_credential
from tests.integration.daemon.support import CallError, Client, RunningDaemon
from tests.unit.daemon.fakes import APPLE_ID, APPLE_PASSWORD, CODE, DEVICES, PASSCODE
from tests.unit.daemon.otp_fixtures import RFC_SEED, otpauth_uri

from passwords_app.sync.ports import AuthRequired

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

ITEM_PASSWORD = "item-pw-never-logged-7f3a"  # gitleaks:allow
WRONG_PASSWORD = "wrong-apple-pw-9c1d"
WRONG_PASSCODE = "864209"


@pytest.fixture
def account_state() -> dict[str, bool]:
    return {"signed_in": False, "joined": False}


@pytest.fixture(autouse=True)
def debug_everything(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    for name in ("passwords_app", "dbus_fast", "asyncio"):
        caplog.set_level(logging.DEBUG, logger=name)


async def session(client: Client, running: RunningDaemon) -> None:
    otp = otpauth_uri(issuer="Shop")
    with pytest.raises(CallError):
        await client.call("SignInStart", "ss", APPLE_ID, WRONG_PASSWORD)
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD)
    with pytest.raises(CallError):
        await client.call("SignInCode", "s", "000000")
    await client.call("SignInCode", "s", CODE)
    await client.call("ListRecoveryDevices")
    with pytest.raises(CallError):
        await client.call("JoinKeychain", "ss", DEVICES[0].id, WRONG_PASSCODE)
    await client.call("JoinKeychain", "ss", DEVICES[0].id, PASSCODE)
    item = {
        "url": Variant("s", "https://shop.example.com"),
        "username": Variant("s", "ann"),
        "password": Variant("s", ITEM_PASSWORD),
        "otpauth": Variant("s", otp),
    }
    new_id = await client.one("Save", "a{sv}", item)
    await client.call("Get", "s", new_id)
    await client.call("GetCode", "s", new_id)
    with pytest.raises(CallError):
        await client.call("Save", "a{sv}", {**item, "otpauth": Variant("s", otp + "&digits=99")})
    with pytest.raises(CallError):
        await client.call("Save", "a{sv}", {"password": Variant("as", [ITEM_PASSWORD])})
    running.remote.put(make_credential("R", password=ITEM_PASSWORD, otpauth=otp))
    await client.call("SyncNow")
    running.remote.fail_next("fetch", AuthRequired("token expired"))
    await client.call("SyncNow")
    running.remote.fail_next("upsert", RuntimeError("store exploded"))
    running.local.put(make_credential("L", password=ITEM_PASSWORD))
    await client.call("SyncNow")
    await client.call("Delete", "s", new_id)
    await client.call("ListTrash")
    await client.call("SignOut")


async def test_no_secret_reaches_any_log(
    client: Client,
    running: RunningDaemon,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    await session(client, running)
    out, err = capfd.readouterr()
    logged = caplog.text + "".join(str(r.args) for r in caplog.records) + out + err
    assert caplog.records, "the session should have produced log records"
    for secret in (
        APPLE_PASSWORD,
        WRONG_PASSWORD,
        CODE,
        PASSCODE,
        WRONG_PASSCODE,
        ITEM_PASSWORD,
        RFC_SEED,
    ):
        assert secret not in logged


async def test_the_session_really_carried_the_secrets(
    client: Client, running: RunningDaemon
) -> None:
    # Guards the test above against passing vacuously: the values did flow through.
    await session(client, running)
    assert running.account.calls.count("join") == 2
    assert any(e.credential.password == ITEM_PASSWORD for e in running.state.trash())
    assert any(i.credential.password == ITEM_PASSWORD for i in running.remote.items.values())
