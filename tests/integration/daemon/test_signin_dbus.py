# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sign-in over D-Bus, from a fresh computer to a joined, syncing daemon."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.fakes.memory_stores import make_credential
from tests.integration.daemon.support import CallError, Client, RunningDaemon, wait_for
from tests.unit.daemon.fakes import APPLE_ID, APPLE_PASSWORD, CODE, DEVICES, PASSCODE

from passwords_app.daemon import INTERFACE
from passwords_app.daemon.errors import UnavailableError

if TYPE_CHECKING:
    from dbus_fast import Variant

pytestmark = pytest.mark.integration

ERR = f"{INTERFACE}.Error."


@pytest.fixture
def account_state() -> dict[str, bool]:
    return {"signed_in": False, "joined": False}


def plain(d: dict[str, Variant]) -> dict[str, object]:
    return {k: v.value for k, v in d.items()}


async def error_of(client: Client, member: str, signature: str = "", *body: object) -> str:
    with pytest.raises(CallError) as info:
        await client.call(member, signature, *body)
    return info.value.name


async def test_signed_out_status(client: Client) -> None:
    status = plain(await client.one("GetStatus"))
    assert status["state"] == "signed-out"
    assert status["apple_id"] == ""
    assert status["last_sync"] == 0
    assert status["next_sync"] == 0


async def test_sync_now_signed_out_is_auth_required(client: Client) -> None:
    assert await error_of(client, "SyncNow") == ERR + "AuthRequired"


async def test_resolve_pause_signed_out_is_auth_required(client: Client) -> None:
    assert await error_of(client, "ResolvePause", "b", True) == ERR + "AuthRequired"  # noqa: FBT003


async def test_full_sign_in(client: Client, running: RunningDaemon) -> None:
    running.remote.put(make_credential("FROM-ICLOUD"))
    step = plain(await client.one("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD))
    assert (step["step"], step["destination"]) == ("code", "trusted-device")
    assert await error_of(client, "SignInCode", "s", "000000") == ERR + "WrongCode"
    step = plain(await client.one("SignInCode", "s", CODE))
    assert step["step"] == "device"
    assert "passcode" in str(step["message"])
    assert "escrow" not in str(step["message"]).lower()
    devices = await client.one("ListRecoveryDevices")
    assert [plain(d) for d in devices] == [
        {"id": d.id, "name": d.name, "model": d.model, "serial": d.serial} for d in DEVICES
    ]
    name = await error_of(client, "JoinKeychain", "ss", DEVICES[0].id, "999999")
    assert name == ERR + "WrongPasscode"
    step = plain(await client.one("JoinKeychain", "ss", DEVICES[0].id, PASSCODE))
    assert step == {"step": "done", "destination": "", "message": step["message"]}
    await wait_for(lambda: "FROM-ICLOUD" in running.local.items)
    status = plain(await client.one("GetStatus"))
    assert status["apple_id"] == APPLE_ID
    assert status["state"] in {"idle", "syncing"}


async def test_wrong_passcode_message_carries_remaining_attempts(client: Client) -> None:
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD)
    await client.call("SignInCode", "s", CODE)
    await client.call("ListRecoveryDevices")
    with pytest.raises(CallError) as info:
        await client.call("JoinKeychain", "ss", DEVICES[1].id, "000000")
    assert "9 attempts left" in info.value.text


async def test_sms(client: Client, running: RunningDaemon) -> None:
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD)
    step = plain(await client.one("SignInRequestSms"))
    assert (step["step"], step["destination"]) == ("code", "sms")
    assert running.account.sms_requests == 1


async def test_wrong_password(client: Client) -> None:
    assert await error_of(client, "SignInStart", "ss", APPLE_ID, "nope") == ERR + "AuthRequired"


async def test_empty_credentials_are_invalid(client: Client) -> None:
    assert await error_of(client, "SignInStart", "ss", "", "") == ERR + "Invalid"


async def test_code_out_of_order_is_invalid(client: Client) -> None:
    assert await error_of(client, "SignInCode", "s", CODE) == ERR + "Invalid"
    assert await error_of(client, "SignInRequestSms") == ERR + "Invalid"


async def test_devices_need_sign_in(client: Client) -> None:
    assert await error_of(client, "ListRecoveryDevices") == ERR + "AuthRequired"


async def test_join_needs_an_explicitly_listed_device(
    client: Client, running: RunningDaemon
) -> None:
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD)
    await client.call("SignInCode", "s", CODE)
    assert await error_of(client, "JoinKeychain", "ss", DEVICES[0].id, PASSCODE) == ERR + "Invalid"
    assert "join" not in running.account.calls


async def test_unreachable_apple_is_unavailable(client: Client, running: RunningDaemon) -> None:
    def offline(apple_id: str, password: str) -> str:
        msg = "Can't reach Apple: connection refused"
        raise UnavailableError(msg)

    running.account.sign_in = offline  # type: ignore[method-assign]
    assert (
        await error_of(client, "SignInStart", "ss", APPLE_ID, APPLE_PASSWORD) == ERR + "Unavailable"
    )


async def test_sign_out_after_sign_in(client: Client, running: RunningDaemon) -> None:
    running.account.needs_code = False
    running.account.known_member = True
    step = plain(await client.one("SignInStart", "ss", APPLE_ID, APPLE_PASSWORD))
    assert step["step"] == "done"
    await client.call("SignOut")
    status = plain(await client.one("GetStatus"))
    assert (status["state"], status["apple_id"]) == ("signed-out", "")
    states = [b["state"].value for b in client.signal_bodies("StatusChanged")]
    assert states[-1] == "signed-out"
