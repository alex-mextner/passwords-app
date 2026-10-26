# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The sign-in step machine: Apple ID -> code -> device passcode -> joined, and sign-out."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential
from tests.unit.daemon.fake_clock import settle
from tests.unit.daemon.fakes import (
    APPLE_ID,
    APPLE_PASSWORD,
    ATTEMPTS,
    CODE,
    DEVICES,
    PASSCODE,
    FakeAccount,
    FakeNotifier,
)

from passwords_app.daemon.controller import (
    ACCOUNT_KEY,
    MSG_CODE_DEVICE,
    MSG_CODE_SMS,
    MSG_DEVICE,
    MSG_DONE,
    Daemon,
)
from passwords_app.daemon.errors import (
    AuthRequiredError,
    InvalidError,
    WrongCodeError,
    WrongPasscodeError,
)
from passwords_app.daemon.status import MSG_NOT_JOINED, MSG_SIGNED_OUT
from passwords_app.sync.ports import AuthRequired

if TYPE_CHECKING:
    from tests.unit.daemon.conftest import Events

    from passwords_app.store.state import StateStore


@pytest.fixture
def account(remote: MemoryRemote) -> FakeAccount:
    """A fresh computer: never signed in."""
    return FakeAccount(remote)


async def to_device_step(daemon: Daemon) -> None:
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    await daemon.sign_in_code(CODE)


async def joined(daemon: Daemon) -> None:
    await to_device_step(daemon)
    await daemon.recovery_devices()
    await daemon.join(DEVICES[0].id, PASSCODE)


async def test_starts_signed_out(daemon: Daemon) -> None:
    assert daemon.status().state == "signed-out"


async def test_start_asks_for_a_code_on_trusted_devices(daemon: Daemon) -> None:
    step = await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    assert (step.step, step.destination, step.message) == (
        "code",
        "trusted-device",
        MSG_CODE_DEVICE,
    )


async def test_step_dict_layout(daemon: Daemon) -> None:
    step = await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    d = step.to_dbus()
    assert {k: v.signature for k, v in d.items()} == {
        "step": "s",
        "destination": "s",
        "message": "s",
    }


@pytest.mark.parametrize(
    ("apple_id", "password"), [("", APPLE_PASSWORD), ("   ", APPLE_PASSWORD), (APPLE_ID, "")]
)
async def test_start_requires_both_fields(
    account: FakeAccount, daemon: Daemon, apple_id: str, password: str
) -> None:
    with pytest.raises(InvalidError):
        await daemon.sign_in_start(apple_id, password)
    assert "sign_in" not in account.calls


async def test_apple_id_is_trimmed(account: FakeAccount, daemon: Daemon) -> None:
    await daemon.sign_in_start(f"  {APPLE_ID}\n", APPLE_PASSWORD)
    await daemon.sign_in_code(CODE)
    assert account.apple_id == APPLE_ID


async def test_wrong_password_is_auth_required(daemon: Daemon) -> None:
    with pytest.raises(AuthRequiredError, match="incorrect"):
        await daemon.sign_in_start(APPLE_ID, "nope")
    assert daemon.status().state == "signed-out"


async def test_wrong_code_then_right_code(daemon: Daemon) -> None:
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    with pytest.raises(WrongCodeError):
        await daemon.sign_in_code("000000")
    step = await daemon.sign_in_code(CODE)
    assert (step.step, step.message) == ("device", MSG_DEVICE)


@pytest.mark.parametrize("raw", [f"{CODE[:3]} {CODE[3:]}", f"{CODE[:3]}-{CODE[3:]}", f" {CODE} "])
async def test_code_separators_are_ignored(daemon: Daemon, raw: str) -> None:
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    assert (await daemon.sign_in_code(raw)).step == "device"


FULLWIDTH_DIGITS = "\uff11\uff12\uff13\uff14\uff15\uff16"


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5", FULLWIDTH_DIGITS])
async def test_malformed_codes_never_reach_apple(
    account: FakeAccount, daemon: Daemon, bad: str
) -> None:
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    with pytest.raises(InvalidError):
        await daemon.sign_in_code(bad)
    assert "submit_code" not in account.calls


async def test_code_without_a_started_sign_in_is_invalid(
    account: FakeAccount, daemon: Daemon
) -> None:
    with pytest.raises(InvalidError, match="Start signing in"):
        await daemon.sign_in_code(CODE)
    assert "submit_code" not in account.calls


async def test_sms_without_a_started_sign_in_is_invalid(daemon: Daemon) -> None:
    with pytest.raises(InvalidError):
        await daemon.sign_in_request_sms()


async def test_sms_switches_the_destination(account: FakeAccount, daemon: Daemon) -> None:
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    step = await daemon.sign_in_request_sms()
    assert (step.step, step.destination, step.message) == ("code", "sms", MSG_CODE_SMS)
    assert account.sms_requests == 1
    assert (await daemon.sign_in_code(CODE)).step == "device"


async def test_code_is_not_accepted_twice(daemon: Daemon) -> None:
    await to_device_step(daemon)
    with pytest.raises(InvalidError):
        await daemon.sign_in_code(CODE)


async def test_device_step_leaves_sign_in_required(daemon: Daemon) -> None:
    await to_device_step(daemon)
    status = daemon.status()
    assert (status.state, status.message, status.apple_id) == (
        "signin-required",
        MSG_NOT_JOINED,
        APPLE_ID,
    )


async def test_only_a_session_waiting_for_the_passcode_is_join_pending(
    account: FakeAccount, daemon: Daemon
) -> None:
    assert not daemon.status().join_pending  # signed out
    assert not daemon.status().to_dbus()["join_pending"].value
    await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    assert not daemon.status().join_pending  # still waiting for the verification code
    await daemon.sign_in_code(CODE)
    assert daemon.status().join_pending
    assert daemon.status().to_dbus()["join_pending"].value is True
    await daemon.recovery_devices()
    await daemon.join(DEVICES[0].id, PASSCODE)
    assert not daemon.status().join_pending  # joined
    await daemon.sign_out()
    assert not daemon.status().join_pending
    assert account.calls[-1] == "sign_out"


async def test_a_restarted_daemon_continues_at_the_device_step_without_signing_in_again(
    account: FakeAccount, unstarted: Daemon
) -> None:
    # The state a daemon finds after its restart: the saved session passed the code, no join yet.
    account.apple_id, account.signed_in, account.joined = APPLE_ID, True, False
    await unstarted.start()
    await settle()
    assert unstarted.status().join_pending
    assert await unstarted.recovery_devices() == list(DEVICES)
    step = await unstarted.join(DEVICES[0].id, PASSCODE)
    assert step.step == "done"
    assert not {"sign_in", "submit_code", "request_sms"} & set(account.calls)
    await settle()
    assert (unstarted.status().state, unstarted.status().join_pending) == ("idle", False)


async def test_recovery_devices_are_listed(daemon: Daemon) -> None:
    await to_device_step(daemon)
    assert await daemon.recovery_devices() == list(DEVICES)


async def test_recovery_devices_need_a_signed_in_account(daemon: Daemon) -> None:
    with pytest.raises(AuthRequiredError):
        await daemon.recovery_devices()


async def test_join_without_listing_devices_first_is_refused(
    account: FakeAccount, daemon: Daemon
) -> None:
    await to_device_step(daemon)
    with pytest.raises(InvalidError, match="from the list"):
        await daemon.join(DEVICES[0].id, PASSCODE)
    assert "join" not in account.calls


@pytest.mark.parametrize(("device", "passcode"), [("", PASSCODE), ("DEV-1", ""), ("", "")])
async def test_join_requires_device_and_passcode(
    account: FakeAccount, daemon: Daemon, device: str, passcode: str
) -> None:
    await to_device_step(daemon)
    await daemon.recovery_devices()
    with pytest.raises(InvalidError):
        await daemon.join(device, passcode)
    assert "join" not in account.calls


async def test_join_with_an_unlisted_device_is_refused(
    account: FakeAccount, daemon: Daemon
) -> None:
    await to_device_step(daemon)
    await daemon.recovery_devices()
    with pytest.raises(InvalidError):
        await daemon.join("DEV-FORGED", PASSCODE)
    assert "join" not in account.calls


async def test_wrong_passcode_reports_remaining_attempts(
    account: FakeAccount, daemon: Daemon
) -> None:
    await to_device_step(daemon)
    await daemon.recovery_devices()
    with pytest.raises(WrongPasscodeError, match=f"{ATTEMPTS - 1} attempts left"):
        await daemon.join(DEVICES[0].id, "000000")
    assert account.attempts[DEVICES[0].id] == ATTEMPTS - 1
    assert daemon.status().state == "signin-required"


async def test_successful_join_starts_syncing(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, events: Events
) -> None:
    remote.put(make_credential("FROM-IPHONE"))
    await to_device_step(daemon)
    await daemon.recovery_devices()
    step = await daemon.join(DEVICES[1].id, PASSCODE)
    assert (step.step, step.destination, step.message) == ("done", "", MSG_DONE)
    await settle()
    assert "FROM-IPHONE" in local.items
    assert daemon.status().state == "idle"
    assert daemon.status().apple_id == APPLE_ID
    assert "idle" in events.states


async def test_known_computer_signs_in_without_joining(
    account: FakeAccount, local: MemoryLocal, remote: MemoryRemote, daemon: Daemon
) -> None:
    account.needs_code = False
    account.known_member = True
    remote.put(make_credential("A"))
    step = await daemon.sign_in_start(APPLE_ID, APPLE_PASSWORD)
    assert step.step == "done"
    await settle()
    assert "A" in local.items


async def test_existing_keyring_items_are_linked_not_duplicated_on_first_sync(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    on_phone = make_credential("PHONE-ID", url="https://shop.example.com", username="a")
    local.put(
        make_credential(
            "SEAHORSE-ID",
            url="https://www.shop.example.com",
            username="a",
            password=on_phone.password,
        )
    )
    remote.put(on_phone)
    await joined(daemon)
    await settle()
    assert set(local.items) == {"PHONE-ID"}
    assert set(remote.items) == {"PHONE-ID"}


async def test_sign_out_keeps_keyring_items_and_forgets_sync_state(  # noqa: PLR0913, PLR0917
    account: FakeAccount,
    remote: MemoryRemote,
    local: MemoryLocal,
    state: StateStore,
    daemon: Daemon,
    notifier: FakeNotifier,
) -> None:
    remote.put(make_credential("A"))
    await joined(daemon)
    await settle()
    remote.fail_next("fetch", AuthRequired("expired"))
    await daemon.sync_now()
    assert notifier.topics() == ["signin"]
    await daemon.sign_out()
    assert "A" in local.items
    assert state.bases() == {}
    assert state.get(ACCOUNT_KEY) is None
    assert (daemon.status().state, daemon.status().message) == ("signed-out", MSG_SIGNED_OUT)
    assert daemon.status().apple_id == ""
    assert notifier.closed == ["signin"]
    assert account.calls[-1] == "sign_out"
    with pytest.raises(AuthRequiredError):
        await daemon.sync_now()


async def test_sign_in_to_another_account_after_sign_out_deletes_nothing(
    account: FakeAccount, remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    await joined(daemon)
    await settle()
    await daemon.sign_out()
    remote.remove("A")  # the other account's iCloud does not have it
    await joined(daemon)
    await settle()
    assert "A" in local.items
    assert "A" in remote.items


async def test_sign_in_calls_never_block_the_loop(account: FakeAccount, daemon: Daemon) -> None:
    await joined(daemon)
    assert threading.get_ident() not in account.threads
