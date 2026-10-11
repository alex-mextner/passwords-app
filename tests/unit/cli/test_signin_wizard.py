# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The terminal sign-in wizard against a scripted daemon client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast, override

import pytest
from tests.unit.cli.terminal import ScriptedTerminal

from passwords_app.cli.client import DaemonCallError, DaemonClient
from passwords_app.cli.signin import (
    CONFIRM_WORD,
    MAX_CODE_TRIES,
    SignInBlockedError,
    SignInCancelledError,
    run_wizard,
)

pytestmark = pytest.mark.timeout(30)

ERR = "io.github.alex_mextner.Passwords1.Error."
APPLE_PW = "apple-pw-for-wizard"
CODE = "123456"
PASSCODE = "4711"
DEVICES = [
    {"id": "D1", "name": "Alice's iPhone", "model": "iPhone17,2", "serial": "F2LTEST"},
    {"id": "D2", "name": "Alice's Mac", "model": "Mac16,7", "serial": ""},
]


def step(name: str, destination: str = "", message: str = "") -> dict[str, Any]:
    return {"step": name, "destination": destination, "message": message or f"{name} message"}


@dataclass
class FakeClient:
    first: str = "code"
    devices: list[dict[str, Any]] = field(default_factory=lambda: list(DEVICES))
    attempts: int = 10
    calls: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)

    async def sign_in_start(self, apple_id: str, password: str) -> dict[str, Any]:
        self.calls.append(("start", (apple_id, password)))
        if password != APPLE_PW:
            raise DaemonCallError(
                ERR + "AuthRequired", "Your Apple Account or password was incorrect."
            )
        return step(self.first, "trusted-device" if self.first == "code" else "")

    async def sign_in_code(self, code: str) -> dict[str, Any]:
        self.calls.append(("code", (code,)))
        if code != CODE:
            raise DaemonCallError(ERR + "WrongCode", "Incorrect verification code.")
        return step("device")

    async def sign_in_request_sms(self) -> dict[str, Any]:
        self.calls.append(("sms", ()))
        return step("code", "sms", "sent by text message")

    async def recovery_devices(self) -> list[dict[str, Any]]:
        self.calls.append(("devices", ()))
        return self.devices

    async def join(self, device_id: str, passcode: str) -> dict[str, Any]:
        self.calls.append(("join", (device_id, passcode)))
        if passcode != PASSCODE:
            self.attempts -= 1
            raise DaemonCallError(ERR + "WrongPasscode", f"{self.attempts} attempts left.")
        return step("done", message="This computer is now part of your iCloud Keychain.")

    def called(self, name: str) -> list[tuple[Any, ...]]:
        return [args for n, args in self.calls if n == name]


async def wizard(client: FakeClient, term: ScriptedTerminal, apple_id: str | None = None) -> None:
    await run_wizard(cast("DaemonClient", client), term, apple_id=apple_id)


def happy_terminal(**overrides: list[str]) -> ScriptedTerminal:
    answers = overrides.get("answers", ["alice@example.com", CODE, "1", CONFIRM_WORD])
    secrets = overrides.get("secrets", [APPLE_PW, PASSCODE])
    return ScriptedTerminal(answers=list(answers), secrets=list(secrets))


async def test_full_flow() -> None:
    client, term = FakeClient(), happy_terminal()
    await wizard(client, term)
    assert client.called("start") == [("alice@example.com", APPLE_PW)]
    assert client.called("code") == [(CODE,)]
    assert client.called("join") == [("D1", PASSCODE)]
    assert "part of your iCloud Keychain" in term.output


async def test_secrets_are_read_without_echo() -> None:
    term = happy_terminal()
    await wizard(FakeClient(), term)
    assert len(term.secret_prompts) == 2
    assert term.secret_prompts[0] == "Password: "
    assert "Passcode of Alice's iPhone" in term.secret_prompts[1]
    assert APPLE_PW not in term.everything
    assert PASSCODE not in term.everything


async def test_explanation_is_plain_language() -> None:
    term = happy_terminal()
    await wizard(FakeClient(), term)
    text = term.everything
    assert "Confirm with a device passcode" in text
    assert "screen passcode of each of your devices" in text
    assert "about 10 wrong tries" in text
    assert "escrow" not in text.lower()


async def test_devices_are_listed_with_model_and_serial() -> None:
    term = happy_terminal()
    await wizard(FakeClient(), term)
    assert "  1. Alice's iPhone (iPhone17,2, serial F2LTEST)" in term.lines
    assert "  2. Alice's Mac (Mac16,7)" in term.lines


async def test_apple_id_from_the_command_line_is_not_asked() -> None:
    client = FakeClient()
    term = ScriptedTerminal(answers=[CODE, "1", CONFIRM_WORD], secrets=[APPLE_PW, PASSCODE])
    await wizard(client, term, apple_id=" alice@example.com ")
    assert client.called("start") == [("alice@example.com", APPLE_PW)]
    assert not any("Apple Account" in p for p in term.prompts)


async def test_wrong_apple_password_propagates() -> None:
    term = happy_terminal(secrets=["nope"])
    with pytest.raises(DaemonCallError) as info:
        await wizard(FakeClient(), term)
    assert info.value.short == "AuthRequired"


async def test_wrong_code_is_asked_again() -> None:
    client = FakeClient()
    term = happy_terminal(answers=["alice@example.com", "000000", CODE, "1", CONFIRM_WORD])
    await wizard(client, term)
    assert client.called("code") == [("000000",), (CODE,)]
    assert "That code was not accepted" in term.output


async def test_too_many_wrong_codes_stop() -> None:
    client = FakeClient()
    term = happy_terminal(answers=["alice@example.com", *["000000"] * MAX_CODE_TRIES])
    with pytest.raises(SignInCancelledError, match="Too many wrong codes"):
        await wizard(client, term)
    assert len(client.called("code")) == MAX_CODE_TRIES
    assert client.called("join") == []


@pytest.mark.parametrize("word", ["sms", "SMS", " sms "])
async def test_sms_on_request(word: str) -> None:
    client = FakeClient()
    term = happy_terminal(answers=["alice@example.com", word, CODE, "1", CONFIRM_WORD])
    await wizard(client, term)
    assert client.called("sms") == [()]
    assert "sent by text message" in term.output


async def test_no_code_needed_skips_to_devices() -> None:
    client = FakeClient(first="device")
    term = happy_terminal(answers=["alice@example.com", "1", CONFIRM_WORD])
    await wizard(client, term)
    assert client.called("code") == []
    assert client.called("join") == [("D1", PASSCODE)]


async def test_already_joined_needs_no_passcode() -> None:
    client = FakeClient(first="done")
    term = ScriptedTerminal(answers=["alice@example.com"], secrets=[APPLE_PW])
    await wizard(client, term)
    assert client.called("devices") == []
    assert term.secret_prompts == ["Password: "]


@pytest.mark.parametrize("bad", ["0", "3", "x", "", "-1", "1.5"])
async def test_invalid_device_choice_is_asked_again(bad: str) -> None:
    client = FakeClient()
    term = happy_terminal(answers=["alice@example.com", CODE, bad, "2", CONFIRM_WORD])
    await wizard(client, term)
    assert client.called("join") == [("D2", PASSCODE)]
    assert "Please type a number from 1 to 2." in term.output


@pytest.mark.parametrize("confirmation", ["", "no", "yes", "joi", "y"])
async def test_without_the_confirmation_word_nothing_is_sent(confirmation: str) -> None:
    client = FakeClient()
    term = happy_terminal(answers=["alice@example.com", CODE, "1", confirmation])
    with pytest.raises(SignInCancelledError, match="nothing was sent"):
        await wizard(client, term)
    assert client.called("join") == []
    assert len(term.secret_prompts) == 1  # the passcode was never even asked for


@pytest.mark.parametrize("confirmation", ["JOIN", " join ", "Join"])
async def test_confirmation_word_is_case_insensitive(confirmation: str) -> None:
    client = FakeClient()
    await wizard(client, happy_terminal(answers=["alice@example.com", CODE, "1", confirmation]))
    assert len(client.called("join")) == 1


async def test_wrong_passcode_is_never_retried_automatically() -> None:
    client = FakeClient()
    term = happy_terminal(
        answers=["alice@example.com", CODE, "1", CONFIRM_WORD, ""], secrets=[APPLE_PW, "0000"]
    )
    with pytest.raises(SignInCancelledError, match="when you have the passcode"):
        await wizard(client, term)
    assert client.called("join") == [("D1", "0000")]
    assert "9 attempts left." in term.output


async def test_wrong_passcode_then_retry_with_another_device() -> None:
    client = FakeClient()
    term = happy_terminal(
        answers=["alice@example.com", CODE, "1", CONFIRM_WORD, "y", "2", CONFIRM_WORD],
        secrets=[APPLE_PW, "0000", PASSCODE],
    )
    await wizard(client, term)
    assert client.called("join") == [("D1", "0000"), ("D2", PASSCODE)]
    assert len(client.called("devices")) == 2  # the list is fetched fresh for the retry


async def test_no_devices_is_blocked_with_guidance() -> None:
    client = FakeClient(devices=[])
    term = happy_terminal(answers=["alice@example.com", CODE])
    with pytest.raises(SignInBlockedError, match="Turn on iCloud Keychain"):
        await wizard(client, term)


async def test_end_of_input_stops_the_wizard() -> None:
    term = ScriptedTerminal(answers=["alice@example.com"], secrets=[APPLE_PW])
    with pytest.raises(EOFError):
        await wizard(FakeClient(), term)


async def test_other_daemon_errors_propagate_during_join() -> None:
    class Locked(FakeClient):
        @override
        async def join(self, device_id: str, passcode: str) -> dict[str, Any]:
            raise DaemonCallError(ERR + "AuthRequired", "sign in again")

    with pytest.raises(DaemonCallError):
        await wizard(Locked(), happy_terminal())
