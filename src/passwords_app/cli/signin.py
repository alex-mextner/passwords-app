# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app signin`: the terminal sign-in wizard.

Apple ID and password, then the verification code, then joining the keychain with one
device's screen passcode. The last step is irreversible-ish: Apple allows about ten wrong
passcodes per device and then destroys that device's sealed copy of the keychain keys. So the
wizard explains this in plain words, makes the user pick a device and type a confirmation
word before asking for the passcode, and never retries a passcode on its own.
"""

from __future__ import annotations

import getpass
from typing import TYPE_CHECKING, Protocol

from passwords_app.cli.client import DaemonCallError

if TYPE_CHECKING:
    from passwords_app.cli.client import DaemonClient, Plain

CONFIRM_WORD = "join"
MAX_CODE_TRIES = 5

EXPLANATION = """\
Confirm with a device passcode

Apple keeps your keychain keys sealed with the screen passcode of each of your devices
(the code you type to unlock your iPhone, iPad, or Mac). Entering the passcode of one of
them lets this computer join your iCloud Keychain. The passcode is sent only to Apple and
is not stored here.

Be careful: after about 10 wrong tries Apple destroys that device's copy of the keys."""


class Terminal(Protocol):
    def ask(self, prompt: str) -> str:
        """Read one line (raises EOFError when input ends)."""
        ...

    def secret(self, prompt: str) -> str:
        """Read one line without echo."""
        ...

    def say(self, text: str = "") -> None: ...


class ConsoleTerminal:
    def ask(self, prompt: str) -> str:
        return input(prompt)

    def secret(self, prompt: str) -> str:
        return getpass.getpass(prompt)

    def say(self, text: str = "") -> None:
        print(text)  # noqa: T201 - this is the CLI's output


class SignInCancelledError(Exception):
    """The user stopped the wizard (or gave up after repeated wrong codes)."""


class SignInBlockedError(Exception):
    """Apple offers no way to finish; the message says what to do."""


async def run_wizard(client: DaemonClient, term: Terminal, *, apple_id: str | None = None) -> None:
    term.say("Sign in to iCloud Keychain")
    term.say()
    step = await _resume(client, term, apple_id)
    if step is None:
        step = await _start(client, term, apple_id)
    term.say()
    term.say(str(step.get("message") or "Signed in."))
    term.say("Your passwords are syncing now; `passwords-app status` shows progress.")


async def _start(client: DaemonClient, term: Terminal, apple_id: str | None) -> Plain:
    account = (apple_id or term.ask("Apple Account (email or phone number): ")).strip()
    password = term.secret("Password: ")
    step = await client.sign_in_start(account, password)
    step = await _codes(client, term, step)
    if step["step"] == "device":
        step = await _join(client, term)
    return step


async def _resume(client: DaemonClient, term: Terminal, apple_id: str | None) -> Plain | None:
    """Continue at the device passcode when the password and the code were already done.

    The daemon keeps that sign-in across restarts, so asking for the Apple Account, the password
    and a new verification code again would only throw it away. Returns None when there is
    nothing to continue (or the saved sign-in cannot be continued): the caller starts over.
    """
    saved = await client.status()
    if not saved.get("join_pending"):
        return None
    account = str(saved.get("apple_id") or "")
    if apple_id and apple_id.strip().casefold() != account.casefold():
        return None  # another Apple Account was asked for
    term.say(
        f"{account} is already signed in on this computer: the password and the verification "
        "code are done. Only the device passcode is missing."
    )
    try:
        devices = await client.recovery_devices()
    except DaemonCallError as exc:
        if exc.short != "AuthRequired":
            raise
        term.say()
        term.say(f"The saved sign-in could not be continued ({exc}).")
        term.say("Starting the sign-in from the beginning; press Ctrl-C to try again later.")
        term.say()
        return None
    return await _join(client, term, devices)


async def _codes(client: DaemonClient, term: Terminal, step: Plain) -> Plain:
    wrong = 0
    while step["step"] == "code":
        term.say()
        term.say(str(step["message"]))
        entry = term.ask("Verification code (or type sms to get it by text message): ").strip()
        if entry.casefold() == "sms":
            step = await client.sign_in_request_sms()
            continue
        try:
            step = await client.sign_in_code(entry)
        except DaemonCallError as exc:
            if exc.short not in {"WrongCode", "Invalid"}:
                raise
            wrong += 1
            if wrong >= MAX_CODE_TRIES:
                msg = "Too many wrong codes. Run `passwords-app signin` to start again."
                raise SignInCancelledError(msg) from exc
            term.say(f"That code was not accepted: {exc}")
    return step


def _describe(device: Plain) -> str:
    details = ", ".join(
        part
        for part in (
            str(device.get("model", "")),
            f"serial {device['serial']}" if device.get("serial") else "",
        )
        if part
    )
    return f"{device['name']} ({details})" if details else str(device["name"])


async def _choose(term: Terminal, devices: list[Plain]) -> Plain:
    for number, device in enumerate(devices, 1):
        term.say(f"  {number}. {_describe(device)}")
    while True:
        answer = term.ask(f"Which device's passcode will you enter? [1-{len(devices)}]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(devices):
            return devices[int(answer) - 1]
        term.say(f"Please type a number from 1 to {len(devices)}.")


async def _join(client: DaemonClient, term: Terminal, devices: list[Plain] | None = None) -> Plain:
    """Pick a device and send its passcode; `devices` is a list the caller already fetched."""
    term.say()
    term.say(EXPLANATION)
    term.say()
    if devices is None:
        devices = await client.recovery_devices()
    while True:
        if not devices:
            msg = (
                "Apple lists no device whose passcode can admit this computer. Turn on "
                "iCloud Keychain on your iPhone, iPad, or Mac, then run `passwords-app signin`."
            )
            raise SignInBlockedError(msg)
        device = await _choose(term, devices)
        name = str(device["name"])
        confirm = term.ask(f"Type {CONFIRM_WORD} to use the passcode of {name}: ").strip()
        if confirm.casefold() != CONFIRM_WORD:
            msg = "Not confirmed; nothing was sent to Apple."
            raise SignInCancelledError(msg)
        passcode = term.secret(f"Passcode of {name}: ")
        try:
            return await client.join(str(device["id"]), passcode)
        except DaemonCallError as exc:
            if exc.short != "WrongPasscode":
                raise
            term.say(f"Apple did not accept that passcode: {exc}")
            again = term.ask("Try again (with this or another device)? [y/N]: ").strip()
            if again.casefold() not in {"y", "yes"}:
                msg = "Stopped. Run `passwords-app signin` when you have the passcode."
                raise SignInCancelledError(msg) from exc
        devices = await client.recovery_devices()  # the retry works from a fresh list
