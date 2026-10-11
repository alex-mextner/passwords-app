# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Stand-ins for the iCloud account and the notification server, used by daemon/CLI tests.

`FakeAccount` follows the real `Account` step machine (sign_in -> code -> device -> join ->
done) with known-good values for each secret, counts wrong passcode attempts per device the
way Apple does, and records which thread every call ran on so tests can prove the daemon
never blocks its event loop on it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from passwords_app.daemon.account import (
    STEP_CODE,
    STEP_DEVICE,
    STEP_DONE,
    AccountInfo,
    RecoveryDevice,
)
from passwords_app.daemon.errors import AuthRequiredError, WrongCodeError, WrongPasscodeError

if TYPE_CHECKING:
    from passwords_app.sync.ports import RemoteStore

APPLE_ID = "alice@example.com"
APPLE_PASSWORD = "apple-password-for-tests"  # noqa: S105 - fake account
CODE = "314159"
PASSCODE = "271828"
DEVICES = (
    RecoveryDevice("DEV-1", "Alice's iPhone", "iPhone17,2", "F2LZK000TEST"),
    RecoveryDevice("DEV-2", "Alice's MacBook Pro", "Mac16,7", "C02ZK000TEST"),
)
ATTEMPTS = 10


@dataclass
class FakeAccount:
    remote: RemoteStore
    apple_id: str | None = None
    signed_in: bool = False
    joined: bool = False
    needs_code: bool = True
    known_member: bool = False  # Apple already trusts this computer: sign-in ends at "done"
    calls: list[str] = field(default_factory=list)
    threads: set[int] = field(default_factory=set)
    attempts: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys((d.id for d in DEVICES), ATTEMPTS)
    )
    sms_requests: int = 0
    remote_store_error: Exception | None = None  # raised by remote_store() while set
    _pending: str | None = None

    def _enter(self, name: str) -> None:
        self.calls.append(name)
        self.threads.add(threading.get_ident())

    def status(self) -> AccountInfo:
        self._enter("status")
        return AccountInfo(self.apple_id, self.signed_in, self.joined)

    def sign_in(self, apple_id: str, password: str) -> str:
        self._enter("sign_in")
        if password != APPLE_PASSWORD:
            msg = "Your Apple Account or password was incorrect."
            raise AuthRequiredError(msg)
        self._pending = apple_id
        return STEP_CODE if self.needs_code else self._complete()

    def _complete(self) -> str:
        assert self._pending is not None
        self.apple_id, self._pending = self._pending, None
        self.signed_in = True
        if self.known_member:
            self.joined = True
        return STEP_DONE if self.joined else STEP_DEVICE

    def submit_code(self, code: str) -> str:
        self._enter("submit_code")
        if self._pending is None:
            msg = "no sign-in is waiting for a code"
            raise AuthRequiredError(msg)
        if code != CODE:
            msg = "Incorrect verification code."
            raise WrongCodeError(msg)
        return self._complete()

    def request_sms(self) -> str:
        self._enter("request_sms")
        if self._pending is None:
            msg = "no sign-in is waiting for a code"
            raise AuthRequiredError(msg)
        self.sms_requests += 1
        return STEP_CODE

    def recovery_devices(self) -> list[RecoveryDevice]:
        self._enter("recovery_devices")
        if not self.signed_in:
            msg = "not signed in"
            raise AuthRequiredError(msg)
        return [d for d in DEVICES if self.attempts[d.id] > 0]

    def join(self, device_id: str, passcode: str) -> str:
        self._enter("join")
        if device_id not in self.attempts or self.attempts[device_id] <= 0:
            msg = "unknown device; list the recovery devices first"
            raise AuthRequiredError(msg)
        if passcode != PASSCODE:
            self.attempts[device_id] -= 1
            msg = f"That passcode is not right. {self.attempts[device_id]} attempts left."
            raise WrongPasscodeError(msg)
        self.joined = True
        return STEP_DONE

    def sign_out(self) -> None:
        self._enter("sign_out")
        self.apple_id = None
        self.signed_in = self.joined = False

    def remote_store(self) -> RemoteStore:
        self._enter("remote_store")
        if self.remote_store_error is not None:
            raise self.remote_store_error
        return self.remote


@dataclass
class FakeNotifier:
    shown: list[tuple[str, str, str]] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)

    async def notify(self, topic: str, summary: str, body: str) -> None:
        self.shown.append((topic, summary, body))

    async def close(self, topic: str) -> None:
        self.closed.append(topic)

    def topics(self) -> list[str]:
        return [t for t, _, _ in self.shown]
