# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`ICloudAccount`: the real Account's results and exceptions, as the daemon needs them.

The iCloud package is replaced by a module with the same public surface (`Account` and its
exception classes), so the translation is pinned independently of Apple's protocol code.
"""

from __future__ import annotations

import enum
import sys
import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from passwords_app.daemon.account import AccountInfo, ICloudAccount, RecoveryDevice
from passwords_app.daemon.errors import (
    AuthRequiredError,
    DaemonError,
    UnavailableError,
    WrongCodeError,
    WrongPasscodeError,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

REMOTE_STORE = object()


class AccountError(Exception):
    pass


class WrongCode(AccountError):  # noqa: N818 - mirrors the real class name
    pass


class WrongPasscode(AccountError):  # noqa: N818
    pass


class SignInRequired(AccountError):  # noqa: N818
    pass


class SignInStep(enum.StrEnum):
    CODE = "code"
    DEVICE = "device"
    DONE = "done"


@dataclass(frozen=True)
class Status:
    apple_id: str | None
    signed_in: bool
    joined: bool


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    model: str
    serial: str


class Account:
    instances: list[Account] = []  # noqa: RUF012 - test bookkeeping

    def __init__(self, config_dir: Path | None = None, anisette_url: str | None = None) -> None:
        self.config_dir = config_dir
        self.anisette_url = anisette_url
        self.raise_next: BaseException | None = None
        self.args: list[tuple[Any, ...]] = []
        Account.instances.append(self)

    def _go(self, *args: Any) -> None:
        self.args.append(args)
        if self.raise_next is not None:
            exc, self.raise_next = self.raise_next, None
            raise exc

    def status(self) -> Status:
        self._go()
        return Status("alice@example.com", signed_in=True, joined=False)

    def sign_in(self, apple_id: str, password: str) -> SignInStep:
        self._go(apple_id, password)
        return SignInStep.CODE

    def submit_code(self, code: str) -> SignInStep:
        self._go(code)
        return SignInStep.DEVICE

    def request_sms(self) -> SignInStep:
        self._go()
        return SignInStep.CODE

    def recovery_devices(self) -> list[Device]:
        self._go()
        return [Device("D1", "iPhone", "iPhone17,2", "SER1")]

    def join(self, device_id: str, passcode: str) -> SignInStep:
        self._go(device_id, passcode)
        return SignInStep.DONE

    def sign_out(self) -> None:
        self._go()

    def remote_store(self) -> object:
        self._go()
        return REMOTE_STORE


@pytest.fixture
def module(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    m = types.ModuleType("passwords_app.icloud.account")
    for cls in (AccountError, WrongCode, WrongPasscode, SignInRequired, Account):
        setattr(m, cls.__name__, cls)
    monkeypatch.setitem(sys.modules, "passwords_app.icloud.account", m)
    Account.instances = []
    return m


@pytest.fixture
def adapter(module: types.ModuleType) -> ICloudAccount:
    return ICloudAccount.load()


def real(adapter: ICloudAccount) -> Account:
    (instance,) = Account.instances
    return instance


def test_load_passes_config(module: types.ModuleType, tmp_path: Path) -> None:
    ICloudAccount.load(tmp_path, "http://127.0.0.1:6969")
    (instance,) = Account.instances
    assert (instance.config_dir, instance.anisette_url) == (tmp_path, "http://127.0.0.1:6969")


def test_status_is_converted(adapter: ICloudAccount) -> None:
    assert adapter.status() == AccountInfo("alice@example.com", signed_in=True, joined=False)


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (lambda a: a.sign_in("alice@example.com", "pw"), "code"),
        (lambda a: a.submit_code("123456"), "device"),
        (lambda a: a.request_sms(), "code"),
        (lambda a: a.join("D1", "123456"), "done"),
    ],
)
def test_steps_become_plain_strings(
    adapter: ICloudAccount, call: Callable[[ICloudAccount], str], expected: str
) -> None:
    step = call(adapter)
    assert step == expected
    assert type(step) is str


def test_arguments_are_passed_through(adapter: ICloudAccount) -> None:
    adapter.sign_in("alice@example.com", "pw")
    adapter.join("D1", "4321")
    assert real(adapter).args == [("alice@example.com", "pw"), ("D1", "4321")]


def test_devices_are_converted(adapter: ICloudAccount) -> None:
    assert adapter.recovery_devices() == [RecoveryDevice("D1", "iPhone", "iPhone17,2", "SER1")]


def test_remote_store_is_returned(adapter: ICloudAccount) -> None:
    assert adapter.remote_store() is REMOTE_STORE


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (WrongCode("Incorrect verification code."), WrongCodeError),
        (WrongPasscode("Wrong passcode, 9 attempts left."), WrongPasscodeError),
        (SignInRequired("sign in again"), AuthRequiredError),
        (AccountError("Your Apple Account or password was incorrect."), AuthRequiredError),
        (ConnectionError("connection refused"), UnavailableError),
        (TimeoutError("timed out"), UnavailableError),
        (OSError("network unreachable"), UnavailableError),
    ],
)
@pytest.mark.parametrize(
    "call",
    [
        lambda a: a.sign_in("alice@example.com", "pw"),
        lambda a: a.submit_code("123456"),
        lambda a: a.request_sms(),
        lambda a: a.recovery_devices(),
        lambda a: a.join("D1", "123456"),
        lambda a: a.sign_out(),
        lambda a: a.status(),
    ],
)
def test_exceptions_are_translated(
    adapter: ICloudAccount,
    call: Callable[[ICloudAccount], object],
    raised: Exception,
    expected: type[DaemonError],
) -> None:
    real(adapter).raise_next = raised
    with pytest.raises(expected) as info:
        call(adapter)
    assert str(raised) in str(info.value)
    assert info.value.__cause__ is raised


def test_unexpected_exceptions_are_not_disguised(adapter: ICloudAccount) -> None:
    real(adapter).raise_next = KeyError("bug")
    with pytest.raises(KeyError):
        adapter.sign_out()
