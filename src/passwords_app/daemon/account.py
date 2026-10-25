# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The iCloud account as the daemon sees it: a blocking step machine plus a remote store.

`AccountPort` is the slice of `passwords_app.icloud.account.Account` the daemon uses; the
daemon calls it through `asyncio.to_thread`. `ICloudAccount` adapts the real class, imported
lazily so the daemon module graph does not pull in the protocol client until it is needed,
and translates its exceptions into the daemon's D-Bus errors in one place.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from passwords_app.daemon.errors import (
    AuthRequiredError,
    UnavailableError,
    WrongCodeError,
    WrongPasscodeError,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from types import ModuleType

    from passwords_app.sync.ports import RemoteStore

STEP_CODE = "code"
STEP_DEVICE = "device"
STEP_DONE = "done"


@dataclass(frozen=True, slots=True)
class AccountInfo:
    apple_id: str | None
    signed_in: bool
    joined: bool
    session_unreadable: bool = False


@dataclass(frozen=True, slots=True)
class RecoveryDevice:
    id: str
    name: str
    model: str
    serial: str


class AccountPort(Protocol):
    """Blocking; step results are "code" | "device" | "done"."""

    def status(self) -> AccountInfo: ...

    def sign_in(self, apple_id: str, password: str) -> str: ...

    def submit_code(self, code: str) -> str: ...

    def request_sms(self) -> str: ...

    def recovery_devices(self) -> list[RecoveryDevice]: ...

    def join(self, device_id: str, passcode: str) -> str: ...

    def sign_out(self) -> None: ...

    def remote_store(self) -> RemoteStore: ...


class ICloudAccount:
    """`AccountPort` over the real iCloud `Account`."""

    def __init__(self, account: object, module: ModuleType) -> None:
        self._account = account
        self._m = module

    @classmethod
    def load(cls, config_dir: Path | None = None, anisette_url: str | None = None) -> ICloudAccount:
        module = importlib.import_module("passwords_app.icloud.account")
        return cls(module.Account(config_dir, anisette_url), module)

    def _call[T](self, op: Callable[[], T]) -> T:
        m = self._m
        try:
            return op()
        except m.WrongCode as exc:
            raise WrongCodeError(str(exc)) from exc
        except m.WrongPasscode as exc:
            raise WrongPasscodeError(str(exc)) from exc
        except m.AccountError as exc:
            # SignInRequired included: Apple wants the user again (password, code, ...).
            raise AuthRequiredError(str(exc)) from exc
        except OSError as exc:
            # requests' exceptions are OSErrors; their text carries URLs, not credentials.
            msg = f"Can't reach Apple: {exc}"
            raise UnavailableError(msg) from exc

    def _a(self, name: str) -> Callable[..., object]:
        return cast("Callable[..., object]", getattr(self._account, name))

    def status(self) -> AccountInfo:
        raw = self._call(self._a("status"))
        return AccountInfo(
            apple_id=cast("str | None", getattr(raw, "apple_id", None)),
            signed_in=bool(getattr(raw, "signed_in", False)),
            joined=bool(getattr(raw, "joined", False)),
            session_unreadable=bool(getattr(raw, "session_unreadable", False)),
        )

    def sign_in(self, apple_id: str, password: str) -> str:
        return str(self._call(lambda: self._a("sign_in")(apple_id, password)))

    def submit_code(self, code: str) -> str:
        return str(self._call(lambda: self._a("submit_code")(code)))

    def request_sms(self) -> str:
        return str(self._call(self._a("request_sms")))

    def recovery_devices(self) -> list[RecoveryDevice]:
        devices = cast("list[object]", self._call(self._a("recovery_devices")))
        return [
            RecoveryDevice(
                id=str(getattr(d, "id", "")),
                name=str(getattr(d, "name", "")),
                model=str(getattr(d, "model", "")),
                serial=str(getattr(d, "serial", "")),
            )
            for d in devices
        ]

    def join(self, device_id: str, passcode: str) -> str:
        return str(self._call(lambda: self._a("join")(device_id, passcode)))

    def sign_out(self) -> None:
        self._call(self._a("sign_out"))

    def remote_store(self) -> RemoteStore:
        return cast("RemoteStore", self._call(self._a("remote_store")))
