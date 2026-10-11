# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app doctor`: check every moving part and say how to fix what is broken.

Read-only: it talks to the anisette server, the daemon and the Secret Service, and reads the
browser manifests, but never changes anything.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from dbus_fast.aio import MessageBus

from passwords_app.cli.client import DaemonCallError, DaemonClient, DaemonUnreachableError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from passwords_app.cli.client import Plain

type Level = Literal["ok", "warn", "fail", "skip"]

ANISETTE_HOST = "127.0.0.1"
ANISETTE_PORT = 6969
ANISETTE_TIMEOUT = 2.0
COLLECTION_LABEL = "iCloud Passwords"
NATIVE_HOST = "io.github.alex_mextner.passwords"
_MARKS: dict[Level, str] = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "-"}
_STATE_LEVEL: dict[str, Level] = {
    "idle": "ok",
    "syncing": "ok",
    "paused": "warn",
    "offline": "warn",
    "signed-out": "warn",
    "signin-required": "fail",
    "error": "fail",
}


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    level: Level
    detail: str
    hint: str = ""

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "level": self.level, "detail": self.detail, "hint": self.hint}


async def check_anisette(host: str, port: int) -> Check:
    name = "Apple sign-in helper (anisette)"
    where = f"{host}:{port}"
    hint = (
        "Apple sign-in needs it. `passwords-app install` sets up the anisette-v3-server "
        "container; if it exists, start it with `docker start passwords-app-anisette`."
    )
    try:
        async with asyncio.timeout(ANISETTE_TIMEOUT):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                writer.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                first = await reader.readline()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
    except (OSError, TimeoutError):
        return Check(name, "fail", f"nothing answers on {where}", hint)
    if not first.startswith(b"HTTP/"):
        return Check(name, "fail", f"{where} answers, but not over HTTP", hint)
    return Check(name, "ok", f"answering on {where}")


async def check_daemon(bus: MessageBus) -> tuple[Check, Plain | None]:
    name = "Sync service (passwords-appd)"
    hint = "See `systemctl --user status passwords-appd` and `journalctl --user -u passwords-appd`."
    try:
        status = await DaemonClient(bus).status()
    except (DaemonUnreachableError, DaemonCallError) as exc:
        return Check(name, "fail", f"not reachable: {exc}", hint), None
    return Check(name, "ok", "running"), status


def check_sync_state(status: Plain) -> Check:
    state = str(status.get("state", ""))
    level = _STATE_LEVEL.get(state, "fail")
    detail = state + (f" — {status['message']}" if status.get("message") else "")
    hint = {
        "signed-out": "Run `passwords-app signin`.",
        "signin-required": "Run `passwords-app signin`.",
        "paused": "Run `passwords-app resolve apply` or `passwords-app resolve restore`.",
        "error": "See `journalctl --user -u passwords-appd` for details.",
    }.get(state, "")
    return Check("Sync state", level, detail, hint)


async def check_keyring(bus: MessageBus) -> Check:
    from passwords_app.keyring.client import (  # noqa: PLC0415 - only doctor needs it
        SecretServiceClient,
        SecretServiceError,
    )
    from passwords_app.keyring.collection import find_collection  # noqa: PLC0415

    name = f'Keyring collection "{COLLECTION_LABEL}"'
    try:
        client = await SecretServiceClient.open(bus)
    except SecretServiceError as exc:
        return Check(
            name, "fail", f"Secret Service unavailable: {exc}", "Is gnome-keyring running?"
        )
    try:
        path = await find_collection(client, COLLECTION_LABEL)
        if path is None:
            return Check(
                name, "warn", "not created yet", "The sync service creates it when it first starts."
            )
        if await client.is_locked(path):
            return Check(name, "warn", "locked", "Unlock it in Passwords and Keys (Seahorse).")
        return Check(name, "ok", "present and unlocked")
    except SecretServiceError as exc:
        return Check(name, "fail", f"cannot read it: {exc}")
    finally:
        with contextlib.suppress(SecretServiceError):
            await client.close()


def _browsers(home: Path) -> list[tuple[str, Path, Path]]:
    """(browser, profile dir that shows it is installed, manifest path)."""
    manifest = f"{NATIVE_HOST}.json"
    config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    return [
        ("Firefox", home / ".mozilla", home / ".mozilla" / "native-messaging-hosts" / manifest),
        (
            "Google Chrome",
            config / "google-chrome",
            config / "google-chrome" / "NativeMessagingHosts" / manifest,
        ),
        ("Chromium", config / "chromium", config / "chromium" / "NativeMessagingHosts" / manifest),
    ]


def _manifest_problem(path: Path) -> str | None:
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"unreadable manifest: {exc}"
    host = cast("dict[str, object]", data).get("path") if isinstance(data, dict) else None
    if not isinstance(host, str) or not host:
        return "manifest has no host path"
    if not os.access(host, os.X_OK):
        return f"host program {host} is missing or not executable"
    return None


def check_browsers(home: Path) -> list[Check]:
    checks: list[Check] = []
    hint = "Run `passwords-app install` to register the browser helper."
    for browser, profile, manifest in _browsers(home):
        name = f"{browser} autofill helper"
        if not manifest.exists():
            if profile.exists():
                checks.append(Check(name, "warn", "not registered", hint))
            else:
                checks.append(Check(name, "skip", f"{browser} not found"))
            continue
        problem = _manifest_problem(manifest)
        if problem is None:
            checks.append(Check(name, "ok", f"registered ({manifest})"))
        else:
            checks.append(Check(name, "fail", problem, hint))
    return checks


async def run_checks(home: Path, *, anisette: tuple[str, int] | None = None) -> list[Check]:
    host, port = anisette or (ANISETTE_HOST, ANISETTE_PORT)
    checks = [await check_anisette(host, port)]
    try:
        bus = await MessageBus().connect()
    except (OSError, EOFError, ValueError) as exc:
        checks.append(Check("Session bus", "fail", f"cannot connect: {exc}"))
    else:
        try:
            daemon, status = await check_daemon(bus)
            checks.append(daemon)
            if status is not None:
                checks.append(check_sync_state(status))
            checks.append(await check_keyring(bus))
        finally:
            bus.disconnect()
    checks.extend(check_browsers(home))
    return checks


def render(checks: Sequence[Check]) -> str:
    lines: list[str] = []
    for c in checks:
        lines.append(f"{_MARKS[c.level]} {c.name}: {c.detail}")
        if c.hint and c.level in {"warn", "fail"}:
            lines.append(f"    {c.hint}")
    return "\n".join(lines)


def healthy(checks: Sequence[Check]) -> bool:
    return all(c.level != "fail" for c in checks)
