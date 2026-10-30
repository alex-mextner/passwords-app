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
import re
import shlex
import ssl
import subprocess  # nosec B404 - runs systemctl --user show only, fixed argv, no shell
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit

from dbus_fast.aio import MessageBus

from passwords_app.cli.client import DaemonCallError, DaemonClient, DaemonUnreachableError
from passwords_app.icloud.const import DEFAULT_ANISETTE_URL

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from passwords_app.cli.client import Plain

type Level = Literal["ok", "warn", "fail", "skip"]

ANISETTE_CHECK = "Apple sign-in helper (anisette)"
ANISETTE_URL_VARIABLE = "PASSWORDS_APP_ANISETTE_URL"
ANISETTE_TIMEOUT = 2.0
SERVICE_UNIT = "passwords-appd.service"
# What a server's data says about the ADI library that made it (X-Apple-I-MD-RINFO).
_ADI_ORIGINS = {
    "17106176": "Android ADI",
    "33883392": "macOS ADI",
    "84215040": "Windows ADI",
}
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


async def check_anisette(host: str, port: int, *, tls: bool = False) -> Check:
    name = ANISETTE_CHECK
    where = f"{host}:{port}"
    hint = (
        "Apple sign-in needs it. `passwords-app install` builds and starts the local anisette "
        "server (Windows ADI under Wine); if it exists, start it with "
        "`docker start passwords-app-anisette-windows`."
    )
    try:
        async with asyncio.timeout(ANISETTE_TIMEOUT):
            # An https URL speaks TLS from the first byte, with the certificate verified.
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl.create_default_context() if tls else None
            )
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


def _main_pid() -> int | None:
    done = _systemctl_show("MainPID")
    return int(done) if done is not None and done.isdigit() and int(done) > 0 else None


def _systemctl_show(prop: str) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed argv, no shell
            ["systemctl", "--user", "show", SERVICE_UNIT, f"--property={prop}", "--value"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _process_environment(pid: int) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return None


def _entry_value(entries: Iterable[str]) -> str | None:
    prefix = f"{ANISETTE_URL_VARIABLE}="
    return next((e.removeprefix(prefix) for e in entries if e.startswith(prefix)), None)


def service_anisette_url() -> str | None:
    """Return the anisette URL the sync service uses: "" if it surely sets none, None if unknown.

    The service, not this shell, talks to Apple, so its environment decides which server counts.
    The running service's own environment (/proc) covers drop-ins, EnvironmentFile= and inherited
    values; without it the unit's Environment= is the best there is, decoded as systemd quotes it.
    """
    pid = _main_pid()
    if pid is not None:
        block = _process_environment(pid)
        if block is not None:
            entries = (e.decode(errors="replace") for e in block.split(b"\0"))
            return _entry_value(entries) or ""
    unit = _systemctl_show("Environment")
    if unit is None:
        return None
    try:
        value = _entry_value(shlex.split(unit))
    except ValueError:
        return None
    # systemd also escapes `$` inside the quotes (`\\$`), which the shell rules leave in place.
    return None if value is None else value.replace("\\$", "$")


def configured_anisette_url() -> str:
    service = service_anisette_url()
    if service is not None:
        return service or DEFAULT_ANISETTE_URL
    return os.environ.get(ANISETTE_URL_VARIABLE) or DEFAULT_ANISETTE_URL


def scrub(text: str) -> str:
    """Drop user info and query strings from every URL in a message, however it was normalised."""
    return re.sub(r"\?[^\s'\"]*", "", re.sub(r"(\w+://)[^/\s@]*@", r"\1", text))


def shown(url: str) -> str:
    """Return the URL without user info, query and fragment: it may carry credentials."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}"


def anisette_endpoint(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    return host, parts.port or (443 if parts.scheme == "https" else 80)


def _ask_apple(url: str) -> tuple[str, int | None]:
    """(RINFO of the server's data, Apple's answer to the account-less init probe)."""
    from passwords_app.icloud.auth.anisette import Anisette  # noqa: PLC0415 - pulls in requests
    from passwords_app.icloud.auth.device import Device  # noqa: PLC0415
    from passwords_app.icloud.auth.gsa import GSAClient  # noqa: PLC0415

    anisette = Anisette(url)
    rinfo = anisette.headers().get("X-Apple-I-MD-RINFO", "")
    return rinfo, GSAClient(Device.generate(), anisette).probe_client()


NO_DATA_HINT = "Is it an anisette server? `passwords-app install` starts the one that works."


async def check_anisette_data(url: str) -> Check:
    """Ask Apple, with no account, whether it accepts the machine data this server makes."""
    from passwords_app.icloud.auth.anisette import AnisetteError  # noqa: PLC0415
    from passwords_app.icloud.auth.gsa import (  # noqa: PLC0415
        ACCEPTED_CLIENT_CODE,
        REFUSED_CLIENT_CODE,
    )
    from passwords_app.icloud.errors import AppleError  # noqa: PLC0415

    name = "Apple accepts the anisette data"
    where = shown(url)
    try:
        rinfo, code = await asyncio.to_thread(_ask_apple, url)
    except AnisetteError as exc:
        detail = f"{where} gave no machine data: {scrub(str(exc))}"
        return Check(name, "fail", detail, NO_DATA_HINT)
    except AppleError as exc:
        reason = scrub(str(exc))
        return Check(
            name, "warn", f"could not ask Apple: {reason}", "Check the internet connection."
        )
    origin = _ADI_ORIGINS.get(rinfo, "unknown ADI")
    fingerprint = f"{origin}, X-Apple-I-MD-RINFO {rinfo or 'missing'}"
    if code == ACCEPTED_CLIENT_CODE:
        return Check(
            name, "ok", f"{where} serves {fingerprint}; Apple's init probe answered {code}"
        )
    if code == REFUSED_CLIENT_CODE:
        return Check(
            name,
            "fail",
            f"Apple refuses the data of {where} ({fingerprint}): init probe answered {code}",
            "Apple stopped accepting Android-ADI anisette (dadoum/anisette-v3-server, "
            "Dadoum/anisette-v3-server#61): no sign-in step can start. Run `passwords-app install` "
            "(it builds the Windows-ADI server from docker/anisette) or set "
            f"{ANISETTE_URL_VARIABLE} to a server that serves Windows or macOS ADI data.",
        )
    return Check(
        name,
        "warn",
        f"{where} serves {fingerprint}; Apple's init probe answered {code}, which is not a verdict",
        "Try again later; if it stays, Apple changed its answer.",
    )


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


async def run_checks(home: Path, *, anisette_url: str | None = None) -> list[Check]:
    url = anisette_url or configured_anisette_url()
    checks: list[Check] = []
    try:
        host, port = anisette_endpoint(url)
        tls = urlsplit(url).scheme == "https"
    except ValueError:
        # Not echoed: a malformed URL may still carry credentials.
        checks.append(
            Check(
                ANISETTE_CHECK,
                "fail",
                f"{ANISETTE_URL_VARIABLE} is not a valid URL",
                f"Set {ANISETTE_URL_VARIABLE} to e.g. http://127.0.0.1:6970 or unset it.",
            )
        )
    else:
        reachable = await check_anisette(host, port, tls=tls)
        checks.append(reachable)
        if reachable.level == "ok":
            checks.append(await check_anisette_data(url))
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
