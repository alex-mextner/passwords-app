# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Doctor checks that need no bus: anisette reachability, sync state, browser manifests."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import TYPE_CHECKING

import pytest

from passwords_app.cli.doctor import (
    NATIVE_HOST,
    Check,
    check_anisette,
    check_browsers,
    check_sync_state,
    healthy,
    render,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable
    from pathlib import Path

pytestmark = pytest.mark.timeout(30)


async def serve(reply: bytes) -> tuple[asyncio.Server, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.fixture
async def server_factory() -> AsyncIterator[Callable[[bytes], Awaitable[int]]]:
    servers: list[asyncio.Server] = []

    async def make(reply: bytes) -> int:
        server, port = await serve(reply)
        servers.append(server)
        return port

    yield make
    for s in servers:
        s.close()
        await s.wait_closed()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_anisette_ok(server_factory: Callable[[bytes], Awaitable[int]]) -> None:
    port = await server_factory(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    check = await check_anisette("127.0.0.1", port)
    assert check.level == "ok"
    assert f"127.0.0.1:{port}" in check.detail


async def test_anisette_not_http(server_factory: Callable[[bytes], Awaitable[int]]) -> None:
    port = await server_factory(b"SSH-2.0-OpenSSH\r\n")
    check = await check_anisette("127.0.0.1", port)
    assert check.level == "fail"
    assert "not over HTTP" in check.detail


async def test_anisette_down() -> None:
    check = await check_anisette("127.0.0.1", free_port())
    assert check.level == "fail"
    assert "nothing answers" in check.detail
    assert "passwords-app install" in check.hint


@pytest.mark.parametrize(
    ("state", "level", "hint"),
    [
        ("idle", "ok", ""),
        ("syncing", "ok", ""),
        ("paused", "warn", "resolve"),
        ("offline", "warn", ""),
        ("signed-out", "warn", "signin"),
        ("signin-required", "fail", "signin"),
        ("error", "fail", "journalctl"),
        ("unheard-of", "fail", ""),
    ],
)
def test_sync_state(state: str, level: str, hint: str) -> None:
    check = check_sync_state({"state": state, "message": "details here"})
    assert check.level == level
    assert hint in check.hint
    assert check.detail == f"{state} — details here"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return tmp_path


def manifest(path: Path, host: str | None, *, raw: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw if raw is not None else json.dumps({"name": NATIVE_HOST, "path": host}))


def executable(path: Path) -> str:
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return str(path)


def by_browser(checks: list[Check]) -> dict[str, Check]:
    return {c.name.removesuffix(" autofill helper"): c for c in checks}


def test_no_browsers_installed(home: Path) -> None:
    checks = by_browser(check_browsers(home))
    assert set(checks) == {"Firefox", "Google Chrome", "Chromium"}
    assert {c.level for c in checks.values()} == {"skip"}


def test_browser_installed_but_helper_missing(home: Path) -> None:
    (home / ".mozilla").mkdir()
    (home / ".config" / "google-chrome").mkdir(parents=True)
    checks = by_browser(check_browsers(home))
    assert checks["Firefox"].level == "warn"
    assert checks["Google Chrome"].level == "warn"
    assert "passwords-app install" in checks["Firefox"].hint
    assert checks["Chromium"].level == "skip"


def test_registered_helpers(home: Path) -> None:
    host = executable(home / "native-host")
    manifest(home / ".mozilla" / "native-messaging-hosts" / f"{NATIVE_HOST}.json", host)
    manifest(
        home / ".config" / "google-chrome" / "NativeMessagingHosts" / f"{NATIVE_HOST}.json", host
    )
    checks = by_browser(check_browsers(home))
    assert checks["Firefox"].level == "ok"
    assert checks["Google Chrome"].level == "ok"


@pytest.mark.parametrize(
    ("raw", "host", "problem"),
    [
        ("{not json", None, "unreadable manifest"),
        (None, None, "no host path"),
        (None, "", "no host path"),
        ('["a list"]', None, "no host path"),
        (None, "/nonexistent/native-host", "missing or not executable"),
    ],
)
def test_broken_manifests(home: Path, raw: str | None, host: str | None, problem: str) -> None:
    manifest(home / ".mozilla" / "native-messaging-hosts" / f"{NATIVE_HOST}.json", host, raw=raw)
    check = by_browser(check_browsers(home))["Firefox"]
    assert check.level == "fail"
    assert problem in check.detail


def test_non_executable_host(home: Path) -> None:
    host = home / "native-host"
    host.write_text("#!/bin/sh\n")
    host.chmod(0o644)
    manifest(home / ".mozilla" / "native-messaging-hosts" / f"{NATIVE_HOST}.json", str(host))
    assert by_browser(check_browsers(home))["Firefox"].level == "fail"


def test_render_shows_hints_only_for_problems() -> None:
    text = render(
        [
            Check("A", "ok", "fine", "never shown"),
            Check("B", "warn", "meh", "do this"),
            Check("C", "fail", "broken", "do that"),
            Check("D", "skip", "absent", "not shown either"),
        ]
    )
    assert text.splitlines() == [
        "✓ A: fine",
        "! B: meh",
        "    do this",
        "✗ C: broken",
        "    do that",
        "- D: absent",
    ]


@pytest.mark.parametrize(
    ("levels", "ok"),
    [
        ([], True),
        (["ok", "skip"], True),
        (["ok", "warn"], True),
        (["ok", "fail"], False),
    ],
)
def test_healthy(levels: list[str], ok: bool) -> None:
    assert healthy([Check("x", lv, "d") for lv in levels]) is ok  # type: ignore[arg-type]


def test_check_json() -> None:
    assert Check("n", "warn", "d", "h").to_json() == {
        "name": "n",
        "level": "warn",
        "detail": "d",
        "hint": "h",
    }
