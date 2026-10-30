# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Doctor checks that need no bus: anisette reachability, sync state, browser manifests."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import subprocess
from typing import TYPE_CHECKING, NoReturn

import pytest

from passwords_app.cli import doctor
from passwords_app.cli.doctor import (
    NATIVE_HOST,
    Check,
    anisette_endpoint,
    check_anisette,
    check_anisette_data,
    check_browsers,
    check_sync_state,
    configured_anisette_url,
    healthy,
    render,
)
from passwords_app.icloud.auth.anisette import AnisetteError
from passwords_app.icloud.const import DEFAULT_ANISETTE_URL
from passwords_app.icloud.errors import AppleError

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


async def test_anisette_over_https_is_probed_with_tls_and_a_verified_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    class Writer:
        def write(self, _data: bytes) -> None: ...

        async def drain(self) -> None: ...

        def close(self) -> None: ...

        async def wait_closed(self) -> None: ...

    class Reader:
        async def readline(self) -> bytes:
            return b"HTTP/1.1 200 OK\r\n"

    async def open_connection(host: str, port: int, **kwargs: object) -> tuple[Reader, Writer]:
        seen.update(host=host, port=port, **kwargs)
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    check = await check_anisette("anisette.example", 443, tls=True)

    assert check.level == "ok"
    assert isinstance(seen["ssl"], ssl.SSLContext)
    assert seen["ssl"].verify_mode == ssl.CERT_REQUIRED
    assert seen["ssl"].check_hostname


async def test_anisette_over_plain_http_uses_no_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    async def open_connection(host: str, port: int, **kwargs: object) -> tuple[None, None]:
        seen.update(kwargs)
        raise OSError

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    await check_anisette("127.0.0.1", 6970)
    assert seen == {"ssl": None}


@pytest.mark.parametrize(
    "url",
    ["http://localhost:not-a-port", "http://localhost:99999", "http://[::1", "http://us:pw@[x"],
)
async def test_an_invalid_url_fails_one_check_without_echoing_it_and_the_rest_still_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str
) -> None:
    class NoBus:
        async def connect(self) -> NoReturn:
            msg = "no bus in this test"
            raise OSError(msg)

    monkeypatch.setattr(doctor, "MessageBus", NoBus)

    checks = await doctor.run_checks(tmp_path, anisette_url=url)

    assert checks[0].name == "Apple sign-in helper (anisette)"
    assert checks[0].level == "fail"
    assert "not a valid URL" in checks[0].detail
    assert "us:pw" not in render(checks)
    assert any(check.name == "Session bus" for check in checks)


def asked_apple(monkeypatch: pytest.MonkeyPatch, rinfo: str, code: int | None) -> None:
    monkeypatch.setattr(doctor, "_ask_apple", lambda _url: (rinfo, code))


async def test_anisette_data_apple_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    asked_apple(monkeypatch, "84215040", -20970)
    check = await check_anisette_data("http://localhost:6970")
    assert check.level == "ok"
    assert "Windows ADI" in check.detail
    assert "-20970" in check.detail


async def test_anisette_data_apple_refuses_the_android_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked_apple(monkeypatch, "17106176", -80045)
    check = await check_anisette_data("http://localhost:6969")
    assert check.level == "fail"
    assert "Android ADI" in check.detail
    assert "17106176" in check.detail
    assert "-80045" in check.detail
    assert "passwords-app install" in check.hint
    assert "PASSWORDS_APP_ANISETTE_URL" in check.hint
    assert "Windows or macOS" in check.hint


async def test_anisette_data_an_answer_that_is_no_verdict_is_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked_apple(monkeypatch, "33883392", None)
    check = await check_anisette_data("http://localhost:6970")
    assert check.level == "warn"
    assert "macOS ADI" in check.detail


async def test_anisette_data_unreachable_apple_is_a_warning_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def offline(_url: str) -> tuple[str, int | None]:
        msg = "GSA init request failed: no route"
        raise AppleError(msg)

    monkeypatch.setattr(doctor, "_ask_apple", offline)
    check = await check_anisette_data("http://localhost:6970")
    assert (check.level, "no route" in check.detail) == ("warn", True)


async def test_anisette_data_a_server_without_machine_data_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def junk(_url: str) -> tuple[str, int | None]:
        msg = "did not return machine data"
        raise AnisetteError(msg)

    monkeypatch.setattr(doctor, "_ask_apple", junk)
    check = await check_anisette_data("http://localhost:6970")
    assert check.level == "fail"
    assert "machine data" in check.detail


@pytest.mark.parametrize(
    ("url", "endpoint"),
    [
        ("http://localhost:6970", ("localhost", 6970)),
        ("http://127.0.0.1:6970/", ("127.0.0.1", 6970)),
        ("http://anisette.example", ("anisette.example", 80)),
        ("https://anisette.example/x", ("anisette.example", 443)),
    ],
)
def test_anisette_endpoint(url: str, endpoint: tuple[str, int]) -> None:
    assert anisette_endpoint(url) == endpoint


def test_the_services_own_url_wins_over_this_shells_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PASSWORDS_APP_ANISETTE_URL", "http://shell.example:1")
    monkeypatch.setattr(doctor, "service_anisette_url", lambda: "http://unit.example:2")
    assert configured_anisette_url() == "http://unit.example:2"


def test_without_a_service_url_the_shell_then_the_default_decide(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor, "service_anisette_url", lambda: None)
    monkeypatch.setenv("PASSWORDS_APP_ANISETTE_URL", "http://shell.example:1")
    assert configured_anisette_url() == "http://shell.example:1"
    monkeypatch.delenv("PASSWORDS_APP_ANISETTE_URL")
    assert configured_anisette_url() == DEFAULT_ANISETTE_URL


def fake_systemctl(
    monkeypatch: pytest.MonkeyPatch, *, main_pid: str = "0", environment: str = ""
) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        out = main_pid if "--property=MainPID" in argv else environment
        return subprocess.CompletedProcess(argv, 0, out + "\n", "")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_service_url_comes_from_the_running_services_own_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # EnvironmentFile= and inherited values only show up here, never in the unit's Environment=.
    calls = fake_systemctl(monkeypatch, main_pid="4242", environment="LANG=C")
    block = b"LANG=C\0PASSWORDS_APP_ANISETTE_URL=http://127.0.0.1:6970\0HOME=/h\0"
    monkeypatch.setattr(doctor, "_process_environment", lambda pid: block if pid == 4242 else None)
    assert doctor.service_anisette_url() == "http://127.0.0.1:6970"
    assert calls[0][:3] == ["systemctl", "--user", "show"]
    assert "passwords-appd.service" in calls[0]


def test_a_running_service_that_sets_none_means_the_default_not_this_shells_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_systemctl(
        monkeypatch, main_pid="4242", environment="PASSWORDS_APP_ANISETTE_URL=http://unit:1"
    )
    monkeypatch.setattr(doctor, "_process_environment", lambda _pid: b"LANG=C\0")
    monkeypatch.setenv("PASSWORDS_APP_ANISETTE_URL", "http://shell.example:1")
    assert doctor.service_anisette_url() == ""
    assert configured_anisette_url() == DEFAULT_ANISETTE_URL


@pytest.mark.parametrize(
    ("serialized", "url"),
    [
        ("PASSWORDS_APP_ANISETTE_URL=http://127.0.0.1:6970", "http://127.0.0.1:6970"),
        ('"PASSWORDS_APP_ANISETTE_URL=http://[::1]:6970"', "http://[::1]:6970"),
        (
            '"PASSWORDS_APP_ANISETTE_URL=https://anisette.example/v1?token=abc"',
            "https://anisette.example/v1?token=abc",
        ),
    ],
)
def test_a_stopped_service_falls_back_to_the_units_environment_as_systemd_quotes_it(
    monkeypatch: pytest.MonkeyPatch, serialized: str, url: str
) -> None:
    fake_systemctl(monkeypatch, environment=f"LANG=C {serialized} X=1")
    assert doctor.service_anisette_url() == url


def test_dollar_signs_in_systemds_escaping_come_back_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_systemctl(
        monkeypatch,
        environment='"PASSWORDS_APP_ANISETTE_URL=https://u:pa\\$ss@anisette.example/v1?t=a\\$b"',
    )
    assert doctor.service_anisette_url() == "https://u:pa$ss@anisette.example/v1?t=a$b"


def test_an_unreadable_process_environment_falls_back_to_the_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_systemctl(
        monkeypatch, main_pid="4242", environment="PASSWORDS_APP_ANISETTE_URL=http://u:2"
    )
    monkeypatch.setattr(doctor, "_process_environment", lambda _pid: None)
    assert doctor.service_anisette_url() == "http://u:2"


def test_service_url_is_unknown_when_the_unit_sets_none_and_nothing_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_systemctl(monkeypatch, environment="LANG=C")
    assert doctor.service_anisette_url() is None


def test_service_url_is_unknown_without_systemctl(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    assert doctor.service_anisette_url() is None


async def test_credentials_in_the_url_never_reach_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "https://alice:s3cret@anisette.example/v1?token=abc"

    def refuse(url: str) -> tuple[str, int | None]:
        # the client strips the trailing slash before it quotes the URL
        msg = f"Could not get anisette data from {url.replace('/v1?', '/v1/?')}: refused"
        raise AnisetteError(msg)

    monkeypatch.setattr(doctor, "_ask_apple", refuse)
    failed = await check_anisette_data(secret)
    asked_apple(monkeypatch, "84215040", -20970)
    accepted = await check_anisette_data(secret)
    asked_apple(monkeypatch, "17106176", -80045)
    refused = await check_anisette_data(secret)

    for check in (failed, accepted, refused):
        text = render([check])
        assert "https://anisette.example/v1" in text
        assert "s3cret" not in text
        assert "alice" not in text
        assert "token=abc" not in text


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
