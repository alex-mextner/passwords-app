# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Argument parsing, the GUI hand-off, and the exit code for every failure class.

Nothing here reaches a bus: the command runner is replaced where a command would run.
"""

from __future__ import annotations

import importlib.metadata
import sys
import types
from typing import TYPE_CHECKING, Any

import pytest

from passwords_app.cli import main as cli
from passwords_app.cli.client import DaemonCallError, DaemonUnreachableError
from passwords_app.cli.installer import ScriptNotFoundError
from passwords_app.cli.signin import SignInBlockedError, SignInCancelledError

if TYPE_CHECKING:
    import argparse

ERR = "io.github.alex_mextner.Passwords1.Error."


@pytest.fixture
def ran(monkeypatch: pytest.MonkeyPatch) -> list[argparse.Namespace]:
    calls: list[argparse.Namespace] = []

    def fake_run(args: argparse.Namespace, ctx: cli.Context) -> int:
        calls.append(args)
        return 0

    monkeypatch.setattr(cli, "_run", fake_run)
    return calls


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["status"], {"command": "status", "json": False}),
        (["status", "--json"], {"command": "status", "json": True}),
        (["sync"], {"command": "sync"}),
        (["list"], {"command": "list", "query": None}),
        (["list", "mail"], {"command": "list", "query": "mail"}),
        (["show", "ID-1"], {"command": "show", "item": "ID-1", "password": False}),
        (["show", "ID-1", "--password"], {"command": "show", "password": True}),
        (["trash"], {"command": "trash", "action": "list"}),
        (["trash", "restore", "T1"], {"action": "restore", "trash_id": "T1"}),
        (["trash", "purge", "T1", "--yes"], {"action": "purge", "yes": True}),
        (["resolve", "apply"], {"command": "resolve", "choice": "apply"}),
        (["resolve", "restore"], {"choice": "restore"}),
        (["signin"], {"command": "signin", "apple_id": None}),
        (["signin", "--apple-id", "a@example.com"], {"apple_id": "a@example.com"}),
        (["signout", "--yes"], {"command": "signout", "yes": True}),
        (["doctor"], {"command": "doctor"}),
        (["install"], {"command": "install"}),
        (["uninstall", "--purge"], {"command": "uninstall", "purge": True}),
    ],
)
def test_parsing(ran: list[argparse.Namespace], argv: list[str], expected: dict[str, Any]) -> None:
    assert cli.main(argv) == 0
    (args,) = ran
    for key, value in expected.items():
        assert getattr(args, key) == value


@pytest.mark.parametrize(
    "argv",
    [
        ["resolve"],
        ["resolve", "maybe"],
        ["show"],
        ["trash", "restore"],
        ["trash", "purge"],
        ["trash", "empty"],
        ["frobnicate"],
        ["status", "--bogus"],
    ],
)
def test_usage_errors_exit_2(ran: list[argparse.Namespace], argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(argv)
    assert info.value.code == cli.EXIT_USAGE
    assert ran == []


def test_help_documents_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    assert "exit codes:" in out
    for code in ("3  the sync service", "5  sign-in", "6  the keyring is locked"):
        assert code in out


@pytest.fixture
def fake_app(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    module = types.ModuleType("passwords_app.app.main")

    def app_main(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    module.main = app_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "passwords_app.app.main", module)
    return calls


@pytest.mark.parametrize(
    "argv",
    [
        [],  # the app's icon and the desktop file's main action
        ["--new"],  # the desktop file's "New Password" action
        ["--search-provider"],  # the GNOME Shell search provider's D-Bus activation
        ["--gapplication-service"],  # GApplication's own options pass through untouched
        ["--new", "--gapplication-service"],
    ],
)
def test_the_app_gets_the_full_argv(
    fake_app: list[list[str]], ran: list[argparse.Namespace], argv: list[str]
) -> None:
    assert cli.main(argv) == 0
    assert fake_app == [["passwords-app", *argv]]
    assert ran == []


def test_the_app_s_exit_status_is_passed_on(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("passwords_app.app.main")
    module.main = lambda _argv: 3  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "passwords_app.app.main", module)
    assert cli.main(["--new"]) == 3


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_stays_with_the_cli(
    fake_app: list[list[str]], capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main([flag])
    assert info.value.code == 0
    assert "usage: passwords-app" in capsys.readouterr().out
    assert fake_app == []


def test_version_stays_with_the_cli(
    fake_app: list[list[str]], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert (
        capsys.readouterr().out == f"passwords-app {importlib.metadata.version('passwords-app')}\n"
    )
    assert fake_app == []


def test_the_app_module_is_imported_only_when_the_app_is_wanted(
    monkeypatch: pytest.MonkeyPatch, ran: list[argparse.Namespace]
) -> None:
    monkeypatch.delitem(sys.modules, "passwords_app.app.main", raising=False)
    assert cli.main(["status"]) == 0
    assert "passwords_app.app.main" not in sys.modules
    assert len(ran) == 1


def test_missing_app_is_explained(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "passwords_app.app.main", None)
    assert cli.main([]) == cli.EXIT_FAILED
    assert "not installed" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("exc", "code", "text"),
    [
        (DaemonUnreachableError("no owner"), cli.EXIT_DAEMON, "doctor"),
        (
            DaemonCallError(ERR + "NotFound", "No password with this id."),
            cli.EXIT_NOT_FOUND,
            "No password",
        ),
        (
            DaemonCallError(ERR + "AuthRequired", "sign in"),
            cli.EXIT_SIGN_IN,
            "passwords-app signin",
        ),
        (DaemonCallError(ERR + "WrongCode", "bad code"), cli.EXIT_SIGN_IN, "bad code"),
        (DaemonCallError(ERR + "WrongPasscode", "8 left"), cli.EXIT_SIGN_IN, "8 left"),
        (DaemonCallError(ERR + "Locked", "locked"), cli.EXIT_LOCKED, "Seahorse"),
        (DaemonCallError(ERR + "Invalid", "url is required"), cli.EXIT_INVALID, "url is required"),
        (DaemonCallError(ERR + "Unavailable", "no network"), cli.EXIT_FAILED, "internet"),
        (DaemonCallError("org.freedesktop.DBus.Error.Failed", "boom"), cli.EXIT_FAILED, "boom"),
        (cli.CliError("ambiguous", cli.EXIT_USAGE, "pick one"), cli.EXIT_USAGE, "pick one"),
        (SignInCancelledError("stopped"), cli.EXIT_INTERRUPTED, "stopped"),
        (SignInBlockedError("no devices"), cli.EXIT_SIGN_IN, "no devices"),
        (ScriptNotFoundError("install.sh not found"), cli.EXIT_FAILED, "git clone"),
        (KeyboardInterrupt(), cli.EXIT_INTERRUPTED, "interrupted"),
        (EOFError(), cli.EXIT_INTERRUPTED, "interrupted"),
    ],
)
def test_failures_map_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exc: BaseException,
    code: int,
    text: str,
) -> None:
    if isinstance(exc, ScriptNotFoundError):
        exc = ScriptNotFoundError("install.sh not found. Run it from a checkout: git clone ...")

    def boom(args: argparse.Namespace, ctx: cli.Context) -> int:
        raise exc

    monkeypatch.setattr(cli, "_run", boom)
    assert cli.main(["status"]) == code
    err = capsys.readouterr().err
    assert err.startswith("passwords-app: ")
    assert text in err


def test_exit_codes_are_distinct() -> None:
    codes = [
        cli.EXIT_OK,
        cli.EXIT_FAILED,
        cli.EXIT_USAGE,
        cli.EXIT_DAEMON,
        cli.EXIT_NOT_FOUND,
        cli.EXIT_SIGN_IN,
        cli.EXIT_LOCKED,
        cli.EXIT_INVALID,
        cli.EXIT_INTERRUPTED,
    ]
    assert len(set(codes)) == len(codes)


def test_install_and_uninstall_run_the_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, list[str]]] = []

    def fake_script(name: str, args: list[str]) -> int:
        calls.append((name, list(args)))
        return 7

    monkeypatch.setattr(cli, "run_script", fake_script)
    assert cli.main(["install"]) == 7
    assert cli.main(["uninstall"]) == 7
    assert cli.main(["uninstall", "--purge"]) == 7
    assert calls == [("install.sh", []), ("uninstall.sh", []), ("uninstall.sh", ["--purge"])]
