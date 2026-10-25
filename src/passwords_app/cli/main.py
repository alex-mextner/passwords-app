# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app`: opens the Passwords app, or runs a subcommand in a terminal.

No arguments, or a first argument that is an option the CLI does not own (`--new`,
`--search-provider`, GApplication's own flags), hands the whole command line to the app:
the desktop file and the GNOME Shell search provider launch it that way.

Every subcommand except install/uninstall talks to the daemon over D-Bus. Failures exit with
a stable code per class (see EPILOG) and a message that says what to do next.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from passwords_app.cli import format as fmt
from passwords_app.cli.client import DaemonCallError, DaemonClient, DaemonUnreachableError
from passwords_app.cli.installer import ScriptNotFoundError, run_script
from passwords_app.cli.service import (
    DaemonStartError,
    ServiceUnit,
    SystemdUserUnit,
    ensure_running,
)
from passwords_app.cli.signin import (
    ConsoleTerminal,
    SignInBlockedError,
    SignInCancelledError,
    Terminal,
    run_wizard,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

PROG = "passwords-app"
# Options argparse answers itself; any other leading option belongs to the app.
_CLI_OPTIONS = frozenset({"-h", "--help", "--version"})

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_DAEMON = 3
EXIT_NOT_FOUND = 4
EXIT_SIGN_IN = 5
EXIT_LOCKED = 6
EXIT_INVALID = 7
EXIT_INTERRUPTED = 130

EPILOG = """\
exit codes:
  0  success
  1  the command ran but the result needs attention (sync error, doctor found problems)
  2  invalid arguments
  3  the sync service is not reachable
  4  no such password or deleted item
  5  sign-in needed or rejected by Apple
  6  the keyring is locked
  7  the daemon refused the input
  130 interrupted
"""

_ERROR_EXITS = {
    "NotFound": EXIT_NOT_FOUND,
    "AuthRequired": EXIT_SIGN_IN,
    "WrongCode": EXIT_SIGN_IN,
    "WrongPasscode": EXIT_SIGN_IN,
    "Locked": EXIT_LOCKED,
    "Invalid": EXIT_INVALID,
    "Unavailable": EXIT_FAILED,
}
_ERROR_HINTS = {
    "AuthRequired": "Run `passwords-app signin`.",
    "Locked": 'Unlock the "iCloud Passwords" keyring in Passwords and Keys (Seahorse).',
    "Unavailable": "Check your internet connection and `passwords-app doctor`.",
}
_ATTENTION_STATES = frozenset({"error", "offline", "signin-required", "paused"})


class CliError(Exception):
    def __init__(self, message: str, code: int, hint: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.hint = hint


class Context:
    """What a command needs besides its arguments (replaced in tests)."""

    def __init__(
        self,
        terminal: Terminal | None = None,
        now: Callable[[], datetime] | None = None,
        service: ServiceUnit | None = None,
    ) -> None:
        self.terminal = terminal or ConsoleTerminal()
        self.now = now or (lambda: datetime.now(UTC))
        self.service = service or SystemdUserUnit()

    def out(self, text: str = "") -> None:
        self.terminal.say(text)


def _json(value: Any) -> str:  # noqa: ANN401 - any JSON-able reply
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


# ---------------------------------------------------------------- commands


async def cmd_status(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    status = await client.status()
    ctx.out(_json(status) if args.json else fmt.status_text(status, ctx.now()))
    return EXIT_OK


async def cmd_sync(client: DaemonClient, _args: argparse.Namespace, ctx: Context) -> int:
    await client.sync_now()
    status = await client.status()
    ctx.out(fmt.status_text(status, ctx.now()))
    return EXIT_FAILED if status["state"] in _ATTENTION_STATES else EXIT_OK


async def cmd_list(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    items = fmt.filter_items(await client.items(), args.query or "")
    ctx.out(_json(items) if args.json else fmt.items_table(items))
    return EXIT_OK


async def _resolve_item(client: DaemonClient, query: str) -> str:
    items = await client.items()
    if any(i["id"] == query for i in items):
        return query
    matches = fmt.filter_items(items, query)
    if len(matches) == 1:
        return str(matches[0]["id"])
    if not matches:
        msg = f"No password matches {query!r}."
        raise CliError(msg, EXIT_NOT_FOUND, "See `passwords-app list`.")
    msg = f"{len(matches)} passwords match {query!r}; use one of their IDs:\n"
    raise CliError(msg + fmt.items_table(matches), EXIT_USAGE)


async def cmd_show(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    item = await client.get(await _resolve_item(client, args.item))
    code = await client.code(str(item["id"])) if item.get("has_code") else None
    if args.json:
        shown = {k: v for k, v in item.items() if k != "otpauth"}
        if not args.password:
            shown.pop("password", None)
        if code is not None:
            shown["code"], shown["code_seconds_left"] = code
        ctx.out(_json(shown))
    else:
        ctx.out(fmt.item_detail(item, reveal=args.password, code=code, now=ctx.now()))
    return EXIT_OK


async def cmd_trash(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    if args.action == "restore":
        new_id = await client.restore(args.trash_id)
        ctx.out(f"Restored as {new_id}. It will be uploaded to iCloud with the next sync.")
        return EXIT_OK
    if args.action == "purge":
        if not args.yes:
            answer = ctx.terminal.ask("Delete it for good? This cannot be undone. [y/N]: ")
            if answer.strip().casefold() not in {"y", "yes"}:
                ctx.out("Kept.")
                return EXIT_OK
        await client.purge(args.trash_id)
        ctx.out("Deleted for good.")
        return EXIT_OK
    entries = await client.trash()
    ctx.out(_json(entries) if args.json else fmt.trash_table(entries, ctx.now()))
    return EXIT_OK


async def cmd_resolve(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    await client.resolve_pause(apply=args.choice == "apply")
    ctx.out(
        "Deletions applied; the items are in Recently Deleted for 90 days."
        if args.choice == "apply"
        else "Deleted items restored on both sides."
    )
    return EXIT_OK


async def cmd_signin(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    await run_wizard(client, ctx.terminal, apple_id=args.apple_id)
    return EXIT_OK


async def cmd_signout(client: DaemonClient, args: argparse.Namespace, ctx: Context) -> int:
    if not args.yes:
        answer = ctx.terminal.ask(
            "Sign out of iCloud? Passwords stay in your keyring but stop syncing. [y/N]: "
        )
        if answer.strip().casefold() not in {"y", "yes"}:
            ctx.out("Still signed in.")
            return EXIT_OK
    await client.sign_out()
    ctx.out("Signed out. Your passwords are still in the keyring.")
    return EXIT_OK


async def cmd_doctor(args: argparse.Namespace, ctx: Context) -> int:
    from passwords_app.cli import doctor  # noqa: PLC0415 - pulls in the keyring client

    checks = await doctor.run_checks(Path.home())
    ctx.out(_json([c.to_json() for c in checks]) if args.json else doctor.render(checks))
    return EXIT_OK if doctor.healthy(checks) else EXIT_FAILED


# ---------------------------------------------------------------- parsing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="iCloud Passwords on Linux. Without a command, opens the Passwords app.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {importlib.metadata.version(PROG)}"
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("status", help="show sync status")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub.add_parser("sync", help="sync now and show the result")
    p = sub.add_parser("list", help="list passwords (no secrets)")
    p.add_argument("query", nargs="?", help="filter by name, website, or username")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = sub.add_parser("show", help="show one password's details")
    p.add_argument("item", help="ID, or text that matches exactly one password")
    p.add_argument("--password", action="store_true", help="print the password itself")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = sub.add_parser("trash", help="Recently Deleted: list, restore, or purge")
    p.add_argument("action", nargs="?", choices=["list", "restore", "purge"], default="list")
    p.add_argument("trash_id", nargs="?", help="TRASH ID from `passwords-app trash`")
    p.add_argument("--yes", action="store_true", help="purge without asking")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = sub.add_parser("resolve", help="decide about deletions held back by a sync pause")
    p.add_argument("choice", choices=["apply", "restore"])
    p = sub.add_parser("signin", help="sign in to iCloud Keychain")
    p.add_argument("--apple-id", help="Apple Account email or phone number")
    p = sub.add_parser("signout", help="sign out of iCloud (passwords stay in the keyring)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p = sub.add_parser("doctor", help="check the installation and say how to fix problems")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub.add_parser("install", help="install or update the service, app, and browser helper")
    p = sub.add_parser("uninstall", help="remove the installation (keeps your data)")
    p.add_argument("--purge", action="store_true", help="also delete local data and settings")
    return parser


_DAEMON_COMMANDS: dict[
    str, Callable[[DaemonClient, argparse.Namespace, Context], Awaitable[int]]
] = {
    "status": cmd_status,
    "sync": cmd_sync,
    "list": cmd_list,
    "show": cmd_show,
    "trash": cmd_trash,
    "resolve": cmd_resolve,
    "signin": cmd_signin,
    "signout": cmd_signout,
}


async def _with_daemon(args: argparse.Namespace, ctx: Context) -> int:
    command = _DAEMON_COMMANDS[args.command]
    async with await DaemonClient.connect() as client:
        await ensure_running(client.is_running, ctx.service)
        return await command(client, args, ctx)


def _run(args: argparse.Namespace, ctx: Context) -> int:
    if args.command == "doctor":
        return asyncio.run(cmd_doctor(args, ctx))
    if args.command in {"install", "uninstall"}:
        extra = ["--purge"] if getattr(args, "purge", False) else []
        return run_script(f"{args.command}.sh", extra)
    return asyncio.run(_with_daemon(args, ctx))


def _explain(exc: BaseException) -> tuple[str, str, int]:
    """(message, hint, exit code) for an expected failure."""
    hint = ""
    match exc:
        case DaemonUnreachableError():
            message, hint, code = (
                f"the sync service is not reachable ({exc}).",
                "Run `passwords-app doctor`.",
                EXIT_DAEMON,
            )
        case DaemonCallError(short=short):
            message, hint = str(exc), _ERROR_HINTS.get(short, "")
            code = _ERROR_EXITS.get(short, EXIT_FAILED)
        case DaemonStartError():
            message, hint, code = (
                f"the sync service could not be started: {exc}.",
                "Full log: `journalctl --user -u passwords-appd`. Then `passwords-app doctor`.",
                EXIT_DAEMON,
            )
        case CliError(code=cli_code, hint=cli_hint):
            message, hint, code = str(exc), cli_hint, cli_code
        case SignInCancelledError():
            message, code = str(exc), EXIT_INTERRUPTED
        case SignInBlockedError():
            message, code = str(exc), EXIT_SIGN_IN
        case ScriptNotFoundError():
            message, code = str(exc), EXIT_FAILED
        case _:
            message, code = "interrupted.", EXIT_INTERRUPTED
    return message, hint, code


def _for_the_app(args: Sequence[str]) -> bool:
    return not args or (args[0].startswith("-") and args[0] not in _CLI_OPTIONS)


def open_app(args: Sequence[str]) -> int:
    try:
        app = importlib.import_module("passwords_app.app.main")
    except ImportError:
        print(  # noqa: T201
            "passwords-app: the Passwords window is not installed in this environment.\n"
            "Run `passwords-app --help` for the command-line tools.",
            file=sys.stderr,
        )
        return EXIT_FAILED
    # GApplication reads argv[0] as the program name and parses the rest itself.
    return int(app.main([PROG, *args]))


def main(argv: Sequence[str] | None = None, *, ctx: Context | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if _for_the_app(args_list):
        return open_app(args_list)
    parser = build_parser()
    args = parser.parse_args(args_list)
    if args.command == "trash" and args.action in {"restore", "purge"} and not args.trash_id:
        parser.error(f"trash {args.action} needs a TRASH ID")
    ctx = ctx or Context()
    try:
        return _run(args, ctx)
    except (
        DaemonUnreachableError,
        DaemonStartError,
        DaemonCallError,
        CliError,
        SignInCancelledError,
        SignInBlockedError,
        ScriptNotFoundError,
        KeyboardInterrupt,
        EOFError,
    ) as exc:
        message, hint, code = _explain(exc)
        print(f"passwords-app: {message}", file=sys.stderr)  # noqa: T201 - CLI diagnostics
        if hint:
            print(hint, file=sys.stderr)  # noqa: T201
        return code
