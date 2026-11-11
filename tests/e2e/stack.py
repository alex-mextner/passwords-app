# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# Every password here is a fictional test value.
"""The whole product on one throwaway desktop, plus the hands and eyes a scenario needs.

`Stack` owns, per test:
- a private D-Bus session with its own unlocked gnome-keyring (tests/harness/dbus_session.py);
- `FakeCloudKit` and `AppleServices` (the Apple side), seeded through the real encoder;
- a signed-in, joined session persisted exactly where `passwords-app signin` leaves it;
- the real `passwords-appd` as a subprocess (tests/e2e/daemon_shim.py points it at the fakes);
- on demand, the real GTK app (in this process, drawn in a headless gnome-shell) and real
  Firefox / Chromium with the extension and the native host (tests/browser/e2e_support.py).

Helpers act on each surface the way its user would: `apple` is the iPhone, `keyring` is
Seahorse, `daemon` is any D-Bus client, `app` the GTK window, `firefox`/`chromium` the browsers.
Every wait is `wait_until`: poll with a deadline, never a bare sleep. At teardown the daemon's
and the native hosts' logs are copied to `LOGS/<test>/`, which CI uploads with the proof.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from tests.browser.e2e_support import NATIVE_HOST_LOG
from tests.e2e.apple import AppleServices, Phone
from tests.fakes.cloudkit_server import FakeCloudKit
from tests.fakes.icloud_session import DEVICE, make_session
from tests.harness.dbus_session import (
    KEYRING_PASSWORD,
    LOGIN_COLLECTION,
    lock_collection,
    start_private_session,
    unlock_collection,
)

from passwords_app.daemon import BUS_NAME, INTERFACE, OBJECT_PATH
from passwords_app.keyring.client import COLLECTION, ITEM, SecretServiceClient
from passwords_app.keyring.collection import find_collection

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    from tests.harness.dbus_session import PrivateSession

    from passwords_app.core.model import Credential

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
# Ignored by git; CI uploads docs/proof/** as the e2e-proof artifact.
LOGS = REPO / "docs" / "proof" / "raw" / "e2e" / "logs"
COLLECTION_LABEL = "iCloud Passwords"
NOTE_SCHEMA = "org.gnome.keyring.Note"
# The daemon's own timings, shrunk so "every minute" and "2 s after a change" fit a test.
FAST_SCHEDULE = {
    "ACTIVE_INTERVAL": 1.5,
    "IDLE_INTERVAL": 1.5,
    "DEBOUNCE": 0.5,
    "DEBOUNCE_MAX": 2.0,
    "BACKOFF_FIRST": 1.0,
    "BACKOFF_MAX": 3.0,
}
DEFAULT_TIMEOUT = 30.0


class SurfaceTimeoutError(AssertionError):
    """A surface never reached the expected state (what an xfail for a product bug names)."""


# ---------------------------------------------------------------------- waiting


def pump(seconds: float = 0.0) -> None:
    """Run pending GLib work (the in-process GTK app) for about `seconds`; sleep otherwise."""
    deadline = time.monotonic() + seconds
    while True:
        if "gi.repository.Gtk" in sys.modules:
            from gi.repository import GLib  # noqa: PLC0415

            context = GLib.MainContext.default()
            while context.iteration(False):  # noqa: FBT003
                pass
        if time.monotonic() >= deadline:
            return
        time.sleep(0.01)


def wait_until[T](
    probe: Callable[[], T | None], *, timeout: float = DEFAULT_TIMEOUT, what: str = "condition"
) -> T:
    """Poll `probe` (keeping the GTK main loop alive) until it is truthy or the deadline."""
    deadline = time.monotonic() + timeout
    while True:
        pump()
        result = probe()
        if result:
            return result
        if time.monotonic() > deadline:
            msg = f"timed out after {timeout:.0f}s waiting for {what}"
            raise SurfaceTimeoutError(msg)
        pump(0.1)


def stays[T](probe: Callable[[], T], *, seconds: float, what: str) -> T:
    """Assert `probe` stays truthy for `seconds` (several sync cycles); return its last value."""
    deadline = time.monotonic() + seconds
    while True:
        result = probe()
        assert result, f"{what} stopped holding"
        if time.monotonic() > deadline:
            return result
        pump(0.2)


# ---------------------------------------------------------------------- async bridge


class Loop:
    """A private asyncio loop on a thread, so sync tests can await dbus-fast calls."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

    def run[T](self, coro: Coroutine[Any, Any, T], timeout: float = 60.0) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def connect(self, address: str) -> MessageBus:
        async def go() -> MessageBus:
            return await MessageBus(bus_address=address).connect()

        return self.run(go())

    def disconnect(self, bus: MessageBus) -> None:
        async def go() -> None:
            bus.disconnect()
            await bus.wait_for_disconnect()  # type: ignore[no-untyped-call]

        self.run(go(), 10)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(5)
        self.loop.close()


def _plain(value: object) -> object:
    if isinstance(value, Variant):
        return _plain(value.value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in cast("dict[str, object]", value).items()}
    if isinstance(value, list):
        return [_plain(v) for v in cast("list[object]", value)]
    return value


class DaemonCallError(Exception):
    def __init__(self, name: str, text: str) -> None:
        super().__init__(f"{name}: {text}")
        self.name = name


class DaemonApi:
    """`io.github.alex_mextner.Passwords1` over plain D-Bus messages, as any client sees it."""

    def __init__(self, loop: Loop, address: str) -> None:
        self._loop = loop
        self._bus = loop.connect(address)

    def close(self) -> None:
        self._loop.disconnect(self._bus)

    def call(self, member: str, signature: str = "", *body: object, timeout: float = 60) -> Any:
        async def go() -> Any:
            reply = await self._bus.call(
                Message(
                    destination=BUS_NAME,
                    path=OBJECT_PATH,
                    interface=INTERFACE,
                    member=member,
                    signature=signature,
                    body=list(body),
                )
            )
            assert reply is not None
            if reply.message_type == MessageType.ERROR:
                text = str(reply.body[0]) if reply.body else ""
                raise DaemonCallError(reply.error_name or "", text)
            return reply.body

        out = _plain(self._loop.run(go(), timeout))
        assert isinstance(out, list)
        return out[0] if len(out) == 1 else (tuple(out) if out else None)

    def has_owner(self) -> bool:
        async def go() -> bool:
            reply = await self._bus.call(
                Message(
                    destination="org.freedesktop.DBus",
                    path="/org/freedesktop/DBus",
                    interface="org.freedesktop.DBus",
                    member="NameHasOwner",
                    signature="s",
                    body=[BUS_NAME],
                )
            )
            return bool(reply.body == [True])

        return self._loop.run(go())

    def status(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self.call("GetStatus"))

    def items(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self.call("List"))

    def get(self, item_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self.call("Get", "s", item_id))

    def find(self, url: str, username: str) -> list[dict[str, Any]]:
        return [i for i in self.items() if (i["url"], i["username"]) == (url, username)]

    def trash(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self.call("ListTrash"))

    def sync_now(self) -> None:
        self.call("SyncNow", timeout=120)

    def get_code(self, item_id: str) -> tuple[str, int]:
        return cast("tuple[str, int]", self.call("GetCode", "s", item_id))


@dataclass(frozen=True)
class KeyringItem:
    path: str
    label: str
    attributes: dict[str, str]
    secret: str

    @property
    def id(self) -> str | None:
        return self.attributes.get("pa-id")


class Keyring:
    """Seahorse ("Passwords and Keys") on the "iCloud Passwords" collection: raw Secret
    Service calls (through the thin `SecretServiceClient` wrapper) on a connection of its own;
    none of the daemon's store, mapping or label logic is involved."""

    def __init__(self, loop: Loop, address: str) -> None:
        self._loop = loop
        self.address = address
        self._bus = loop.connect(address)
        self.client = loop.run(SecretServiceClient.open(self._bus))

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._loop.run(self.client.close(), 10)
        self._loop.disconnect(self._bus)

    def collection(self) -> str | None:
        return self._loop.run(find_collection(self.client, COLLECTION_LABEL))

    def _collection(self) -> str:
        path = self.collection()
        assert path is not None, "the daemon has not created the iCloud Passwords keyring"
        return path

    def items(self) -> list[KeyringItem]:
        async def go() -> list[KeyringItem]:
            coll = await find_collection(self.client, COLLECTION_LABEL)
            if coll is None:
                return []
            paths = list(await self.client.get_property(coll, COLLECTION, "Items"))
            secrets = await self.client.get_secrets(paths)
            out = []
            for path in paths:
                props = await self.client.get_all(path, ITEM)
                secret = secrets.get(path)
                out.append(
                    KeyringItem(
                        path,
                        str(props["Label"]),
                        dict(props["Attributes"]),
                        secret.decode() if secret is not None else "",
                    )
                )
            return out

        return self._loop.run(go())

    def by_id(self, item_id: str) -> KeyringItem | None:
        found = [i for i in self.items() if i.id == item_id]
        assert len(found) <= 1, f"{len(found)} keyring items carry pa-id {item_id}"
        return found[0] if found else None

    def by_label(self, label: str) -> KeyringItem | None:
        found = [i for i in self.items() if i.label == label]
        return found[0] if len(found) == 1 else None

    def create(self, label: str, secret: str) -> str:
        """Seahorse's "New password": a Note item with just a label and a secret."""
        coll = self._collection()
        return self._loop.run(
            self.client.create_item(
                coll, label, {"xdg:schema": NOTE_SCHEMA}, secret.encode(), replace=False
            )
        )

    def _settle_human_pace(self, path: str) -> None:
        # Seahorse edits come from a person, seconds after the daemon last wrote the item;
        # the daemon tells its own writes from edits by that gap (keyring times are seconds).
        modified = int(self._loop.run(self.client.get_property(path, ITEM, "Modified")))
        while time.time() < modified + 3:
            pump(0.2)

    def set_secret(self, path: str, secret: str) -> None:
        self._settle_human_pace(path)
        self._loop.run(self.client.set_secret(path, secret.encode()))

    def rename(self, path: str, label: str) -> None:
        self._settle_human_pace(path)
        self._loop.run(self.client.set_property(path, ITEM, "Label", Variant("s", label)))

    def delete(self, path: str) -> None:
        self._loop.run(self.client.delete_item(path))

    def lock_everything(self) -> None:
        """Lock the iCloud collection and the login keyring (which holds its password)."""
        coll = self._collection()
        self._loop.run(lock_collection(self.address, coll))
        self._loop.run(lock_collection(self.address, LOGIN_COLLECTION))

    def unlock_login(self) -> None:
        """The user unlocks the login keyring; the daemon unlocks its collection from it."""
        self._loop.run(unlock_collection(self.address, LOGIN_COLLECTION, KEYRING_PASSWORD))


# ---------------------------------------------------------------------- the stack


class Stack:
    """See the module docstring. Built by the `stack` fixture; tests use its attributes."""

    def __init__(self, root: Path, request: Any) -> None:
        self.root = root
        self._request = request
        self._exit = contextlib.ExitStack()
        self.session: PrivateSession = self._exit.enter_context(start_private_session())
        self.cloudkit: FakeCloudKit = self._exit.enter_context(FakeCloudKit())
        self.services: AppleServices = self._exit.enter_context(AppleServices(self.cloudkit))
        self.apple = Phone(self.cloudkit)
        self._loop = Loop()
        self._exit.callback(self._loop.close)
        self.keyring = Keyring(self._loop, self.session.address)
        self._exit.callback(self.keyring.close)
        self.daemon = DaemonApi(self._loop, self.session.address)
        self._exit.callback(self.daemon.close)
        self.clock_file = root / "days-later"
        self.config = root / "daemon.json"
        self.config.write_text(
            json.dumps(
                {
                    "apple_url": self.services.url,
                    "scheduler": FAST_SCHEDULE,
                    "clock_file": str(self.clock_file),
                }
            ),
            encoding="utf-8",
        )
        self.process: subprocess.Popen[bytes] | None = None
        self.daemon_starts = 0
        self._app: Any = None
        self._browsers: dict[str, Any] = {}
        # What the iPhone held before the daemon started (filled by the `stack` fixture).
        self.seeded: dict[str, Credential] = {}

    # --- environment ---------------------------------------------------------------------

    @property
    def address(self) -> str:
        return self.session.address

    def env(self) -> dict[str, str]:
        return {
            **self.session.env,
            "PYTHONPATH": str(REPO),
            "PASSWORDS_APP_ANISETTE_URL": f"{self.services.url}/anisette",
            # No NetworkManager here: the daemon must not find the host's system bus.
            "DBUS_SYSTEM_BUS_ADDRESS": f"unix:path={self.session.root}/no-system-bus",
        }

    def _run_child(self, script: str, *args: str) -> None:
        result = subprocess.run(  # noqa: S603 - our interpreter, our script
            [sys.executable, str(HERE / script), *args],
            env=self.env(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")

    def sign_in(self) -> None:
        """Leave the account signed in and joined, as the sign-in wizard would."""
        payload = self.root / "session.json"
        payload.write_text(
            json.dumps(
                {
                    "device": {
                        "device_id": DEVICE.device_id,
                        "serial": DEVICE.serial,
                        "local_user_uuid": DEVICE.local_user_uuid,
                    },
                    "session": make_session(self.cloudkit),
                }
            ),
            encoding="utf-8",
        )
        self._run_child("seed_session.py", str(payload))
        payload.unlink()

    def days_later(self, days: float) -> None:
        """Move the daemon's wall clock `days` days ahead of real time."""
        self.clock_file.write_text(str(days), encoding="utf-8")

    # --- the daemon ----------------------------------------------------------------------

    @property
    def daemon_log(self) -> Path:
        return self.root / f"passwords-appd-{self.daemon_starts}.log"

    def start_daemon(self, *, wait_synced: bool = True) -> None:
        assert self.process is None, "the daemon is already running"
        self.daemon_starts += 1
        with self.daemon_log.open("wb") as log:
            self.process = subprocess.Popen(  # noqa: S603 - our interpreter, our script
                [sys.executable, str(HERE / "daemon_shim.py"), str(self.config)],
                env=self.env(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        process = self.process
        wait_until(
            lambda: process.poll() is not None or self.daemon.has_owner(),
            timeout=60,
            what="passwords-appd on the bus",
        )
        assert process.poll() is None, self.log_tail()
        if wait_synced:
            self.wait_cycle()

    def wait_cycle(self, *, states: tuple[str, ...] = ("idle",)) -> dict[str, Any]:
        """Wait for a finished cycle ending in one of `states`; returns the status."""
        return wait_until(
            lambda: (
                s if (s := self.daemon.status())["state"] in states and s["last_sync"] > 0 else None
            ),
            what=f"a sync cycle ending {states} (daemon log: {self.daemon_log})",
        )

    def stop_daemon(self, *, kill: bool = False) -> None:
        """SIGTERM (systemd stop / logout) or SIGKILL (power loss)."""
        process = self.process
        assert process is not None
        process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
        process.wait(30)
        self.process = None
        wait_until(lambda: not self.daemon.has_owner(), what="the daemon's bus name released")

    def log_tail(self, lines: int = 60) -> str:
        if not self.daemon_log.exists():
            return ""
        text = self.daemon_log.read_text(encoding="utf-8", errors="replace")
        return "\n".join(text.splitlines()[-lines:])

    # --- other surfaces (started on first use) ---------------------------------------------

    @property
    def app(self) -> Any:
        if self._app is None:
            from tests.e2e.desktop import AppWindow  # noqa: PLC0415 - GTK only when used

            desktop = self._request.getfixturevalue("desktop")
            self._app = AppWindow(desktop, self.address)
        return self._app

    def _browser(self, name: str) -> Any:
        if name not in self._browsers:
            from tests.browser.e2e_support import ChromiumSession, FirefoxSession  # noqa: PLC0415

            site = self._request.getfixturevalue("site")
            home = self.root / f"{name}-home"
            home.mkdir(exist_ok=True)
            cls = FirefoxSession if name == "firefox" else ChromiumSession
            self._browsers[name] = cls(home, self.address, site)
        return self._browsers[name]

    @property
    def firefox(self) -> Any:
        return self._browser("firefox")

    @property
    def chromium(self) -> Any:
        return self._browser("chromium")

    # --- teardown --------------------------------------------------------------------------

    def close(self) -> None:
        errors: list[BaseException] = []
        for browser in self._browsers.values():
            try:
                browser.close()
            except Exception as exc:  # noqa: BLE001 - finish the teardown, report after
                errors.append(exc)
        if self._app is not None:
            self._app.close()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        try:
            self.keep_logs()
        except OSError as exc:
            errors.append(exc)
        self._exit.close()
        if errors:
            raise errors[0]

    def keep_logs(self) -> None:
        """Copy every daemon run's log and each browser's native host log to `LOGS/<test>/`:
        when a scenario fails in CI, its cause has to be readable from the uploaded artifact."""
        target = LOGS / self._request.node.name
        shutil.rmtree(target, ignore_errors=True)  # an earlier local run of the same test
        target.mkdir(parents=True, exist_ok=True)
        for log in sorted(self.root.glob("passwords-appd-*.log")):
            shutil.copy2(log, target / log.name)
        # From every browser home, including one whose session failed to start; there is no
        # log when the extension never asked its host.
        for host_log in sorted(self.root.glob(f"*-home/{NATIVE_HOST_LOG}")):
            browser = host_log.parent.name.removesuffix("-home")
            shutil.copy2(host_log, target / f"native-host-{browser}.log")

    # --- cross-surface views ----------------------------------------------------------------

    def keyring_matches(self, cred: Credential) -> KeyringItem | None:
        """The keyring item mirroring `cred` (same id, password, url and username), if any."""
        item = self.keyring.by_id(cred.id)
        if item is None:
            return None
        same = (
            item.secret == cred.password
            and item.attributes.get("url") == cred.url
            and item.attributes.get("username") == cred.username
        )
        return item if same else None

    def keyring_login(self, url: str, username: str) -> KeyringItem | None:
        found = [
            i
            for i in self.keyring.items()
            if (i.attributes.get("url"), i.attributes.get("username")) == (url, username)
        ]
        assert len(found) <= 1, f"{len(found)} keyring items for {username} at {url}"
        return found[0] if found else None

    def trash_entry(self, item_id: str, reason: str | None = None) -> dict[str, Any] | None:
        """The daemon's Recently Deleted entry for `item_id` (and `reason`), if any."""
        for entry in self.daemon.trash():
            if entry["item"]["id"] == item_id and reason in {None, entry["reason"]}:
                return entry
        return None

    def assert_no_duplicates(self) -> None:
        """No login appears twice on any side (the classic failure of a two-way sync)."""
        sides: dict[str, list[tuple[str | None, str | None]]] = {
            "iCloud": [(c.url, c.username) for c in self.apple.logins().values()],
            "keyring": [
                (i.attributes.get("url"), i.attributes.get("username"))
                for i in self.keyring.items()
            ],
            "daemon": [(i["url"], i["username"]) for i in self.daemon.items()],
        }
        for side, rows in sides.items():
            assert len(rows) == len(set(rows)), f"duplicates in {side}: {sorted(rows)}"


@contextlib.contextmanager
def running_stack(root: Path, request: Any) -> Iterator[Stack]:
    stack = Stack(root, request)
    try:
        yield stack
    finally:
        stack.close()
