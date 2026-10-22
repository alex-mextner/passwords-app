# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""App lock: the idle timer and the polkit unlock, against a fake polkit on a private bus.

`ui/lock.py` imports only Gio/GLib, never Gtk. The system bus is never used: tests hand the
authorizer a private-bus connection or point DBUS_SYSTEM_BUS_ADDRESS at nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import gi.events  # noqa: F401 - imported lazily by Gio's async overrides
    from gi.repository import Gio, GLib

    from passwords_app.app.constants import APP_ID, POLKIT_UNLOCK_ACTION
    from passwords_app.app.ui import lock
    from passwords_app.app.ui.lock import (
        FingerprintProbe,
        IdleTimer,
        PolkitAuthorizer,
        idle_lock_hint,
        unlock_hint,
    )

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

pytestmark = [
    pytest.mark.timeout(60),
    # PyGObject's MainContext.iteration override touches asyncio APIs Python 3.14 deprecates.
    pytest.mark.filterwarnings(r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"),
]

POLKIT_NAME = "org.freedesktop.PolicyKit1"
POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority"
_BUS_CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={socket}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""
_POLKIT_XML = """
<node>
  <interface name="org.freedesktop.PolicyKit1.Authority">
    <method name="EnumerateActions">
      <arg type="s" direction="in"/>
      <arg type="a(ssssssuuua{ss})" direction="out"/>
    </method>
    <method name="CheckAuthorization">
      <arg type="(sa{sv})" direction="in"/>
      <arg type="s" direction="in"/>
      <arg type="a{ss}" direction="in"/>
      <arg type="u" direction="in"/>
      <arg type="s" direction="in"/>
      <arg type="(bba{ss})" direction="out"/>
    </method>
  </interface>
</node>
"""

FPRINT_NAME = "net.reactivated.Fprint"
FPRINT_MANAGER_PATH = "/net/reactivated/Fprint/Manager"
FPRINT_DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
_FPRINT_MANAGER_XML = """
<node>
  <interface name="net.reactivated.Fprint.Manager">
    <method name="GetDefaultDevice">
      <arg type="o" direction="out"/>
    </method>
  </interface>
</node>
"""
_FPRINT_DEVICE_XML = """
<node>
  <interface name="net.reactivated.Fprint.Device">
    <method name="ListEnrolledFingers">
      <arg type="s" direction="in"/>
      <arg type="as" direction="out"/>
    </method>
  </interface>
</node>
"""

# ---------------------------------------------------------------------- main-loop helpers


def wait_until[T](probe: Callable[[], T], *, timeout: float = 10.0, what: str = "callback") -> T:
    """Run the default main context until `probe()` is truthy."""
    context = GLib.MainContext.default()
    deadline = time.monotonic() + timeout
    while True:
        while context.iteration(False):  # noqa: FBT003
            pass
        result = probe()
        if result:
            return result
        if time.monotonic() > deadline:
            msg = f"timed out after {timeout}s waiting for {what}"
            raise AssertionError(msg)
        time.sleep(0.005)


def pump(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    context = GLib.MainContext.default()
    while time.monotonic() < deadline:
        while context.iteration(False):  # noqa: FBT003
            pass
        time.sleep(0.005)


# ---------------------------------------------------------------------- IdleTimer


@dataclass
class Idle:
    minutes: int = 5
    fired: int = 0
    asked: list[int] = field(default_factory=list)

    def get_minutes(self) -> int:
        self.asked.append(self.minutes)
        return self.minutes

    def on_idle(self) -> None:
        self.fired += 1


def _source(timer: IdleTimer) -> GLib.Source:
    source_id = timer._source
    assert source_id, "the timer has no pending timeout"
    source = GLib.MainContext.default().find_source_by_id(source_id)
    assert source is not None
    return source


def _seconds_left(source: GLib.Source) -> float:
    return (source.get_ready_time() - GLib.get_monotonic_time()) / 1_000_000


@pytest.fixture
def idle() -> Iterator[tuple[Idle, IdleTimer]]:
    state = Idle()
    timer = IdleTimer(state.get_minutes, state.on_idle)
    try:
        yield state, timer
    finally:
        timer.disarm()


def test_timer_starts_disarmed_and_poke_is_ignored(idle: tuple[Idle, IdleTimer]) -> None:
    state, timer = idle
    assert not timer.armed
    timer.poke()
    assert timer._source == 0
    assert state.asked == []


@pytest.mark.parametrize(("minutes", "seconds"), [(5, 300), (1, 60), (0, 60), (-3, 60)])
def test_arm_schedules_after_the_configured_minutes(
    idle: tuple[Idle, IdleTimer], minutes: int, seconds: int
) -> None:
    state, timer = idle
    state.minutes = minutes
    timer.arm()
    assert timer.armed
    # timeout_add_seconds may coalesce to a whole-second boundary.
    assert seconds - 1.5 <= _seconds_left(_source(timer)) <= seconds + 1.5
    assert state.fired == 0


def test_poke_restarts_the_countdown_with_current_minutes(idle: tuple[Idle, IdleTimer]) -> None:
    state, timer = idle
    timer.arm()
    first = _source(timer)
    state.minutes = 10
    timer.poke()
    second = _source(timer)
    assert first.is_destroyed()
    assert not second.is_destroyed()
    assert 600 - 1.5 <= _seconds_left(second) <= 600 + 1.5
    assert state.asked == [5, 10]


def test_disarm_cancels(idle: tuple[Idle, IdleTimer]) -> None:
    state, timer = idle
    timer.arm()
    source = _source(timer)
    timer.disarm()
    assert not timer.armed
    assert timer._source == 0
    assert source.is_destroyed()
    timer.poke()
    assert timer._source == 0
    timer.disarm()  # idempotent
    assert state.fired == 0


def test_fires_once_when_the_timeout_elapses(idle: tuple[Idle, IdleTimer]) -> None:
    state, timer = idle
    timer.arm()
    source = _source(timer)
    source.set_ready_time(0)  # make the pending timeout due now
    wait_until(lambda: state.fired, what="idle callback")
    pump(0.05)
    assert state.fired == 1
    assert timer._source == 0
    assert source.is_destroyed()
    assert timer.armed  # still armed: the next input restarts the countdown
    timer.poke()
    assert timer._source


# ---------------------------------------------------------------------- process start time


def _stat_line(comm: str, start_time: int) -> str:
    # Fields 3..21, then field 22 (starttime), then a few more.
    fields = ["S", *(str(n) for n in range(4, 22)), str(start_time), "1000", "2000"]
    return f"4242 ({comm}) {' '.join(fields)}\n"


@pytest.mark.parametrize(
    "comm", ["python3", "my app", "evil) 1 2 3 (x", "((", "a b c d e f g h i j k l m n o p q r s t"]
)
def test_process_start_time_survives_hostile_command_names(
    comm: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stat = tmp_path / "stat"
    stat.write_text(_stat_line(comm, 987_654_321), encoding="ascii")
    opened: list[str] = []

    def fake_path(text: str) -> Path:
        opened.append(text)
        return stat

    monkeypatch.setattr(lock, "Path", fake_path)
    assert lock._process_start_time(4242) == 987_654_321
    assert opened == ["/proc/4242/stat"]


def test_process_start_time_of_real_processes() -> None:
    own = lock._process_start_time(os.getpid())
    assert own > 0
    assert lock._process_start_time(os.getpid()) == own
    child = subprocess.Popen(["sleep", "5"])  # noqa: S607 - coreutils on PATH
    try:
        time.sleep(0.05)
        assert lock._process_start_time(child.pid) >= own
    finally:
        child.kill()
        child.wait()


# ---------------------------------------------------------------------- polkit


@pytest.fixture
def bus_address(tmp_path: Path) -> Iterator[str]:
    """A bare private dbus-daemon standing in for the system bus."""
    binary = shutil.which("dbus-daemon")
    if binary is None:
        pytest.skip("dbus-daemon is not installed")
    socket = tmp_path / "bus"
    config = tmp_path / "bus.conf"
    config.write_text(_BUS_CONFIG.format(socket=socket))
    proc = subprocess.Popen(  # noqa: S603 - fixed argv built from a trusted binary
        [binary, f"--config-file={config}", "--nofork", "--print-address"],
        stdout=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert proc.stdout is not None
    address = proc.stdout.readline().decode().strip()
    try:
        yield address
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        proc.stdout.close()


def _connect(address: str) -> Gio.DBusConnection:
    return Gio.DBusConnection.new_for_address_sync(
        address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )


@pytest.fixture
def bus(bus_address: str) -> Iterator[Gio.DBusConnection]:
    conn = _connect(bus_address)
    try:
        yield conn
    finally:
        conn.close_sync(None)


@dataclass
class FakePolkit:
    """Answers EnumerateActions/CheckAuthorization and records the authorization requests."""

    actions: list[str] = field(default_factory=lambda: ["org.example.other", POLKIT_UNLOCK_ACTION])
    authorized: bool = True
    fail_with: str = ""
    requests: list[tuple[object, ...]] = field(default_factory=list)
    # polkit's implicit authorization for the active session: with `auth_self_keep` the first
    # successful prompt is remembered and later checks pass silently; `auth_self` prompts again.
    implicit: str = "auth_self"
    prompts: int = 0
    _kept: bool = False

    def handle(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if self.fail_with:
            invocation.return_dbus_error(self.fail_with, "denied by test")
            return
        if method == "EnumerateActions":
            no_annotations: dict[str, str] = {}
            rows = [(a, "d", "m", "v", "u", "i", 0, 0, 0, no_annotations) for a in self.actions]
            invocation.return_value(GLib.Variant("(a(ssssssuuua{ss}))", (rows,)))
            return
        self.requests.append(cast("tuple[object, ...]", params.unpack()))
        if not self._kept:
            self.prompts += 1
            self._kept = self.authorized and self.implicit == "auth_self_keep"
        invocation.return_value(GLib.Variant("((bba{ss}))", ((self.authorized, False, {}),)))


@pytest.fixture
def polkit(bus_address: str) -> Iterator[FakePolkit]:
    conn = _connect(bus_address)
    fake = FakePolkit()
    info = Gio.DBusNodeInfo.new_for_xml(_POLKIT_XML).interfaces[0]
    registration = conn.register_object_with_closures2(POLKIT_PATH, info, fake.handle, None, None)
    conn.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        GLib.Variant("(su)", (POLKIT_NAME, 4)),
        GLib.VariantType.new("(u)"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )
    try:
        yield fake
    finally:
        conn.unregister_object(registration)
        conn.close_sync(None)


def answer(start: Callable[[Callable[[bool], None]], None]) -> bool:
    box: list[bool] = []
    start(box.append)
    wait_until(lambda: box, what="polkit answer")
    return box[0]


def test_unavailable_without_polkit_on_the_bus(bus: Gio.DBusConnection) -> None:
    authorizer = PolkitAuthorizer(bus)
    assert answer(authorizer.check_available) is False
    assert answer(authorizer) is False


def test_unavailable_without_any_system_bus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    nowhere = f"unix:path={tmp_path / 'no-system-bus'}"
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", nowhere)
    assert os.environ["DBUS_SYSTEM_BUS_ADDRESS"] == nowhere  # never the real system bus
    authorizer = PolkitAuthorizer()
    assert answer(authorizer.check_available) is False
    assert answer(authorizer) is False


def test_available_only_with_the_installed_policy(
    bus: Gio.DBusConnection, polkit: FakePolkit
) -> None:
    authorizer = PolkitAuthorizer(bus)
    assert answer(authorizer.check_available) is True
    polkit.actions = ["org.example.other"]
    assert answer(authorizer.check_available) is False
    polkit.actions = []
    assert answer(authorizer.check_available) is False


def test_authorization_request_describes_this_process(
    bus: Gio.DBusConnection, polkit: FakePolkit
) -> None:
    assert answer(PolkitAuthorizer(bus)) is True
    [(subject, action, details, flags, cancellation)] = polkit.requests
    kind, props = cast("tuple[str, dict[str, object]]", subject)
    assert kind == "unix-process"
    assert props == {"pid": os.getpid(), "start-time": lock._process_start_time(os.getpid())}
    assert action == POLKIT_UNLOCK_ACTION
    assert details == {}
    assert flags == 1  # AllowUserInteraction: polkit may show its dialog
    assert cancellation == ""


def test_denied_authorization(bus: Gio.DBusConnection, polkit: FakePolkit) -> None:
    polkit.authorized = False
    assert answer(PolkitAuthorizer(bus)) is False


def test_polkit_errors_mean_no(bus: Gio.DBusConnection, polkit: FakePolkit) -> None:
    polkit.fail_with = "org.freedesktop.PolicyKit1.Error.Failed"
    authorizer = PolkitAuthorizer(bus)
    assert answer(authorizer.check_available) is False
    assert answer(authorizer) is False


def _shipped_implicit_authorization() -> str:
    policy = Path(__file__).resolve().parents[3] / "data" / "polkit" / f"{APP_ID}.policy"
    root = ET.parse(policy).getroot()  # noqa: S314 - the repository's own file
    action = root.find(f"action[@id='{POLKIT_UNLOCK_ACTION}']")
    assert action is not None
    return action.findtext("defaults/allow_active", "")


def test_unlock_after_relock_asks_again(bus: Gio.DBusConnection, polkit: FakePolkit) -> None:
    """Each unlock after a re-lock prompts again: the shipped policy keeps no authorization."""
    polkit.implicit = _shipped_implicit_authorization()
    authorizer = PolkitAuthorizer(bus)
    assert answer(authorizer) is True  # first unlock
    assert answer(authorizer) is True  # unlock after the window locked again
    assert polkit.prompts == 2  # one prompt per unlock


def test_fake_authority_models_a_kept_authorization(
    bus: Gio.DBusConnection, polkit: FakePolkit
) -> None:
    """Guards the test above: under `auth_self_keep` the second unlock would not prompt."""
    polkit.implicit = "auth_self_keep"
    authorizer = PolkitAuthorizer(bus)
    assert answer(authorizer) is True
    assert answer(authorizer) is True
    assert polkit.prompts == 1


# ---------------------------------------------------------------------- fingerprint reader


@dataclass
class FakeFprint:
    """net.reactivated.Fprint: a default reader with enrolled fingers, or one of its errors."""

    default_device_error: str = ""
    list_error: str = ""
    fingers: list[str] = field(default_factory=lambda: ["right-index-finger"])
    users: list[str] = field(default_factory=list)

    def manager(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        _method: str,
        _params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if self.default_device_error:
            invocation.return_dbus_error(self.default_device_error, "No devices available")
            return
        invocation.return_value(GLib.Variant("(o)", (FPRINT_DEVICE_PATH,)))

    def device(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        _method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        self.users.append(params.unpack()[0])
        if self.list_error:
            invocation.return_dbus_error(self.list_error, "No fingerprints enrolled")
            return
        invocation.return_value(GLib.Variant("(as)", (self.fingers,)))


@pytest.fixture
def fprintd(bus_address: str) -> Iterator[FakeFprint]:
    conn = _connect(bus_address)
    fake = FakeFprint()
    manager = Gio.DBusNodeInfo.new_for_xml(_FPRINT_MANAGER_XML).interfaces[0]
    device = Gio.DBusNodeInfo.new_for_xml(_FPRINT_DEVICE_XML).interfaces[0]
    registrations = [
        conn.register_object_with_closures2(FPRINT_MANAGER_PATH, manager, fake.manager, None, None),
        conn.register_object_with_closures2(FPRINT_DEVICE_PATH, device, fake.device, None, None),
    ]
    conn.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        GLib.Variant("(su)", (FPRINT_NAME, 4)),
        GLib.VariantType.new("(u)"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )
    try:
        yield fake
    finally:
        for registration in registrations:
            conn.unregister_object(registration)
        conn.close_sync(None)


def test_no_fingerprint_without_fprintd_on_the_bus(bus: Gio.DBusConnection) -> None:
    assert answer(FingerprintProbe(bus)) is False


def test_no_fingerprint_without_any_system_bus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    nowhere = f"unix:path={tmp_path / 'no-system-bus'}"
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", nowhere)
    assert os.environ["DBUS_SYSTEM_BUS_ADDRESS"] == nowhere  # never the real system bus
    assert answer(FingerprintProbe()) is False


def test_no_fingerprint_when_fprintd_has_no_reader(
    bus: Gio.DBusConnection, fprintd: FakeFprint
) -> None:
    """The machine fprintd is installed on but `fprintd-list` says "No devices available"."""
    fprintd.default_device_error = "net.reactivated.Fprint.Error.NoSuchDevice"
    assert answer(FingerprintProbe(bus)) is False
    assert fprintd.users == []  # no reader, so nobody asked it about enrolled fingers


@pytest.mark.parametrize(
    ("error", "fingers"),
    [("net.reactivated.Fprint.Error.NoEnrolledPrints", ["ignored"]), ("", [])],
    ids=["NoEnrolledPrints", "empty list"],
)
def test_no_fingerprint_when_nothing_is_enrolled(
    bus: Gio.DBusConnection, fprintd: FakeFprint, error: str, fingers: list[str]
) -> None:
    fprintd.list_error = error
    fprintd.fingers = fingers
    assert answer(FingerprintProbe(bus)) is False


def test_fingerprint_with_a_reader_and_enrolled_fingers(
    bus: Gio.DBusConnection, fprintd: FakeFprint
) -> None:
    assert answer(FingerprintProbe(bus)) is True
    assert fprintd.users == [""]  # the empty name means the calling user


def test_texts_promise_a_fingerprint_only_when_one_can_be_given() -> None:
    assert unlock_hint(fingerprint=False) == "Unlock with your password."
    assert unlock_hint(fingerprint=True) == "Unlock with your password or fingerprint."
    assert idle_lock_hint(fingerprint=False) == "Ask for your password after a period without use."
    assert (
        idle_lock_hint(fingerprint=True)
        == "Ask for your password or fingerprint after a period without use."
    )
