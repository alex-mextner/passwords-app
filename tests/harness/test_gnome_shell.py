# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Tests for the headless GNOME Shell harness.

The pure helpers are tested directly; the ``gui``-marked tests start real private sessions
(skipped when gnome-shell is not installed) and prove the three promises GUI tests rely on:
a client window becomes visible pixels, a recording is a playable WebM, and teardown leaves
nothing running.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING

import gi
import pytest
from tests.harness.gnome_shell import (
    KEEP_ROOT_VAR,
    MARKER_VAR,
    SYSTEM_PATH,
    GnomeShellError,
    GnomeShellSession,
    MonitorSize,
    WindowInfo,
    count_matching_pixels,
    exclusive_session_lock,
    extension_metadata_json,
    find_service_file,
    isolated_environment,
    parse_windows,
    png_size,
    processes_with_marker,
    screencast_template,
    session_bus_config,
    session_mode_json,
    shell_major_version,
    terminate_pids,
    wait_until,
)

gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf, Gio, GLib  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterator

HAVE_DBUS = Path("/usr/bin/dbus-daemon").exists()
HAVE_SHELL = shutil.which("gnome-shell") is not None and HAVE_DBUS
needs_shell = pytest.mark.skipif(not HAVE_SHELL, reason="gnome-shell/dbus-daemon not installed")
# The fake-shell tests stand in for gnome-shell, so the unit CI job (dbus, no shell) runs them.
needs_dbus = pytest.mark.skipif(not HAVE_DBUS, reason="dbus-daemon not installed")

PROBE_TITLE = "pa-harness-probe"
PROBE_RGB = (200, 20, 140)
PROBE_SIZE = (360, 240)
# A GTK4 window whose whole content is one known colour; with --animate it repaints every
# frame (alternating two shades) so a screencast has continuous damage to encode.
PROBE_APP = textwrap.dedent(
    """
    import sys
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gio, Gtk

    RGB = tuple(int(v) for v in sys.argv[2].split(","))
    W, H = (int(v) for v in sys.argv[3].split("x"))
    animate = "--animate" in sys.argv
    tick = [0]

    def draw(_area, cr, _w, _h):
        shade = 0 if not animate else (tick[0] % 2) * 8
        cr.set_source_rgb(RGB[0] / 255, (RGB[1] + shade) / 255, RGB[2] / 255)
        cr.paint()

    def on_tick(area, _clock):
        tick[0] += 1
        area.queue_draw()
        return True

    def activate(app):
        win = Gtk.ApplicationWindow(application=app, title=sys.argv[1])
        win.set_decorated(False)
        area = Gtk.DrawingArea(content_width=W, content_height=H)
        area.set_draw_func(draw)
        if animate:
            area.add_tick_callback(on_tick)
        win.set_child(area)
        win.present()

    # NON_UNIQUE: several probes share one session and must not merge into one instance.
    app = Gtk.Application(
        application_id="io.github.alex_mextner.HarnessProbe",
        flags=Gio.ApplicationFlags.NON_UNIQUE,
    )
    app.connect("activate", activate)
    app.run([])
    """
)


def write_png(path: Path, pixels: list[list[tuple[int, int, int]]], *, alpha: bool = False) -> Path:
    height, width = len(pixels), len(pixels[0])
    channels = 4 if alpha else 3
    data = bytearray()
    for row in pixels:
        for rgb in row:
            data.extend(rgb)
            if alpha:
                data.append(255)
    pixbuf = GdkPixbuf.Pixbuf.new_from_bytes(
        GLib.Bytes.new(bytes(data)),
        GdkPixbuf.Colorspace.RGB,
        alpha,
        8,
        width,
        height,
        width * channels,
    )
    pixbuf.savev(str(path), "png", [], [])
    return path


def spawn_marked(token: str, *, ignore_term: bool = False) -> subprocess.Popen[bytes]:
    code = "import signal, time\n"
    if ignore_term:
        code += "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    code += "print('ready', flush=True)\ntime.sleep(60)\n"
    env = {**os.environ, MARKER_VAR: token}
    proc = subprocess.Popen(  # noqa: S603  (fixed interpreter and code)
        [sys.executable, "-c", code], env=env, stdout=subprocess.PIPE
    )
    assert proc.stdout is not None
    assert proc.stdout.readline() == b"ready\n"  # signal handler installed before we signal
    return proc


def reap(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()


# ---------------------------------------------------------------------- MonitorSize


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1280x800", (1280, 800)),
        ("1920x1080", (1920, 1080)),
        (" 800x600\n", (800, 600)),
        ("320x200", (320, 200)),
        ("7680x4320", (7680, 4320)),
    ],
)
def test_monitor_size_parses_accepted_geometry(text: str, expected: tuple[int, int]) -> None:
    size = MonitorSize.parse(text)
    assert (size.width, size.height) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "1280",
        "1280x",
        "x800",
        "1280X800",
        "0x800",
        "1280x0",
        "-1280x800",
        "1280x800x2",
        "1280 x 800",
        "01280x800",
        "319x200",
        "320x199",
        "7681x4320",
        "7680x4321",
        "1280x800@60",
    ],
)
def test_monitor_size_rejects_malformed_or_out_of_range(text: str) -> None:
    with pytest.raises(ValueError, match="virtual monitor size"):
        MonitorSize.parse(text)


def test_monitor_size_renders_back_to_the_cli_form() -> None:
    assert str(MonitorSize.parse("1024x768")) == "1024x768"


# ---------------------------------------------------------------------- shell version


@pytest.mark.parametrize(
    ("output", "major"),
    [
        ("GNOME Shell 50.1\n", "50"),
        ("GNOME Shell 50\n", "50"),
        ("GNOME Shell 49.alpha", "49"),
        ("GNOME Shell 51.beta.1\n", "51"),
        ("Gjs-Message: noise\nGNOME Shell 52.0\n", "52"),
    ],
)
def test_shell_major_version_extracts_major(output: str, major: str) -> None:
    assert shell_major_version(output) == major


@pytest.mark.parametrize("output", ["", "gnome-shell 50.1", "Mutter 50.1", "GNOME Shell"])
def test_shell_major_version_rejects_unknown_output(output: str) -> None:
    with pytest.raises(GnomeShellError, match="unrecognized gnome-shell version"):
        shell_major_version(output)


def test_screencast_template_doubles_literal_percent_signs() -> None:
    target = Path("/srv/run%done/clip%t.webm")
    assert screencast_template(target) == "/srv/run%%done/clip%%t"


# ---------------------------------------------------------------------- environment isolation

HOST_ENV = {
    "DISPLAY": ":0",
    "WAYLAND_DISPLAY": "wayland-0",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
    "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/run/dbus/system_bus_socket",
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "XDG_SESSION_ID": "4",
    "SSH_AUTH_SOCK": "/run/user/1000/ssh",
    "LD_PRELOAD": "/opt/evil/libevil.so",
    "GTK_THEME": "Adwaita:dark",
    "GSETTINGS_BACKEND": "dconf",
    "PIPEWIRE_REMOTE": "pipewire-0",
    "AT_SPI_BUS_ADDRESS": "unix:path=/run/user/1000/at-spi/bus",
    "HOME": "/home/owner",
    "PATH": "/home/owner/.local/bin:/usr/bin",
    "PYTHONPATH": "/home/owner/lib",
    "LANG": "ru_RU.UTF-8",
    "LC_TIME": "ru_RU.UTF-8",
    "TZ": "Europe/Berlin",
    "TERM": "xterm-256color",
}


@pytest.mark.parametrize("key", sorted(set(HOST_ENV) - {"TZ", "TERM", "PATH"}))
def test_isolated_environment_drops_host_session_variables(key: str) -> None:
    assert key not in isolated_environment(HOST_ENV, {})


@pytest.mark.parametrize("key", ["TZ", "TERM"])
def test_isolated_environment_keeps_harmless_host_variables(key: str) -> None:
    assert isolated_environment(HOST_ENV, {})[key] == HOST_ENV[key]


def test_isolated_environment_uses_system_path_not_the_hosts() -> None:
    assert isolated_environment(HOST_ENV, {})["PATH"] == SYSTEM_PATH


def test_isolated_environment_overrides_win() -> None:
    env = isolated_environment(HOST_ENV, {"TZ": "UTC", "DISPLAY": ":99", "PATH": "/opt/bin"})
    assert (env["TZ"], env["DISPLAY"], env["PATH"]) == ("UTC", ":99", "/opt/bin")


# ---------------------------------------------------------------------- bus configuration


@pytest.mark.parametrize("system", [False, True])
def test_bus_config_activates_only_from_our_service_dir(tmp_path: Path, system: bool) -> None:
    services = tmp_path / "svc"
    tree = ET.fromstring(  # noqa: S314  (we generated this XML ourselves)
        session_bus_config(services, tmp_path / "run", system=system).split("\n", 2)[2]
    )
    assert [e.text for e in tree.iter("servicedir")] == [str(services)]
    assert tree.find("standard_session_servicedirs") is None
    assert tree.find("standard_system_servicedirs") is None
    assert tree.findtext("type") == ("system" if system else "session")


def test_bus_config_listens_inside_the_private_runtime_dir(tmp_path: Path) -> None:
    text = session_bus_config(tmp_path / "svc", tmp_path / "run")
    assert f"<listen>unix:dir={tmp_path / 'run'}</listen>" in text


def test_bus_config_escapes_paths_into_valid_xml(tmp_path: Path) -> None:
    odd = tmp_path / "a&b<c>"
    tree = ET.fromstring(  # noqa: S314  (we generated this XML ourselves)
        session_bus_config(odd, odd).split("\n", 2)[2]
    )
    assert tree.findtext("servicedir") == str(odd)


def test_bus_config_listen_address_escapes_dbus_delimiters(tmp_path: Path) -> None:
    odd = tmp_path / "build,proof;100%"
    tree = ET.fromstring(  # noqa: S314  (we generated this XML ourselves)
        session_bus_config(odd, odd).split("\n", 2)[2]
    )
    listen = tree.findtext("listen") or ""
    assert Gio.dbus_is_supported_address(listen)
    assert listen == f"unix:dir={Gio.dbus_address_escape_value(str(odd))}"


def test_find_service_file_prefers_earlier_directories(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    for directory in (first, second):
        directory.mkdir()
        (directory / "org.example.Svc.service").write_text("[D-BUS Service]\n")
    assert (
        find_service_file("org.example.Svc", [first, second]) == first / "org.example.Svc.service"
    )
    assert find_service_file("org.example.Svc", [tmp_path / "missing", second]) == (
        second / "org.example.Svc.service"
    )


def test_find_service_file_returns_none_when_absent(tmp_path: Path) -> None:
    assert find_service_file("org.example.Nope", [tmp_path]) is None


# ---------------------------------------------------------------------- mode + extension


def test_session_mode_enables_only_the_harness_extension_and_no_welcome() -> None:
    mode = json.loads(session_mode_json("x@y"))
    assert mode == {"parentMode": "user", "enabledExtensions": ["x@y"], "showWelcomeDialog": False}


@pytest.mark.parametrize("major", ["49", "50", "51"])
def test_extension_metadata_targets_exactly_the_running_shell(major: str) -> None:
    meta = json.loads(extension_metadata_json("x@y", major))
    assert meta["uuid"] == "x@y"
    assert meta["shell-version"] == [major]


# ---------------------------------------------------------------------- Introspect parsing


def test_parse_windows_maps_introspect_properties() -> None:
    reply: dict[int, dict[str, object]] = {
        7: {
            "title": "Passwords",
            "app-id": "io.github.alex_mextner.Passwords.desktop",
            "wm-class": "io.github.alex_mextner.Passwords",
            "width": 800,
            "height": 600,
            "has-focus": True,
        }
    }
    assert parse_windows(reply) == [
        WindowInfo(
            7,
            "Passwords",
            "io.github.alex_mextner.Passwords.desktop",
            "io.github.alex_mextner.Passwords",
            800,
            600,
            has_focus=True,
        )
    ]


def test_parse_windows_tolerates_missing_and_mistyped_properties() -> None:
    (window,) = parse_windows({3: {"width": True, "height": "600", "has-focus": 1}})
    assert window == WindowInfo(3, "", "", "", 0, 0, has_focus=False)


def test_parse_windows_orders_by_window_id() -> None:
    windows = parse_windows({9: {"title": "b"}, 2: {"title": "a"}, 5: {"title": "c"}})
    assert [w.window_id for w in windows] == [2, 5, 9]


def test_parse_windows_of_empty_reply_is_empty() -> None:
    assert parse_windows({}) == []


# ---------------------------------------------------------------------- pixel counting

RED, GREEN, BLUE = (255, 0, 0), (0, 255, 0), (0, 0, 255)


@pytest.mark.parametrize("alpha", [False, True])
def test_count_matching_pixels_counts_exact_colour(tmp_path: Path, alpha: bool) -> None:
    png = write_png(tmp_path / "x.png", [[RED, GREEN, RED], [BLUE, RED, GREEN]], alpha=alpha)
    assert count_matching_pixels(png, RED) == 3
    assert count_matching_pixels(png, BLUE) == 1
    assert count_matching_pixels(png, (1, 2, 3)) == 0


@pytest.mark.parametrize(
    ("pixel", "tolerance", "matches"),
    [
        ((102, 50, 50), 2, True),  # exactly at the tolerance edge
        ((103, 50, 50), 2, False),  # one past it
        ((98, 48, 52), 2, True),  # every channel off, each within tolerance
        ((100, 50, 53), 2, False),  # one channel out is enough to reject
        ((100, 50, 51), 0, False),  # zero tolerance is exact
    ],
)
def test_count_matching_pixels_tolerance_is_per_channel_inclusive(
    tmp_path: Path, pixel: tuple[int, int, int], tolerance: int, matches: bool
) -> None:
    png = write_png(tmp_path / "x.png", [[pixel]])
    assert count_matching_pixels(png, (100, 50, 50), tolerance=tolerance) == int(matches)


# ---------------------------------------------------------------------- process sweeping


@pytest.mark.timeout(30)
def test_processes_with_marker_finds_only_exact_token() -> None:
    # Random per run: the scan sees every process of this user, including concurrent runs.
    token = uuid.uuid4().hex
    mine = spawn_marked(token)
    longer = spawn_marked(token + "2222")  # shares our token as a prefix
    other = spawn_marked(uuid.uuid4().hex)
    try:
        assert processes_with_marker(token) == [mine.pid]
    finally:
        for proc in (mine, longer, other):
            reap(proc)


def test_processes_with_marker_skips_unreadable_and_non_numeric_entries(tmp_path: Path) -> None:
    fake_proc = tmp_path / "proc"
    (fake_proc / "self").mkdir(parents=True)
    (fake_proc / "123").mkdir()  # no environ file: process vanished mid-scan
    environ = f"A=1\0{MARKER_VAR}=tok\0".encode()
    (fake_proc / "456").mkdir()
    (fake_proc / "456" / "environ").write_bytes(environ)
    (fake_proc / "self" / "environ").write_bytes(environ)
    assert processes_with_marker("tok", fake_proc) == [456]


@pytest.mark.timeout(30)
def test_terminate_pids_stops_a_cooperative_process() -> None:
    proc = spawn_marked("cccc3333")
    try:
        terminate_pids([proc.pid], grace=5.0)
        assert proc.wait(timeout=5) == -signal.SIGTERM
    finally:
        reap(proc)


@pytest.mark.timeout(30)
def test_terminate_pids_escalates_to_sigkill_after_grace() -> None:
    proc = spawn_marked("dddd4444", ignore_term=True)
    try:
        start = time.monotonic()
        terminate_pids([proc.pid], grace=0.5)
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert time.monotonic() - start >= 0.5
    finally:
        reap(proc)


@pytest.mark.timeout(30)
def test_terminate_pids_ignores_already_gone_pids() -> None:
    proc = spawn_marked("eeee5555")
    reap(proc)
    terminate_pids([proc.pid], grace=0.1)  # must not raise


# ---------------------------------------------------------------------- waiting + locking


@pytest.mark.timeout(30)
def test_wait_until_returns_first_non_none_including_falsy_values() -> None:
    answers = iter([None, None, 0])
    assert wait_until(lambda: next(answers), timeout=5, interval=0.01, what="x") == 0


def test_wait_until_accepts_false_as_a_result() -> None:
    assert wait_until(lambda: False, timeout=1, what="x") is False


@pytest.mark.timeout(30)
def test_wait_until_times_out_naming_what_it_waited_for() -> None:
    start = time.monotonic()
    with pytest.raises(GnomeShellError, match="timed out after 0s waiting for the moon"):
        wait_until(lambda: None, timeout=0.2, interval=0.05, what="the moon")
    assert time.monotonic() - start >= 0.2


@pytest.mark.timeout(30)
def test_exclusive_session_lock_serializes_holders(tmp_path: Path) -> None:
    lock = tmp_path / "lock"
    events: list[str] = []
    first_holds = threading.Event()

    def second() -> None:
        first_holds.wait()
        with exclusive_session_lock(lock):
            events.append("second")

    worker = threading.Thread(target=second)
    worker.start()
    with exclusive_session_lock(lock):
        first_holds.set()
        time.sleep(0.3)
        events.append("first")
    worker.join(timeout=5)
    assert events == ["first", "second"]


# ---------------------------------------------------------------------- session guards


def test_invalid_size_fails_before_anything_starts() -> None:
    with pytest.raises(ValueError, match="virtual monitor size"):
        GnomeShellSession("huge")


def test_unstarted_session_has_no_environment() -> None:
    with pytest.raises(GnomeShellError, match="not started"):
        GnomeShellSession().env()


def test_stop_recording_without_recording_is_an_error() -> None:
    with pytest.raises(GnomeShellError, match="no recording"):
        GnomeShellSession().stop_recording()


def test_recordings_must_be_webm(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="WebM"):
        GnomeShellSession().start_recording(tmp_path / "x.mp4")


def test_close_of_unstarted_session_is_a_no_op() -> None:
    session = GnomeShellSession()
    session.close()
    session.close()


def test_closed_session_cannot_be_started_again() -> None:
    # close() is final: a later start() would leak, since the next close() is a no-op.
    session = GnomeShellSession()
    session.close()
    with pytest.raises(GnomeShellError, match="closed"):
        session.start()


def test_close_tears_down_even_when_finalizing_the_recording_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = GnomeShellSession()
    stopped: list[bool] = []

    def lost_recording() -> Path:
        msg = "recording directory removed"
        raise FileNotFoundError(msg)

    monkeypatch.setattr(session, "_recording", object())
    monkeypatch.setattr(session, "stop_recording", lost_recording)
    monkeypatch.setattr(session, "_stop_processes", lambda: stopped.append(True))
    session.close()  # the lost file must not mask a test failure propagating through __exit__
    assert stopped == [True]


def test_close_releases_the_lock_when_stopping_processes_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = GnomeShellSession()
    lock = contextlib.ExitStack()
    released: list[bool] = []
    lock.callback(lambda: released.append(True))

    def unkillable() -> None:
        msg = "pid recycled to another user"
        raise PermissionError(msg)

    monkeypatch.setattr(session, "_lock", lock)
    monkeypatch.setattr(session, "_stop_processes", unkillable)
    with pytest.raises(PermissionError):
        session.close()
    assert released == [True]


def test_missing_gnome_shell_binary_is_reported(tmp_path: Path) -> None:
    session = GnomeShellSession(gnome_shell="no-such-gnome-shell", lock_path=tmp_path / "l")
    with pytest.raises(GnomeShellError, match="no-such-gnome-shell not found"):
        session.start()


def fake_shell(tmp_path: Path) -> Path:
    """A gnome-shell stand-in that reports a version and then refuses to start."""
    fake = tmp_path / "gnome-shell"
    fake.write_text(
        '#!/bin/sh\n[ "$1" = --version ] && { echo "GNOME Shell 50.1"; exit 0; }\n'
        'echo "fake shell refusing to start"\nexit 3\n'
    )
    fake.chmod(0o755)
    return fake


@pytest.mark.timeout(60)
@needs_dbus
def test_shell_that_dies_at_startup_is_reported_and_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEEP_ROOT_VAR, raising=False)
    session = GnomeShellSession(
        gnome_shell=str(fake_shell(tmp_path)), lock_path=tmp_path / "l", startup_timeout=20
    )
    with pytest.raises(GnomeShellError, match=r"exited with 3(.|\n)*refusing to start"):
        session.start()
    assert session.leftover_processes() == []
    assert not session.root.exists()


@pytest.mark.timeout(60)
@needs_dbus
def test_keep_root_variable_preserves_logs_for_debugging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEEP_ROOT_VAR, "1")
    session = GnomeShellSession(
        gnome_shell=str(fake_shell(tmp_path)), lock_path=tmp_path / "l", startup_timeout=20
    )
    with pytest.raises(GnomeShellError):
        session.start()
    try:
        assert "refusing to start" in session.shell_log.read_text()
        assert session.leftover_processes() == []  # processes still go, only files stay
    finally:
        shutil.rmtree(session.root)


# ---------------------------------------------------------------------- live sessions


@pytest.fixture(scope="module")
def shell() -> Iterator[GnomeShellSession]:
    if not HAVE_SHELL:
        pytest.skip("gnome-shell/dbus-daemon not installed")
    with GnomeShellSession("1024x768") as session:
        yield session


def launch_probe(session: GnomeShellSession, title: str, *, animate: bool = False) -> None:
    argv = [
        sys.executable,
        "-c",
        PROBE_APP,
        title,
        ",".join(map(str, PROBE_RGB)),
        f"{PROBE_SIZE[0]}x{PROBE_SIZE[1]}",
    ]
    if animate:
        argv.append("--animate")
    session.spawn(argv)
    session.wait_for_window(title, timeout=30)


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_gtk_window_appears_in_screenshot(shell: GnomeShellSession, tmp_path: Path) -> None:
    title = f"{PROBE_TITLE}-shot"
    launch_probe(shell, title)
    png = shell.screenshot(tmp_path / "shot.png")
    area = PROBE_SIZE[0] * PROBE_SIZE[1]
    # Colour-managed output may shift a channel by a step or two; 90% leaves room for
    # rounded window corners.
    assert count_matching_pixels(png, PROBE_RGB, tolerance=2) >= 0.9 * area


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_screenshot_covers_exactly_the_virtual_monitor(
    shell: GnomeShellSession, tmp_path: Path
) -> None:
    assert png_size(shell.screenshot(tmp_path / "full.png")) == (1024, 768)


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_wait_for_window_reports_the_mapped_window(shell: GnomeShellSession) -> None:
    title = f"{PROBE_TITLE}-info"
    launch_probe(shell, title)
    (window,) = [w for w in shell.windows() if w.title == title]
    assert window.width >= PROBE_SIZE[0]
    assert window.height >= PROBE_SIZE[1]


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_wait_for_window_times_out_for_absent_title(shell: GnomeShellSession) -> None:
    with pytest.raises(GnomeShellError, match="window 'never-opened'"):
        shell.wait_for_window("never-opened", timeout=1)


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_unsafe_mode_is_on_inside_the_private_session(shell: GnomeShellSession) -> None:
    assert shell.eval_js("global.context.unsafe_mode") == "true"


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_wait_frames_returns_on_a_settled_stage(shell: GnomeShellSession) -> None:
    shell.wait_frames(1)  # let any pending paint finish so nothing else requests frames
    started = time.monotonic()
    shell.wait_frames(3)
    assert time.monotonic() - started < 5


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_shell_runs_on_private_buses_and_runtime_dir(shell: GnomeShellSession) -> None:
    (shell_pid,) = [
        pid
        for pid in shell.leftover_processes()
        if Path(f"/proc/{pid}/comm").read_text().strip() == "gnome-shell"
    ]
    raw = Path(f"/proc/{shell_pid}/environ").read_bytes().split(b"\0")
    env = dict(item.decode().split("=", 1) for item in raw if b"=" in item)
    assert env["DBUS_SESSION_BUS_ADDRESS"] == shell.bus_address
    assert str(shell.runtime_dir) in env["DBUS_SESSION_BUS_ADDRESS"]
    assert str(shell.runtime_dir) in env["DBUS_SYSTEM_BUS_ADDRESS"]
    assert env["XDG_RUNTIME_DIR"] == str(shell.runtime_dir)
    assert "DISPLAY" not in env
    assert (shell.runtime_dir / "wayland-0").exists()


@pytest.mark.timeout(240)
@pytest.mark.gui
def test_recording_is_a_valid_webm_with_many_frames(
    shell: GnomeShellSession, tmp_path: Path
) -> None:
    if shutil.which("ffprobe") is None:
        pytest.skip("ffprobe not installed")
    launch_probe(shell, f"{PROBE_TITLE}-rec", animate=True)
    target = tmp_path / "proof" / "clip.webm"
    shell.start_recording(target)
    with pytest.raises(GnomeShellError, match="already running"):
        shell.start_recording(tmp_path / "second.webm")
    time.sleep(3)
    assert shell.stop_recording() == target.resolve()
    probe = subprocess.run(  # noqa: S603  (resolved ffprobe, fixed arguments)
        [
            shutil.which("ffprobe") or "ffprobe",
            "-v",
            "error",
            "-count_frames",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name,width,height,nb_read_frames:format=format_name",
            "-of",
            "json",
            str(target),
        ],
        capture_output=True,
        check=True,
        text=True,
        timeout=60,
    )
    info = json.loads(probe.stdout)
    stream = info["streams"][0]
    assert "webm" in info["format"]["format_name"]
    assert stream["codec_name"] == "vp8"
    assert (stream["width"], stream["height"]) == (1024, 768)
    assert int(stream["nb_read_frames"]) > 30
    assert not list(target.parent.glob("*.undefined"))


@pytest.mark.timeout(240)
@pytest.mark.gui
@needs_shell
def test_teardown_leaves_no_processes_and_no_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEEP_ROOT_VAR, raising=False)
    with GnomeShellSession("800x600", lock_path=tmp_path / "l") as session:
        launch_probe(session, f"{PROBE_TITLE}-teardown")
        session.start_recording(tmp_path / "t.webm")  # pipewire + wireplumber too
        started = session.leftover_processes()
        root = session.root
        names = {Path(f"/proc/{pid}/comm").read_text().strip() for pid in started}
    assert {"gnome-shell", "dbus-daemon", "pipewire", "wireplumber"} <= names
    assert session.leftover_processes() == []
    assert not root.exists()
    assert (tmp_path / "t.webm").stat().st_size > 0  # close() finished the open recording
