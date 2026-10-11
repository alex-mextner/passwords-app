# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A private, headless GNOME Shell session for GUI tests and recorded proof.

Everything runs under a throwaway root: its own HOME/XDG directories, a private session bus
and a private "system" bus (so the shell never registers with the owner's logind or GDM), and
a headless ``gnome-shell --virtual-monitor``. GNOME 50 dropped the ``--unsafe-mode`` flag, so a
session-mode extension that exists only inside this root turns unsafe mode on; that unlocks
``org.gnome.Shell.Eval``, ``Screenshot`` and ``Introspect`` for the test process without
touching any real session.

Every child inherits a per-session marker variable, which is how teardown also finds the
D-Bus-activated services that re-parent away from us.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import secrets
import select
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, Self, override

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from types import TracebackType

    from gi.repository import GdkPixbuf

MARKER_VAR = "PASSWORDS_APP_GNOME_SHELL_SESSION"
MODE_NAME = "passwords-app-harness"
EXTENSION_UUID = "unsafe-mode@harness.passwords-app"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYSTEM_DATA_DIRS = "/usr/local/share:/usr/share"
# Only these activatable services exist on the private bus. The default service directories
# would let the shell start evolution, goa, gvfs and portals, which outlive the session and
# mount FUSE file systems.
ACTIVATABLE_SERVICES = ("org.gnome.Shell.Screencast",)
SYSTEM_SERVICE_DIRS = (Path("/usr/share/dbus-1/services"), Path("/usr/local/share/dbus-1/services"))
DBUS_DAEMON = "/usr/bin/dbus-daemon"
# Locale comes from the session's `lang` so screenshots do not depend on the developer's.
_KEPT_HOST_VARS = ("TZ", "TERM")
_SIZE_RE = re.compile(r"^([1-9][0-9]{1,4})x([1-9][0-9]{1,4})$")
_VERSION_RE = re.compile(r"\bGNOME Shell ([0-9]+)(?:\.[0-9A-Za-z.]+)?\b")
_CALL_TIMEOUT_MS = 30_000
KEEP_ROOT_VAR = "PASSWORDS_APP_KEEP_SHELL_ROOT"
type _DBusTarget = tuple[str, str, str]  # bus name, object path, interface
_BUS: _DBusTarget = ("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus")
_SHELL: _DBusTarget = ("org.gnome.Shell", "/org/gnome/Shell", "org.gnome.Shell")
_SCREENSHOT: _DBusTarget = (
    "org.gnome.Shell.Screenshot",
    "/org/gnome/Shell/Screenshot",
    "org.gnome.Shell.Screenshot",
)
_SCREENCAST: _DBusTarget = (
    "org.gnome.Shell.Screencast",
    "/org/gnome/Shell/Screencast",
    "org.gnome.Shell.Screencast",
)
_INTROSPECT: _DBusTarget = (
    "org.gnome.Shell.Introspect",
    "/org/gnome/Shell/Introspect",
    "org.gnome.Shell.Introspect",
)
_LOCK_PATH = Path(tempfile.gettempdir()) / f"passwords-app-gnome-shell-{os.getuid()}.lock"

# The extension and session mode are generated per session; they never exist outside its root.
_EXTENSION_JS = """\
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

export default class HarnessExtension extends Extension {
    enable() {
        global.context.unsafe_mode = true;
        const leaveOverview = () => Main.overview.hide();
        if (Main.layoutManager._startingUp)
            this._startupId = Main.layoutManager.connect('startup-complete', leaveOverview);
        else
            leaveOverview();
    }

    disable() {
        if (this._startupId)
            Main.layoutManager.disconnect(this._startupId);
        this._startupId = 0;
        global.context.unsafe_mode = false;
    }
}
"""

# Deterministic frames: no animations, banners, idle blanking or first-run dialogs.
_SETTINGS_KEYFILE = """\
[org/gnome/desktop/interface]
enable-animations=false

[org/gnome/desktop/notifications]
show-banners=false

[org/gnome/desktop/session]
idle-delay=uint32 0

[org/gnome/desktop/screensaver]
lock-enabled=false
idle-activation-enabled=false

[org/gnome/shell]
welcome-dialog-last-shown-version='999'
"""

# Recording only needs a video graph; audio, Bluetooth and camera monitors would open the
# owner's real devices from inside the private session.
_WIREPLUMBER_CONF = """\
wireplumber.profiles = {
  main = {
    hardware.audio = disabled
    hardware.bluetooth = disabled
    hardware.video-capture = disabled
    support.portal-permissionstore = disabled
    support.logind = disabled
  }
}
"""

# VP8/WebM is forced because the shell otherwise prefers H.264/MP4 whenever openh264 exists.
WEBM_PIPELINE = (
    "videoconvert chroma-mode=none dither=none matrix-mode=output-only n-threads=%T ! "
    "queue ! vp8enc cpu-used=16 max-quantizer=17 deadline=1 keyframe-mode=disabled "
    "threads=%T static-threshold=1000 buffer-size=20000 ! queue ! webmmux"
)


class GnomeShellError(RuntimeError):
    """The private session could not be started or did not do what was asked."""


@dataclass(frozen=True, slots=True)
class MonitorSize:
    width: int
    height: int

    @classmethod
    def parse(cls, text: str) -> MonitorSize:
        """Parse ``WxH`` as accepted by ``gnome-shell --virtual-monitor``."""
        match = _SIZE_RE.fullmatch(text.strip())
        if match is None:
            msg = f"virtual monitor size must look like 1280x800, got {text!r}"
            raise ValueError(msg)
        width, height = int(match[1]), int(match[2])
        if width < 320 or height < 200 or width > 7680 or height > 4320:
            msg = f"virtual monitor size {width}x{height} is outside 320x200..7680x4320"
            raise ValueError(msg)
        return cls(width, height)

    @override
    def __str__(self) -> str:
        return f"{self.width}x{self.height}"


@dataclass(frozen=True, slots=True)
class WindowInfo:
    window_id: int
    title: str
    app_id: str
    wm_class: str
    width: int
    height: int
    has_focus: bool


def shell_major_version(version_output: str) -> str:
    """Return the major version from ``gnome-shell --version`` output (``GNOME Shell 50.1``)."""
    match = _VERSION_RE.search(version_output)
    if match is None:
        msg = f"unrecognized gnome-shell version output: {version_output.strip()!r}"
        raise GnomeShellError(msg)
    return match[1]


def screencast_template(target: Path) -> str:
    """The Screencast filename argument for ``target``: the service expands ``%d``/``%t``
    anywhere in it and turns ``%%`` into ``%``, so literal percent signs are doubled."""
    return str(target.with_suffix("")).replace("%", "%%")


def isolated_environment(host: Mapping[str, str], overrides: Mapping[str, str]) -> dict[str, str]:
    """Build a child environment that cannot reach the owner's display, bus or session.

    It is an allowlist: only the time zone and terminal type survive from ``host``, so no
    display, bus, agent socket, locale or library override leaks in; ``overrides`` supply
    everything else.
    """
    env = {key: value for key, value in host.items() if key in _KEPT_HOST_VARS}
    env["PATH"] = SYSTEM_PATH
    env.update(overrides)
    return env


def session_bus_config(service_dir: Path, socket_dir: Path, *, system: bool = False) -> str:
    """Render a dbus-daemon configuration whose only activatable services are ours."""
    kind = "system" if system else "session"
    return f"""<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>{kind}</type>
  <keep_umask/>
  <listen>unix:dir={_xml_escape(Gio.dbus_address_escape_value(str(socket_dir)))}</listen>
  <auth>EXTERNAL</auth>
  <servicedir>{_xml_escape(str(service_dir))}</servicedir>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def find_service_file(name: str, search: Sequence[Path] = SYSTEM_SERVICE_DIRS) -> Path | None:
    """Locate the system ``.service`` file that activates bus name ``name``."""
    for directory in search:
        candidate = directory / f"{name}.service"
        if candidate.is_file():
            return candidate
    return None


def session_mode_json(extension_uuid: str) -> str:
    return json.dumps(
        {
            "parentMode": "user",
            "enabledExtensions": [extension_uuid],
            "showWelcomeDialog": False,
        },
        indent=2,
    )


def extension_metadata_json(extension_uuid: str, shell_major: str) -> str:
    return json.dumps(
        {
            "uuid": extension_uuid,
            "name": "passwords-app test harness",
            "description": "Enables unsafe mode inside a private test session.",
            "shell-version": [shell_major],
        },
        indent=2,
    )


def parse_windows(reply: Mapping[int, Mapping[str, object]]) -> list[WindowInfo]:
    """Convert ``org.gnome.Shell.Introspect.GetWindows`` output into ``WindowInfo``."""
    windows = [
        WindowInfo(
            window_id=window_id,
            title=_str(props.get("title")),
            app_id=_str(props.get("app-id")),
            wm_class=_str(props.get("wm-class")),
            width=_int(props.get("width")),
            height=_int(props.get("height")),
            has_focus=props.get("has-focus") is True,
        )
        for window_id, props in reply.items()
    ]
    return sorted(windows, key=lambda w: w.window_id)


def _as_window_map(reply: object) -> dict[int, Mapping[str, object]]:
    if not isinstance(reply, dict):
        msg = f"unexpected GetWindows reply: {type(reply).__name__}"
        raise GnomeShellError(msg)
    windows: dict[int, Mapping[str, object]] = {}
    for key, props in reply.items():  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, int) and isinstance(props, dict):
            windows[key] = {str(k): v for k, v in props.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    return windows


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def load_png(png: Path) -> GdkPixbuf.Pixbuf:
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf  # noqa: PLC0415  (only screenshot users pay for it)

    pixbuf = GdkPixbuf.Pixbuf.new_from_file(str(png))
    if pixbuf is None:
        msg = f"{png} is not a readable image"
        raise GnomeShellError(msg)
    return pixbuf


def png_size(png: Path) -> tuple[int, int]:
    pixbuf = load_png(png)
    return pixbuf.get_width(), pixbuf.get_height()


def count_matching_pixels(png: Path, rgb: tuple[int, int, int], *, tolerance: int = 0) -> int:
    """Count pixels of ``png`` within ``tolerance`` of ``rgb`` on every channel."""
    pixbuf = load_png(png)
    data = pixbuf.get_pixels()
    stride = pixbuf.get_rowstride()
    channels = pixbuf.get_n_channels()
    width = pixbuf.get_width()
    red, green, blue = rgb
    count = 0
    for y in range(pixbuf.get_height()):
        row = y * stride
        for x in range(width):
            i = row + x * channels
            if (
                abs(data[i] - red) <= tolerance
                and abs(data[i + 1] - green) <= tolerance
                and abs(data[i + 2] - blue) <= tolerance
            ):
                count += 1
    return count


def processes_with_marker(token: str, proc: Path = Path("/proc")) -> list[int]:
    """PIDs of this user's processes whose environment carries the session marker."""
    needle = f"{MARKER_VAR}={token}".encode()
    uid = os.getuid()
    found: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            environ = (entry / "environ").read_bytes()
        except OSError:  # exited meanwhile, or not ours to read
            continue
        if needle in environ.split(b"\0"):
            found.append(int(entry.name))
    return sorted(found)


def terminate_pids(pids: Sequence[int], *, grace: float = 5.0) -> None:
    """SIGTERM ``pids``, then SIGKILL whatever is still alive after ``grace`` seconds."""
    for pid in pids:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    alive = list(pids)
    while alive and time.monotonic() < deadline:
        alive = [pid for pid in alive if _alive(pid)]
        if alive:
            time.sleep(0.05)
    for pid in alive:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    for pid in alive:
        _wait_gone(pid, 2.0)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    try:
        # A zombie has already exited; reaping it is its parent's job (Popen.wait for our
        # own children), and doing it here would steal the exit status from Popen.
        return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def _wait_gone(pid: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)


def wait_until[T](
    probe: Callable[[], T | None], *, timeout: float, interval: float = 0.1, what: str
) -> T:
    """Poll ``probe`` until it returns non-None; raise ``GnomeShellError`` on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            msg = f"timed out after {timeout:.0f}s waiting for {what}"
            raise GnomeShellError(msg)
        time.sleep(interval)


@contextlib.contextmanager
def exclusive_session_lock(path: Path = _LOCK_PATH) -> Generator[None]:
    """Serialize sessions machine-wide for this user; each one costs a full compositor."""
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class GnomeShellSession:
    """Headless gnome-shell on private buses under a temporary root.

    Use as a context manager; ``close()`` stops every process the session started,
    including D-Bus-activated ones, and removes the root (set
    ``PASSWORDS_APP_KEEP_SHELL_ROOT=1`` to keep it, with its logs, for debugging).
    """

    def __init__(
        self,
        size: str | MonitorSize = "1280x800",
        *,
        startup_timeout: float = 90.0,
        gnome_shell: str = "gnome-shell",
        lock_path: Path = _LOCK_PATH,
        lang: str = "C.UTF-8",
    ) -> None:
        self.size = size if isinstance(size, MonitorSize) else MonitorSize.parse(size)
        self.lang = lang
        self.token = secrets.token_hex(8)
        self._startup_timeout = startup_timeout
        self._gnome_shell = gnome_shell
        self._lock_path = lock_path
        self._lock: contextlib.ExitStack | None = None
        self._root: Path | None = None
        self._procs: dict[str, subprocess.Popen[bytes]] = {}
        self._logs: list[IO[bytes]] = []
        self._session_address = ""
        self._system_address = ""
        self._conn: Gio.DBusConnection | None = None
        self._recording: Path | None = None
        self._recording_actual: Path | None = None
        self._clients: list[subprocess.Popen[bytes]] = []
        self._closed = False

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def root(self) -> Path:
        if self._root is None:
            msg = "session not started"
            raise GnomeShellError(msg)
        return self._root

    @property
    def bus_address(self) -> str:
        return self._session_address

    @property
    def runtime_dir(self) -> Path:
        return self.root / "runtime"

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def shell_log(self) -> Path:
        return self.root / "logs" / "gnome-shell.log"

    def start(self) -> None:
        if self._root is not None or self._closed:
            msg = "session already started or closed; use a new GnomeShellSession"
            raise GnomeShellError(msg)
        binary = shutil.which(self._gnome_shell)
        if binary is None:
            msg = f"{self._gnome_shell} not found"
            raise GnomeShellError(msg)
        stack = contextlib.ExitStack()
        stack.enter_context(exclusive_session_lock(self._lock_path))
        self._lock = stack
        try:
            self._root = Path(tempfile.mkdtemp(prefix="pa-gnome-shell-"))
            self._prepare_root(shell_major_version(_run_text([binary, "--version"])))
            self._session_address = self._start_bus("session-bus", system=False)
            self._system_address = self._start_bus("system-bus", system=True)
            self._start_shell(binary)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """Stop everything this session started. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._recording is not None:
                # OSError: the recording's directory may be gone; that must not mask the
                # exception a failing test is already propagating through __exit__.
                with contextlib.suppress(GnomeShellError, GLib.Error, OSError):
                    self.stop_recording()
        finally:
            # Teardown must run even if finalizing the recording raised something unexpected,
            # and the machine-wide lock must be released even if stopping processes raised.
            try:
                if self._conn is not None:
                    with contextlib.suppress(GLib.Error):
                        self._conn.close_sync(None)
                    self._conn = None
                self._stop_processes()
            finally:
                for handle in self._logs:
                    handle.close()
                if self._root is not None and os.environ.get(KEEP_ROOT_VAR) != "1":
                    shutil.rmtree(self._root, ignore_errors=True)
                if self._lock is not None:
                    self._lock.close()
                    self._lock = None

    def _stop_processes(self) -> None:
        # Shell first so it does not respawn helpers while the buses go away.
        for name in ("gnome-shell", "wireplumber", "pipewire", "system-bus", "session-bus"):
            proc = self._procs.get(name)
            if proc is not None and proc.poll() is None:
                terminate_pids([proc.pid], grace=10.0)
        terminate_pids(processes_with_marker(self.token))
        for proc in [*self._procs.values(), *self._clients]:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)
            if proc.stdout is not None:
                proc.stdout.close()

    def leftover_processes(self) -> list[int]:
        """Processes started by this session that are still running (empty after close)."""
        return processes_with_marker(self.token)

    # ------------------------------------------------------------------ environment
    def env(self, **extra: str) -> dict[str, str]:
        """Environment for launching a client inside the session (GTK apps, browsers)."""
        root = self.root
        overrides = {
            MARKER_VAR: self.token,
            "HOME": str(root / "home"),
            "XDG_RUNTIME_DIR": str(root / "runtime"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_STATE_HOME": str(root / "state"),
            "XDG_DATA_DIRS": f"{root / 'share'}:{SYSTEM_DATA_DIRS}",
            "XDG_CONFIG_DIRS": "/etc/xdg",
            "XDG_SESSION_TYPE": "wayland",
            "XDG_CURRENT_DESKTOP": "GNOME",
            "XDG_SESSION_DESKTOP": "gnome",
            "WAYLAND_DISPLAY": "wayland-0",
            "GDK_BACKEND": "wayland",
            "DBUS_SESSION_BUS_ADDRESS": self._session_address,
            "DBUS_SYSTEM_BUS_ADDRESS": self._system_address,
            "GSETTINGS_BACKEND": "keyfile",
            "NO_AT_BRIDGE": "1",
            "GTK_A11Y": "none",
            "LANG": self.lang,
        }
        overrides.update(extra)
        return isolated_environment(os.environ, overrides)

    def spawn(self, argv: Sequence[str], **extra_env: str) -> subprocess.Popen[bytes]:
        """Start a client inside the session; ``close()`` reaps it with everything else."""
        log = self._open_log(Path(argv[0]).name)
        proc = subprocess.Popen(  # noqa: S603  (argv comes from the test itself)
            list(argv),
            env=self.env(**extra_env),
            cwd=self.home,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._clients.append(proc)
        return proc

    # ------------------------------------------------------------------ shell API
    def eval_js(self, code: str) -> str:
        """Run JavaScript in the shell (unsafe mode, private session only); return its JSON."""
        reply = self._call(_SHELL, "Eval", GLib.Variant("(s)", (code,)), "(bs)")
        ok, result = reply
        if not ok:
            msg = f"Eval failed: {result or 'unsafe mode is off'}"
            raise GnomeShellError(msg)
        return str(result)

    def screenshot(self, path: Path) -> Path:
        """Save a PNG of the whole virtual monitor to ``path``."""
        target = path.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        ok, used = self._call(
            _SCREENSHOT, "Screenshot", GLib.Variant("(bbs)", (False, False, str(target))), "(bs)"
        )
        if not ok:
            msg = f"screenshot to {target} failed"
            raise GnomeShellError(msg)
        return Path(str(used))

    def windows(self) -> list[WindowInfo]:
        (reply,) = self._call(_INTROSPECT, "GetWindows", None, "(a{ta{sv}})")
        return parse_windows(_as_window_map(reply))

    def wait_for_window(self, title: str, *, timeout: float = 30.0) -> WindowInfo:
        """Wait until a window titled exactly ``title`` is mapped and painted."""

        def probe() -> WindowInfo | None:
            # Introspect lists a window as soon as its app tracks it, before the client has
            # attached its first buffer; mutter shows the actor only once that buffer exists.
            return next(
                (
                    w
                    for w in self.windows()
                    if w.title == title and self._window_actor_shown(w.window_id)
                ),
                None,
            )

        window = wait_until(probe, timeout=timeout, interval=0.2, what=f"window {title!r}")
        self.wait_frames(2)
        return window

    def _window_actor_shown(self, window_id: int) -> bool:
        # `?.`: an actor being unmanaged mid-poll can have a null meta_window.
        shown = self.eval_js(
            "global.get_window_actors().some(a => a.meta_window?.get_id() == "
            + str(int(window_id))
            + " && a.visible && a.meta_window.showing_on_its_workspace())"
        )
        return shown == "true"

    def wait_frames(self, count: int = 1) -> None:
        """Block until the stage has painted ``count`` more frames."""
        frames = str(max(1, count))
        # Shell's Eval awaits a returned Promise. Each paint queues the next redraw: an idle
        # stage would otherwise paint once and never reach `count`.
        self.eval_js(
            "new Promise(resolve => { let left = " + frames + ";"
            " const id = global.stage.connect('after-paint', () => {"
            " if (--left <= 0) { global.stage.disconnect(id); resolve(true); }"
            " else { global.stage.queue_redraw(); } });"
            " global.stage.queue_redraw(); })"
        )

    def start_recording(
        self, path: Path, *, framerate: int = 30, draw_cursor: bool = False
    ) -> None:
        """Record the whole monitor as VP8/WebM into ``path`` until ``stop_recording()``."""
        if self._recording is not None:
            msg = "a recording is already running"
            raise GnomeShellError(msg)
        if path.suffix != ".webm":
            msg = f"recordings are WebM; {path.name} must end in .webm"
            raise ValueError(msg)
        self._ensure_pipewire()
        target = path.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        options = {
            "pipeline": GLib.Variant("s", WEBM_PIPELINE),
            "framerate": GLib.Variant("i", framerate),
            "draw-cursor": GLib.Variant("b", draw_cursor),
        }
        ok, used = self._call(
            _SCREENCAST,
            "Screencast",
            GLib.Variant("(sa{sv})", (screencast_template(target), options)),
            "(bs)",
        )
        if not ok:
            msg = "the shell refused to start a screencast"
            raise GnomeShellError(msg)
        self._recording = target
        # A custom pipeline has no known extension, so the service names the file
        # "<stem>.undefined"; remember what it chose.
        self._recording_actual = Path(str(used))

    def stop_recording(self) -> Path:
        """Finish the recording and return the WebM path."""
        if self._recording is None:
            msg = "no recording is running"
            raise GnomeShellError(msg)
        target = self._recording
        actual = self._recording_actual or target
        self._recording = None
        (ok,) = self._call(_SCREENCAST, "StopScreencast", None, "(b)")
        if not ok:
            msg = "the shell failed to stop the screencast"
            raise GnomeShellError(msg)
        if actual != target:
            actual.replace(target)
        return target

    # ------------------------------------------------------------------ internals
    def _prepare_root(self, shell_major: str) -> None:
        root = self.root
        for sub in (
            "home",
            "config",
            "data",
            "cache",
            "state",
            "logs",
            "services",
            "system-services",
            "share/gnome-shell/modes",
        ):
            (root / sub).mkdir(parents=True, exist_ok=True)
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        (root / "share/gnome-shell/modes" / f"{MODE_NAME}.json").write_text(
            session_mode_json(EXTENSION_UUID)
        )
        ext_dir = root / "share/gnome-shell/extensions" / EXTENSION_UUID
        ext_dir.mkdir(parents=True)
        (ext_dir / "metadata.json").write_text(extension_metadata_json(EXTENSION_UUID, shell_major))
        (ext_dir / "extension.js").write_text(_EXTENSION_JS)
        keyfile = root / "config/glib-2.0/settings/keyfile"
        keyfile.parent.mkdir(parents=True)
        keyfile.write_text(_SETTINGS_KEYFILE)
        wp_conf = root / "config/wireplumber/wireplumber.conf.d/90-harness.conf"
        wp_conf.parent.mkdir(parents=True)
        wp_conf.write_text(_WIREPLUMBER_CONF)
        for name in ACTIVATABLE_SERVICES:
            source = find_service_file(name)
            if source is not None:
                shutil.copyfile(source, root / "services" / source.name)

    def _open_log(self, name: str) -> IO[bytes]:
        handle = (self.root / "logs" / f"{name}.log").open("ab")
        self._logs.append(handle)
        return handle

    def _base_env(self) -> dict[str, str]:
        return self.env()

    def _start_bus(self, name: str, *, system: bool) -> str:
        root = self.root
        services = root / ("system-services" if system else "services")
        config = root / f"{name}.conf"
        config.write_text(session_bus_config(services, root / "runtime", system=system))
        proc = subprocess.Popen(  # noqa: S603  (fixed binary, generated config)
            [DBUS_DAEMON, f"--config-file={config}", "--nofork", "--print-address=1"],
            env=self._base_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=self._open_log(name),
            start_new_session=True,
        )
        self._procs[name] = proc
        address = _read_line(proc, timeout=10.0)
        if not address:
            msg = f"{name} did not report its address"
            raise GnomeShellError(msg)
        return address

    def _start_shell(self, binary: str) -> None:
        env = self._base_env()
        proc = subprocess.Popen(  # noqa: S603  (resolved gnome-shell binary)
            [
                binary,
                "--headless",
                "--wayland",
                "--no-x11",
                f"--virtual-monitor={self.size}",
                f"--mode={MODE_NAME}",
            ],
            env=env,
            cwd=self.home,
            stdin=subprocess.DEVNULL,
            stdout=self._open_log("gnome-shell"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._procs["gnome-shell"] = proc
        self._conn = Gio.DBusConnection.new_for_address_sync(
            self._session_address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
            | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
            None,
            None,
        )

        def ready() -> bool | None:
            if proc.poll() is not None:
                msg = f"gnome-shell exited with {proc.returncode}:\n{self._log_tail()}"
                raise GnomeShellError(msg)
            try:
                state = self.eval_js("!Main.layoutManager._startingUp && !Main.overview.visible")
            except (GLib.Error, GnomeShellError):
                return None
            return True if state == "true" else None

        try:
            wait_until(
                ready, timeout=self._startup_timeout, interval=0.25, what="gnome-shell startup"
            )
        except GnomeShellError as exc:
            msg = f"{exc}\n{self._log_tail()}"
            raise GnomeShellError(msg) from exc
        self._update_activation_environment(env)

    def _update_activation_environment(self, env: Mapping[str, str]) -> None:
        self._call(_BUS, "UpdateActivationEnvironment", GLib.Variant("(a{ss})", (dict(env),)), None)

    def _ensure_pipewire(self) -> None:
        if "pipewire" in self._procs:
            return
        self._spawn_service("pipewire")
        socket = self.runtime_dir / "pipewire-0"
        wait_until(
            lambda: True if socket.exists() else None, timeout=10.0, what="the PipeWire socket"
        )
        self._spawn_service("wireplumber")
        self._wait_for_session_manager()

    def _spawn_service(self, name: str) -> None:
        binary = shutil.which(name, path=SYSTEM_PATH)
        if binary is None:
            msg = f"{name} is required for recording"
            raise GnomeShellError(msg)
        self._procs[name] = subprocess.Popen(  # noqa: S603  (resolved system binary)
            [binary],
            env=self._base_env(),
            cwd=self.home,
            stdin=subprocess.DEVNULL,
            stdout=self._open_log(name),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def _wait_for_session_manager(self) -> None:
        # WirePlumber links the shell's stream to the recorder; without it the recorder
        # waits forever for its first frame.
        log = self.root / "logs" / "wireplumber.log"

        def settled() -> bool | None:
            proc = self._procs["wireplumber"]
            if proc.poll() is not None:
                msg = f"wireplumber exited with {proc.returncode}: {log.read_text()[-2000:]}"
                raise GnomeShellError(msg)
            return True if _pw_has_session_manager(self.env()) else None

        wait_until(settled, timeout=15.0, interval=0.2, what="WirePlumber")

    def _call(
        self,
        target: _DBusTarget,
        method: str,
        params: GLib.Variant | None,
        reply_type: str | None,
    ) -> tuple[object, ...]:
        if self._conn is None:
            msg = "session not started"
            raise GnomeShellError(msg)
        bus_name, path, interface = target
        reply = self._conn.call_sync(
            bus_name,
            path,
            interface,
            method,
            params,
            GLib.VariantType.new(reply_type) if reply_type else None,
            Gio.DBusCallFlags.NONE,
            _CALL_TIMEOUT_MS,
            None,
        )
        unpacked: tuple[object, ...] = reply.unpack()
        return unpacked

    def _log_tail(self, lines: int = 40) -> str:
        try:
            text = self.shell_log.read_text(errors="replace")
        except OSError:
            return "(no gnome-shell log)"
        return "\n".join(text.splitlines()[-lines:])


def _pw_has_session_manager(env: Mapping[str, str]) -> bool:
    pw_dump = shutil.which("pw-dump", path=SYSTEM_PATH)
    if pw_dump is None:
        return True  # cannot tell; let the recorder's own timeout report problems
    result = subprocess.run(  # noqa: S603  (resolved system binary)
        [pw_dump, "--no-colors"], env=dict(env), capture_output=True, check=False, timeout=10
    )
    return b'"WirePlumber"' in result.stdout


def _run_text(argv: Sequence[str]) -> str:
    result = subprocess.run(  # noqa: S603  (resolved binary, fixed arguments)
        list(argv), capture_output=True, check=False, timeout=30, text=True
    )
    return result.stdout + result.stderr


def _read_line(proc: subprocess.Popen[bytes], *, timeout: float) -> str:
    stream = proc.stdout
    if stream is None:
        return ""
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        return ""
    return stream.readline().decode().strip()
