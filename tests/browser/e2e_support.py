# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Real Firefox and Chromium with the built extension, a real native host and a FakeDaemon.

Pieces:
- `SiteServer`: serves `tests/browser/pages/` for every host name on one loopback port, in
  both http and https (the first byte of a connection decides), so "same port, other scheme"
  is testable. Browsers map the fictional host names to it (`network.dns.localDomains`,
  `--host-resolver-rules`) and accept its self-signed certificate.
- `install_native_host`: a wrapper script that starts the real host on the private bus, plus
  the browser's native messaging manifest pointing at it (rendered by `manifests`).
- `FirefoxSession` (Selenium + geckodriver, temporary add-on) and `ChromiumSession`
  (Playwright, `--load-extension`) behind the same small `Page` API the scenarios use.

The browsers get an environment of their own: a throwaway HOME, the private bus, no DISPLAY,
so nothing reaches the real desktop session, keyring or browser profiles.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, Self, cast, override

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from passwords_app.browser import manifests

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

REPO: Final = Path(__file__).resolve().parents[2]
EXTENSION: Final = REPO / "extension"
PAGES: Final = Path(__file__).resolve().parent / "pages"
PROOF: Final = REPO / "docs" / "proof" / "browser"

NORTHWIND: Final = "login.northwind.example"
FABRIKAM: Final = "accounts.fabrikam.example"
# A lookalike that ends in the real host's name, and one that only resembles it.
LOOKALIKE: Final = "login.northwind.example.evil.example"
SQUAT: Final = "northwind-login.example"
HOSTS: Final = (NORTHWIND, FABRIKAM, LOOKALIKE, SQUAT)

FIREFOX_ID: Final = "passwords-app@alex-mextner.github.io"
# Fixed internal UUID so moz-extension:// URLs are known before the add-on is installed.
FIREFOX_UUID: Final = "6f0b8d3e-1c2a-4b5e-9d7f-0a1b2c3d4e5f"
CHROME_ID: Final = "djaiceficanbdafmmlcmgbfjefiapjaf"
VIEWPORT: Final = (1280, 820)
TLS_HANDSHAKE: Final = 0x16


def wait_until[T](
    probe: Callable[[], T | None], timeout: float = 10.0, interval: float = 0.05, what: str = ""
) -> T:
    """Poll `probe` until it returns something truthy; fail the test after `timeout` s."""
    deadline = time.monotonic() + timeout
    while True:
        value = probe()
        if value:
            return value
        if time.monotonic() > deadline:
            msg = f"timed out after {timeout} s waiting for {what or probe}"
            raise AssertionError(msg)
        time.sleep(interval)


# ---------------------------------------------------------------------- web server


def _self_signed(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "passwords-app e2e")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "site.crt", directory / "site.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    server_version = "fixture"

    @override
    def log_message(self, format: str, *args: Any) -> None:
        """Keep test output quiet; form posts carry fictional passwords."""

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].lstrip("/") or "login.html"
        file = (PAGES / path).resolve()
        if file.parent != PAGES or not file.is_file():
            self.send_error(404)
            return
        body = file.read_bytes()
        kind = {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}[file.suffix]
        self.send_response(200)
        self.send_header("Content-Type", f"{kind}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        # Every form "succeeds" and lands on the welcome page, like a login redirect.
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(303)
        self.send_header("Location", "/welcome.html")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _DualServer(ThreadingHTTPServer):
    """http and https on one port: a TLS ClientHello starts with byte 0x16."""

    daemon_threads = True
    address_family = socket.AF_INET

    def __init__(self, tls: ssl.SSLContext) -> None:
        self.tls = tls
        super().__init__(("127.0.0.1", 0), _Handler)

    @override
    def get_request(self) -> tuple[socket.socket, Any]:
        conn, addr = self.socket.accept()
        conn.settimeout(10)
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except OSError:
            first = b""
        if first[:1] == bytes([TLS_HANDSHAKE]):
            try:
                conn = self.tls.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                conn.close()
                raise
        return conn, addr

    @override
    def handle_error(self, request: Any, client_address: Any) -> None:
        """Aborted handshakes and closed tabs are normal for browsers; stay quiet."""


class SiteServer:
    def __init__(self, workdir: Path) -> None:
        cert, key = _self_signed(workdir)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        self._server = _DualServer(tls)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)

    def url(self, host: str, path: str = "/login.html", scheme: str = "https") -> str:
        return f"{scheme}://{host}:{self.port}{path}"

    def origin(self, host: str, scheme: str = "https") -> str:
        return f"{scheme}://{host}:{self.port}"


# ---------------------------------------------------------------------- extension + host


def build_extension() -> tuple[Path, Path]:
    """Build dist/{firefox,chrome} unless they are newer than every source file."""
    dist = EXTENSION / "dist"
    outputs = [dist / "firefox" / "manifest.json", dist / "chrome" / "manifest.json"]
    sources = [p for d in ("src", "static") for p in (EXTENSION / d).rglob("*") if p.is_file()] + [
        EXTENSION / "package.json",
        EXTENSION / "scripts" / "build.ts",
    ]
    newest = max(p.stat().st_mtime for p in sources)
    if not all(o.exists() and o.stat().st_mtime >= newest for o in outputs):
        bun = shutil.which("bun") or str(Path.home() / ".bun" / "bin" / "bun")
        if not (EXTENSION / "node_modules").is_dir():
            # A fresh checkout (CI) has no dependencies yet; the bundle inlines tldts.
            subprocess.run(  # noqa: S603
                [bun, "install", "--frozen-lockfile"],
                cwd=EXTENSION,
                check=True,
                capture_output=True,
            )
        subprocess.run([bun, "scripts/build.ts"], cwd=EXTENSION, check=True, capture_output=True)  # noqa: S603
    return dist / "firefox", dist / "chrome"


def install_native_host(
    home: Path, bus_address: str, browser: manifests.Browser, manifest_dir: Path | None = None
) -> Path:
    """Write the host wrapper and the browser's manifest; returns the manifest path."""
    wrapper = home / "bin" / "passwords-app-native-host"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        "#!/bin/sh\n"
        f"export DBUS_SESSION_BUS_ADDRESS='{bus_address}'\n"
        f"export PYTHONPATH='{REPO / 'src'}'\n"
        f"exec '{sys.executable}' -m passwords_app.browser.native_host \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    target = manifest_dir or manifests.manifest_dir(browser, home)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{manifests.HOST_NAME}.json"
    path.write_text(manifests.dumps(manifests.render(browser, wrapper)), encoding="utf-8")
    return path


def browser_env(home: Path, bus_address: str) -> dict[str, str]:
    """Environment for a browser process: throwaway HOME, the private bus, no display."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_RUNTIME_DIR": str(home / "runtime"),
        "DBUS_SESSION_BUS_ADDRESS": bus_address,
        "LANG": "en_US.UTF-8",
        "TZ": "UTC",
        "MOZ_CRASHREPORTER_DISABLE": "1",
    }
    (home / "runtime").mkdir(mode=0o700, parents=True, exist_ok=True)
    return env


# ---------------------------------------------------------------------- page API


class Page(Protocol):
    name: str

    def goto(self, url: str) -> None: ...
    def click(self, css: str) -> None: ...
    def type(self, css: str, text: str) -> None: ...
    def press(self, key: str) -> None: ...
    def js(self, expression: str) -> Any: ...
    def click_at(self, x: float, y: float) -> None: ...
    def screenshot(self, path: Path) -> None: ...
    def element_screenshot(self, css: str, path: Path) -> None: ...
    def open_popup(self) -> None: ...
    def back_to_page(self) -> None: ...


def value(page: Page, css: str) -> str:
    return str(page.js(f"return document.querySelector({json.dumps(css)}).value"))


def overlay_rect(page: Page, name: str) -> dict[str, float] | None:
    """Bounding box of one of the extension's in-page overlays, or None when absent."""
    rect = page.js(
        "const h = document.querySelector('[data-passwords-app=\"" + name + "\"]');"
        "if (!h) return null; const r = h.getBoundingClientRect();"
        "return r.height > 0 ? {x: r.x, y: r.y, width: r.width, height: r.height} : null;"
    )
    return cast("dict[str, float] | None", rect)


def wait_overlay(page: Page, name: str, timeout: float = 15.0) -> dict[str, float]:
    return wait_until(lambda: overlay_rect(page, name), timeout, what=f"{name} on {page.name}")


def assert_no_overlay(page: Page, name: str, settle: float = 2.5) -> None:
    """The overlay must not show up within `settle` seconds (time for a host round-trip)."""
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        assert overlay_rect(page, name) is None, f"{name} appeared on {page.name}"
        time.sleep(0.1)


def _geckodriver_service_class() -> type[Any]:
    from selenium.webdriver.firefox.service import Service  # noqa: PLC0415

    class GeckodriverService(Service):
        """geckodriver answers selenium's GET /shutdown with 405 and selenium leaks the
        unclosed HTTPError (a ResourceWarning, an error under filterwarnings=error);
        stop() terminates the process anyway, so the remote shutdown is skipped."""

        @override
        def send_remote_shutdown_command(self) -> None:
            return

    return GeckodriverService


class FirefoxSession:
    """Selenium Firefox (non-snap build) with the extension installed as a temporary add-on."""

    def __init__(
        self, home: Path, bus_address: str, site: SiteServer, *, dark: bool = False
    ) -> None:
        from selenium import webdriver  # noqa: PLC0415 - heavy, only for browser tests

        self.name = "firefox-dark" if dark else "firefox"
        binary, driver = firefox_binaries()
        firefox_dist, _ = build_extension()
        install_native_host(home, bus_address, "firefox")
        options = webdriver.FirefoxOptions()
        options.binary_location = str(binary)
        options.add_argument("-headless")
        options.accept_insecure_certs = True
        prefs: Mapping[str, str | int | bool] = {
            "network.dns.localDomains": ",".join(HOSTS),
            "dom.security.https_first": False,
            "dom.security.https_first_schemeless": False,
            "dom.security.https_only_mode": False,
            "extensions.webextensions.uuids": json.dumps({FIREFOX_ID: FIREFOX_UUID}),
            "widget.use-xdg-desktop-portal.native-messaging": 0,
            "signon.rememberSignons": False,
            "signon.autofillForms": False,
            "browser.shell.checkDefaultBrowser": False,
            "datareporting.policy.dataSubmissionEnabled": False,
            "ui.systemUsesDarkTheme": 1 if dark else 0,
            "layout.css.prefers-color-scheme.content-override": 0 if dark else 1,
        }
        for key, pref in prefs.items():
            options.set_preference(key, pref)
        service = _geckodriver_service_class()(
            executable_path=str(driver),
            service_args=["--allow-system-access"],  # chrome context, used by open_popup
            env=browser_env(home, bus_address),
        )
        self.driver = webdriver.Firefox(options=options, service=service)
        self.driver.set_window_size(*VIEWPORT)
        self.driver.install_addon(str(firefox_dist), temporary=True)
        # install_addon can return before the background page has started and the content
        # scripts are registered; a page loaded in that gap gets no content script.
        # readyPromise is null once the add-on is ready.
        with self.driver.context(self.driver.CONTEXT_CHROME):
            self.driver.execute_async_script(
                "const done = arguments[arguments.length - 1];"
                "Promise.resolve(WebExtensionPolicy.getByID(arguments[0]).readyPromise)"
                ".then(() => done(true));",
                FIREFOX_ID,
            )
        self.site = site
        self._page_handle = self.driver.current_window_handle

    def close(self) -> None:
        self.driver.quit()

    def goto(self, url: str) -> None:
        self.driver.get(url)

    def _element(self, css: str) -> Any:
        from selenium.webdriver.common.by import By  # noqa: PLC0415

        return self.driver.find_element(By.CSS_SELECTOR, css)

    def click(self, css: str) -> None:
        self._element(css).click()

    def type(self, css: str, text: str) -> None:
        self._element(css).send_keys(text)

    def press(self, key: str) -> None:
        from selenium.webdriver.common.action_chains import ActionChains  # noqa: PLC0415
        from selenium.webdriver.common.keys import Keys  # noqa: PLC0415

        keys = {
            "ArrowDown": Keys.ARROW_DOWN,
            "ArrowUp": Keys.ARROW_UP,
            "Enter": Keys.ENTER,
            "Escape": Keys.ESCAPE,
        }
        ActionChains(self.driver).send_keys(keys.get(key, key)).perform()

    def js(self, expression: str) -> Any:
        return self.driver.execute_script(expression)

    def click_at(self, x: float, y: float) -> None:
        from selenium.webdriver.common.actions.action_builder import ActionBuilder  # noqa: PLC0415

        actions = ActionBuilder(self.driver)
        actions.pointer_action.move_to_location(int(x), int(y)).click()  # type: ignore[no-untyped-call]
        actions.perform()

    def screenshot(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.driver.save_screenshot(str(path))

    def element_screenshot(self, css: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._element(css).screenshot(str(path))

    def open_popup(self) -> None:
        # Marionette refuses content-context navigation to moz-extension:// URLs,
        # so the new tab loads the popup from chrome context with the system principal.
        self.driver.switch_to.new_window("tab")
        with self.driver.context(self.driver.CONTEXT_CHROME):
            self.driver.execute_script(
                "gBrowser.selectedBrowser.fixupAndLoadURIString(arguments[0], {"
                "triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal()});",
                f"moz-extension://{FIREFOX_UUID}/popup.html",
            )
        wait_until(
            lambda: self.driver.current_url.startswith("moz-extension://"),
            10.0,
            what="popup tab",
        )

    def back_to_page(self) -> None:
        for handle in self.driver.window_handles:
            if handle != self._page_handle:
                self.driver.switch_to.window(handle)
                self.driver.close()
        self.driver.switch_to.window(self._page_handle)


class ChromiumSession:
    """Playwright Chromium with the unpacked Chrome build loaded via --load-extension."""

    def __init__(
        self, home: Path, bus_address: str, site: SiteServer, *, dark: bool = False
    ) -> None:
        self.name = "chromium-dark" if dark else "chromium"
        from playwright.sync_api import sync_playwright  # noqa: PLC0415 - heavy, browser tests only

        _, chrome_dist = build_extension()
        profile = home / "chromium-profile"
        # Chromium reads user-level host manifests from <user-data-dir>/NativeMessagingHosts.
        install_native_host(home, bus_address, "chromium", profile / "NativeMessagingHosts")
        self._pw = sync_playwright().start()
        rules = ", ".join(f"MAP {h} 127.0.0.1" for h in HOSTS)
        self.context = self._pw.chromium.launch_persistent_context(
            str(profile),
            channel="chromium",
            headless=True,
            env=dict[str, str | float | bool](browser_env(home, bus_address)),
            ignore_https_errors=True,
            viewport={"width": VIEWPORT[0], "height": VIEWPORT[1]},
            color_scheme="dark" if dark else "light",
            args=[
                f"--disable-extensions-except={chrome_dist}",
                f"--load-extension={chrome_dist}",
                f"--host-resolver-rules={rules}",
                "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable",
                "--password-store=basic",
            ],
        )
        self.site = site
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self._popup: Any = None

    def close(self) -> None:
        self.context.close()
        self._pw.stop()

    @property
    def _current(self) -> Any:
        return self._popup or self.page

    def goto(self, url: str) -> None:
        self.page.goto(url)

    def click(self, css: str) -> None:
        self._current.click(css)

    def type(self, css: str, text: str) -> None:
        self._current.locator(css).press_sequentially(text)

    def press(self, key: str) -> None:
        self._current.keyboard.press(key)

    def js(self, expression: str) -> Any:
        return self._current.evaluate(f"() => {{ {expression} }}")

    def click_at(self, x: float, y: float) -> None:
        self._current.mouse.click(x, y)

    def screenshot(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._current.screenshot(path=str(path))

    def element_screenshot(self, css: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._current.locator(css).screenshot(path=str(path))

    def open_popup(self) -> None:
        self._popup = self.context.new_page()
        self._popup.set_viewport_size({"width": 360, "height": 520})
        self._popup.goto(f"chrome-extension://{CHROME_ID}/popup.html")

    def back_to_page(self) -> None:
        if self._popup is not None and not self._popup.is_closed():
            self._popup.close()
        self._popup = None
        self.page.bring_to_front()


def firefox_binaries() -> tuple[Path, Path]:
    """A non-snap Firefox and its geckodriver, downloaded once by Selenium Manager.

    Snap Firefox can only reach native hosts through the desktop portal, which a private test
    session does not run; a Mozilla build reads ~/.mozilla/native-messaging-hosts itself.
    `PA_FIREFOX` / `PA_GECKODRIVER` override the lookup.
    """
    if os.environ.get("PA_FIREFOX") and os.environ.get("PA_GECKODRIVER"):
        return Path(os.environ["PA_FIREFOX"]), Path(os.environ["PA_GECKODRIVER"])
    cache = Path(os.environ.get("SE_CACHE_PATH") or Path.home() / ".cache" / "selenium")
    firefoxes = sorted(cache.glob("firefox/linux64/*/firefox"), key=lambda p: p.stat().st_mtime)
    drivers = sorted(
        cache.glob("geckodriver/linux64/*/geckodriver"), key=lambda p: p.stat().st_mtime
    )
    if firefoxes and drivers:
        return firefoxes[-1], drivers[-1]
    from selenium.webdriver.common.selenium_manager import SeleniumManager  # noqa: PLC0415

    result = SeleniumManager().binary_paths(
        [
            "--browser",
            "firefox",
            "--browser-version",
            "stable",
            "--force-browser-download",
            "--skip-driver-in-path",
            "--cache-path",
            str(cache),
        ]
    )
    return Path(result["browser_path"]), Path(result["driver_path"])


# Top 600 px of the 1280x820 viewport: every form, menu and prompt sits there.
_PROOF_FILTER: Final = (
    "crop=iw:min(ih\\,600):0:0,split[a][b];"
    "[a]palettegen=max_colors=256:stats_mode=full[p];[b][p]paletteuse=dither=sierra2_4a"
)


def compress_proof(raw: Path, out: Path) -> None:
    """Keep a page screenshot small enough to commit: the top of the page as a 256-colour
    PNG, dithered so the page gradients do not band. Removes `raw`."""
    subprocess.run(  # noqa: S603 - fixed argv, ffmpeg from PATH
        [
            shutil.which("ffmpeg") or "ffmpeg",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(raw),
            "-vf",
            _PROOF_FILTER,
            str(out),
        ],
        check=True,
    )
    raw.unlink()


class FrameRecorder:
    """A `Page` that grabs a full-page frame after every action, for the proof videos.

    Neither geckodriver nor a headless Firefox records video, so both browsers get the same
    treatment: frames after each step, `screenshot()` scenes held longer, encoded to WebM.
    Scenario screenshots go to the frames only, never over the proof PNGs.
    """

    def __init__(self, page: Page, frames: Path) -> None:
        self.name = page.name
        self._page = page
        self._frames = frames
        self._durations: list[float] = []
        frames.mkdir(parents=True, exist_ok=True)

    def _frame(self, hold: float = 0.6) -> None:
        # Chromium refuses a capture while a click's navigation is committing; retry briefly.
        path = self._frames / f"{len(self._durations):04d}.png"
        deadline = time.monotonic() + 3.0
        while True:
            try:
                self._page.screenshot(path)
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)
        self._durations.append(hold)

    def goto(self, url: str) -> None:
        self._page.goto(url)
        self._frame()

    def click(self, css: str) -> None:
        self._page.click(css)
        self._frame()

    def type(self, css: str, text: str) -> None:
        self._page.type(css, text)
        self._frame()

    def press(self, key: str) -> None:
        self._page.press(key)
        self._frame()

    def js(self, expression: str) -> Any:
        return self._page.js(expression)

    def click_at(self, x: float, y: float) -> None:
        self._page.click_at(x, y)
        self._frame()

    def screenshot(self, path: Path) -> None:
        del path  # a scene: shown longer in the video
        self._frame(hold=1.8)

    def element_screenshot(self, css: str, path: Path) -> None:
        del css, path
        self._frame(hold=1.8)

    def open_popup(self) -> None:
        self._page.open_popup()

    def back_to_page(self) -> None:
        self._page.back_to_page()

    def hold(self, seconds: float = 1.2) -> None:
        """One more frame of the current state (after a wait the scenario did itself)."""
        self._frame(hold=seconds)

    def encode(self, out: Path) -> None:
        """Concatenate the frames with their hold times into a VP9 WebM."""
        lines = []
        for index, seconds in enumerate(self._durations):
            lines += [f"file '{index:04d}.png'", f"duration {seconds}"]
        lines.append(f"file '{len(self._durations) - 1:04d}.png'")  # concat demuxer quirk
        listing = self._frames / "frames.txt"
        listing.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603 - fixed argv, ffmpeg from PATH
            [
                shutil.which("ffmpeg") or "ffmpeg",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "concat",
                "-safe",
                "0",
                "-i",
                str(listing),
                "-vf",
                "fps=10,scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p",
                "-c:v",
                "libvpx-vp9",
                "-b:v",
                "0",
                "-crf",
                "36",
                str(out),
            ],
            check=True,
        )
