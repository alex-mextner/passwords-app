# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Adaptive three-pane layout and website icons."""

from __future__ import annotations

import http.server
import struct
import threading
import zlib
from typing import Any, override

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _png(size: int = 16) -> bytes:
    """A real PNG (solid blue square), built here so no binary fixture is needed."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    rows = b"".join(b"\x00" + b"\x1c\x71\xd8" * size for _ in range(size))
    header = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


PNG = _png()


def _resize(app: support.AppUnderTest, width: int, height: int = 760) -> None:
    app.window.set_default_size(width, height)
    support.wait_until(lambda: app.window.get_width() == width, what=f"width {width}")
    support.pump(0.2)


def test_wide_window_shows_three_panes(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _resize(app, 1180)
    assert not app.window.outer.get_collapsed()
    assert not app.window.inner.get_collapsed()


def test_medium_window_hides_the_sidebar(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _resize(app, 800)
    assert app.window.outer.get_collapsed()
    assert not app.window.inner.get_collapsed()


def test_narrow_window_shows_one_pane_and_navigates(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _resize(app, 420)
    assert app.window.outer.get_collapsed()
    assert app.window.inner.get_collapsed()
    app.window.outer.set_show_content(True)
    app.select("Northwind Mail")
    app.window.activate_action("win.show-detail", None)
    support.wait_until(app.window.inner.get_show_content, what="detail pane shown")
    app.window.activate_action("win.search", None)
    support.wait_until(lambda: not app.window.inner.get_show_content(), what="back to list")


def test_choosing_a_section_on_a_narrow_window_shows_the_list(app: support.AppUnderTest) -> None:
    from passwords_app.app import sections  # noqa: PLC0415

    app.wait_loaded()
    _resize(app, 420)
    app.window.outer.set_show_content(False)
    support.pump(0.3)
    app.window.sidebar.select(sections.CODES)
    support.wait_until(app.window.outer.get_show_content, what="list shown")


def test_window_size_is_remembered(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _resize(app, 1000, 700)
    app.window.close()
    support.pump(0.2)
    assert app.settings.get_int("window-width") == 1000
    assert app.settings.get_int("window-height") == 700


class _IconServer(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []  # noqa: RUF012 - shared by the server thread and the test

    def do_GET(self) -> None:
        self.hits.append(self.path)
        if self.path.startswith("/mail.northwind.example/"):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(PNG)
        else:
            self.send_response(404)
            self.end_headers()

    @override
    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def icon_server(app: support.AppUnderTest, tmp_path: Any) -> Any:
    _IconServer.hits = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IconServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cache = app.window.favicons.cache
    cache.directory = tmp_path / "favicons"
    cache.session.trust_env = False
    port = server.server_address[1]
    cache.url_for = lambda host: f"http://127.0.0.1:{port}/{host}/favicon.ico"
    yield _IconServer.hits
    server.shutdown()
    server.server_close()


def test_icons_are_off_by_default_and_nothing_is_fetched(
    app: support.AppUnderTest, icon_server: list[str]
) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    support.pump(0.5)
    assert icon_server == []
    assert not app.window.detail.tile.showing_icon


def test_enabling_icons_fetches_and_shows_them(
    app: support.AppUnderTest, icon_server: list[str]
) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    # Gio.Settings.set_boolean only takes the value positionally.
    app.settings.set_boolean("favicons-enabled", True)  # noqa: FBT003
    support.wait_until(lambda: app.window.detail.tile.showing_icon, what="icon shown")
    assert "/mail.northwind.example/favicon.ico" in icon_server
    assert (app.window.favicons.cache.directory).is_dir()
    app.settings.set_boolean("favicons-enabled", False)  # noqa: FBT003
    support.wait_until(lambda: not app.window.detail.tile.showing_icon, what="letters again")


def test_sites_without_an_icon_keep_their_letter(
    app: support.AppUnderTest, icon_server: list[str]
) -> None:
    app.wait_loaded()
    app.settings.set_boolean("favicons-enabled", True)  # noqa: FBT003
    app.select("Contoso ID")
    support.wait_until(lambda: any("contoso" in h for h in icon_server), what="asked")
    support.pump(0.3)
    assert not app.window.detail.tile.showing_icon
    assert app.window.detail.tile.get_text() == "C"
