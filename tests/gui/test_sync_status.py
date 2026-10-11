# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Header sync status, Sync Now, and the pause / sign-in / service banners."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _status_title(app: support.AppUnderTest) -> str:
    title: str = app.window.status_button.content.get_label()
    return title


def test_header_shows_synced_with_last_sync_time(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    support.wait_until(lambda: _status_title(app) == "Synced", what="synced")
    button = app.window.status_button
    assert button.detail.get_text() == "Last synced 2 minutes ago"
    assert button.account.get_text() == "Apple Account: alex.doe@example.com"
    assert button.sync_button.get_visible()
    assert button.sync_button.get_sensitive()
    assert not button.sign_in_button.get_visible()


@pytest.mark.parametrize(
    ("hook", "title"),
    [
        (lambda d: d.go_offline(), "Offline"),
        (lambda d: d.start_syncing(), "Syncing…"),
        (lambda d: d.require_signin(), "Sign-In Required"),
        (lambda d: d.sign_out(), "Not Signed In"),
        (lambda d: d.set_error("CloudKit said no"), "Sync Error"),
    ],
)
def test_status_follows_the_daemon(app: support.AppUnderTest, hook: Any, title: str) -> None:
    app.wait_loaded()
    app.call(hook)
    support.wait_until(lambda: _status_title(app) == title, what=title)


def test_sync_now_runs_a_cycle(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.status_button.sync_button.emit("clicked")
    support.wait_until(lambda: _status_title(app) == "Syncing…", what="syncing")
    support.wait_until(lambda: _status_title(app) == "Synced", what="synced again")
    assert app.window.status_button.detail.get_text() == "Last synced just now"
    assert "SyncNow" in app.call(lambda d: d.calls)


def test_sync_now_is_disabled_while_syncing(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.start_syncing())
    support.wait_until(lambda: _status_title(app) == "Syncing…", what="syncing")
    assert not app.window.lookup_action("sync-now").get_enabled()
    assert not app.window.status_button.sync_button.get_sensitive()


def test_error_message_from_the_daemon_is_shown_verbatim(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.set_error("Apple rejected the request (503)"))
    support.wait_until(
        lambda: app.window.status_button.detail.get_text() == "Apple rejected the request (503)",
        what="message",
    )


def _pause(app: support.AppUnderTest, count: int = 6) -> list[str]:
    ids: list[str] = app.call(lambda d: list(d.items)[:count])
    app.call(lambda d: d.pause(local_ids=ids))
    banner = app.window.list_page.pause_banner
    support.wait_until(banner.get_revealed, what="pause banner")
    return ids


def test_pause_banner_counts_the_pending_deletions(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _pause(app, 6)
    banner = app.window.list_page.pause_banner
    assert banner.get_title() == "Sync paused: 6 passwords would be deleted"
    assert banner.get_button_label() == "Review…"
    assert _status_title(app) == "Sync Paused"


def _review(app: support.AppUnderTest) -> Any:
    support.wait_button(app.window.list_page.pause_banner, "Review…").emit("clicked")
    return support.wait_until(lambda: app.window.pause_dialog, what="pause dialog")


def test_pause_apply_deletes_the_pending_items(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    ids = _pause(app)
    dialog = _review(app)
    assert {"apply", "restore", "cancel"} <= {
        r for r in ("apply", "restore", "cancel") if dialog.has_response(r)
    }
    dialog.emit("response", "apply")
    support.wait_until(lambda: not app.window.list_page.pause_banner.get_revealed(), what="hidden")
    assert not set(ids) & set(app.call(lambda d: d.items))
    support.wait_until(lambda: len(app.titles()) == 60 - len(ids), what="list shrank")


def test_pause_restore_keeps_every_item(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    ids = _pause(app)
    _review(app).emit("response", "restore")
    support.wait_until(lambda: not app.window.list_page.pause_banner.get_revealed(), what="hidden")
    assert set(ids) <= set(app.call(lambda d: d.items))
    assert len(app.titles()) == 60
    support.wait_toast(app, "Passwords restored")


def test_pause_decide_later_changes_nothing(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _pause(app)
    _review(app).emit("response", "cancel")
    support.pump(0.3)
    assert app.window.list_page.pause_banner.get_revealed()
    assert "ResolvePause" not in app.call(lambda d: d.calls)


def test_signin_banner_opens_the_wizard(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.require_signin())
    banner = app.window.list_page.signin_banner
    support.wait_until(banner.get_revealed, what="sign-in banner")
    support.wait_button(banner, "Sign In…").emit("clicked")
    dialog = support.wait_until(lambda: app.window.sign_in_dialog, what="wizard")
    assert dialog.apple_id.get_text() == "alex.doe@example.com"


def test_service_down_shows_a_banner_and_recovers(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.stop())
    banner = app.window.list_page.unreachable_banner
    support.wait_until(banner.get_revealed, what="unreachable banner")
    assert _status_title(app) == "Service Not Running"
    app.call(lambda d: d.start(app.fake.bus_address))
    support.wait_until(lambda: not banner.get_revealed(), what="banner gone")
    support.wait_until(lambda: _status_title(app) == "Synced", what="synced")
