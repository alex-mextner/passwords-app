# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Detail pane: fields, reveal, strength, live verification code, warnings, websites."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from tests.gui import support

from passwords_app.app.formatting import MASK

pytestmark = pytest.mark.timeout(120)


def _first(app: support.AppUnderTest, predicate: Any) -> str:
    page = app.window.list_page
    for i in range(page.filtered.get_n_items()):
        item = page.filtered.get_item(i).item
        if predicate(item):
            title: str = item.display_title
            return title
    msg = "no matching item"
    raise AssertionError(msg)


def test_detail_shows_title_username_and_masked_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    detail = app.window.detail
    assert detail.title_label.get_text() == "Northwind Mail"
    assert detail.username_row.get_subtitle() == item.username
    assert detail.password_row.get_subtitle() == MASK
    assert item.password not in support.visible_texts(app.window)
    assert detail.stack.get_visible_child_name() == "view"


def test_reveal_shows_and_hides_the_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    detail = app.window.detail
    detail.reveal_button.set_active(True)
    assert detail.password_row.get_subtitle() == item.password
    assert detail.reveal_button.get_tooltip_text() == "Hide Password"
    detail.reveal_button.set_active(False)
    assert detail.password_row.get_subtitle() == MASK


def test_reveal_is_forgotten_when_another_item_is_selected(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    app.window.detail.reveal_button.set_active(True)
    app.select("Contoso ID")
    assert not app.window.detail.reveal_button.get_active()
    assert app.window.detail.password_row.get_subtitle() == MASK


def test_strength_meter_reflects_the_password(app: support.AppUnderTest) -> None:
    from passwords_app.app.security import Issue, Level  # noqa: PLC0415

    app.wait_scanned()
    weak_title = _first(app, lambda i: Issue.WEAK in app.vault.report.of(i.id))
    app.select(weak_title)
    assert app.window.detail.strength.level in {Level.VERY_WEAK, Level.WEAK}
    strong_title = _first(app, lambda i: not app.vault.report.of(i.id))
    app.select(strong_title)
    assert app.window.detail.strength.level in {Level.GOOD, Level.STRONG}


def test_verification_code_matches_the_daemon_and_counts_down(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    title = _first(app, lambda i: i.has_code)
    item = app.select(title)
    detail = app.window.detail
    support.wait_until(lambda: detail.code, what="code")
    # A period boundary may pass between the two reads; one retry covers it.
    assert (
        detail.code == app.code_now(item.id)
        or detail._fetch_code()
        or support.wait_until(
            lambda: detail.code == app.code_now(item.id), what="code agrees with the daemon"
        )
    )
    assert detail.code_label.get_text() == f"{detail.code[:3]} {detail.code[3:]}"
    before = detail.ring.seconds_left
    support.pump(1.2)
    assert 0 < detail.ring.seconds_left < before


def test_code_refreshes_when_its_period_ends(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    title = _first(app, lambda i: i.has_code)
    item = app.select(title)
    detail = app.window.detail
    support.wait_until(lambda: detail.code, what="first code")
    # Move the fake's clock to the next period, then let the shown code expire.
    later = datetime.now(UTC).timestamp() + 30
    app.call(lambda d: setattr(d, "clock", lambda: datetime.fromtimestamp(later, UTC)))
    expected = app.code_now(item.id)
    detail._code_expired()
    support.wait_until(lambda: detail.code == expected, what="refreshed code")


def test_code_row_hidden_without_a_code(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select(_first(app, lambda i: not i.has_code))
    assert not app.window.detail.code_row.get_visible()
    assert not app.window.lookup_action("copy-code").get_enabled()


def test_reused_password_shows_a_warning(app: support.AppUnderTest) -> None:
    from passwords_app.app.security import Issue  # noqa: PLC0415

    app.wait_scanned()
    title = _first(app, lambda i: Issue.REUSED in app.vault.report.of(i.id))
    app.select(title)
    detail = app.window.detail
    assert detail.warnings_group.get_visible()
    assert any("Also used on" in r.get_title() for r in detail.warning_rows)


def test_no_warning_for_a_healthy_password(app: support.AppUnderTest) -> None:
    app.wait_scanned()
    app.select(_first(app, lambda i: not app.vault.report.of(i.id)))
    assert not app.window.detail.warnings_group.get_visible()


def test_websites_notes_and_dates_are_shown(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select(_first(app, lambda i: i.alt_urls))
    detail = app.window.detail
    shown = [r.get_title() for r in detail.site_rows]
    assert shown == [u.split("://", 1)[-1] for u in (item.url, *item.alt_urls)]
    assert detail.created_row.get_subtitle()
    assert detail.modified_row.get_subtitle()
    item = app.select(_first(app, lambda i: i.notes))
    assert detail.notes_group.get_visible()
    assert detail.notes_label.get_text() == item.notes
    item = app.select(_first(app, lambda i: not i.notes))
    assert not detail.notes_group.get_visible()


def test_group_row_only_for_shared_items(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select(_first(app, lambda i: i.group == "Family"))
    assert app.window.detail.group_row.get_visible()
    assert app.window.detail.group_row.get_subtitle() == "Family"
    app.select(_first(app, lambda i: not i.group))
    assert not app.window.detail.group_row.get_visible()


def test_open_website_hands_the_url_to_the_launcher(
    app: support.AppUnderTest, monkeypatch: pytest.MonkeyPatch
) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    opened: list[str] = []
    monkeypatch.setattr(app.window, "open_uri", opened.append)
    button = next(
        w for w in support.walk(app.window.detail.site_rows[0]) if w.__class__.__name__ == "Button"
    )
    button.emit("clicked")
    assert opened == [item.url]


def test_item_deleted_elsewhere_clears_the_pane(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    app.delete_remotely(item.id)
    support.wait_until(
        lambda: app.window.detail.stack.get_visible_child_name() == "empty", what="cleared pane"
    )
    assert "Northwind Mail" not in app.titles()
