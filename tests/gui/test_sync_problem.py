# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Passwords iCloud refuses to store: row badge, detail banner and the header's warning."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)

DUPLICATE = "another password for this website and username already exists"
TITLE = "Northwind Mail"


def _id_of(app: support.AppUnderTest, title: str) -> str:
    item_id: str = next(
        c.id for c in app.call(lambda d: list(d.items.values())) if c.title == title
    )
    return item_id


def _badges(app: support.AppUnderTest) -> dict[str, str]:
    """Shown rows' titles -> their badge text ("" without one)."""
    from passwords_app.app.ui.item_list import ItemRow  # noqa: PLC0415

    return {
        w.title.get_text(): w.local_badge.get_label() if w.local_badge.get_visible() else ""
        for w in support.walk(app.window.list_page.list_view)
        if isinstance(w, ItemRow) and w.get_mapped()
    }


def _refuse(app: support.AppUnderTest, title: str) -> str:
    item_id = _id_of(app, title)
    app.call(lambda d: d.refuse(item_id, DUPLICATE))
    support.wait_until(lambda: app.vault.count_refused() == 1, what="refusal reloaded")
    return item_id


def test_a_refused_password_is_marked_on_this_computer_only(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item_id = _refuse(app, TITLE)
    assert app.window.list_page.select_id(item_id)  # scrolls its row into view
    support.wait_until(lambda: _badges(app).get(TITLE), what="badge")
    badges = _badges(app)
    assert badges[TITLE] == "On this computer only"
    assert [t for t, badge in badges.items() if badge] == [TITLE]


def test_the_detail_explains_why(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _refuse(app, TITLE)
    app.select(TITLE)
    banner = app.window.detail.local_banner
    support.wait_until(banner.get_revealed, what="banner")
    assert banner.get_title() == (
        "On this computer only: iCloud did not accept this password. "
        "Another password for this website and username already exists."
    )
    app.select("Contoso ID")
    support.wait_until(lambda: not banner.get_revealed(), what="no banner for a synced one")


def test_the_banner_goes_once_icloud_takes_the_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item_id = _refuse(app, TITLE)
    app.select(TITLE)
    banner = app.window.detail.local_banner
    support.wait_until(banner.get_revealed, what="banner")
    app.call(lambda d: d.accept(item_id))
    support.wait_until(lambda: not banner.get_revealed(), what="banner gone")
    assert not _badges(app).get(TITLE)


def test_the_header_warns_instead_of_synced(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    button: Any = app.window.status_button
    support.wait_until(lambda: button.content.get_label() == "Synced", what="synced")
    item_id = _refuse(app, TITLE)
    support.wait_until(lambda: button.content.get_label() == "Not All Synced", what="warning")
    assert button.content.get_icon_name() == "dialog-warning-symbolic"
    assert button.has_css_class("warning")
    assert button.local_only.get_visible()
    assert button.local_only.get_text() == "1 password is on this computer only"
    app.call(lambda d: d.accept(item_id))
    support.wait_until(lambda: button.content.get_label() == "Synced", what="synced again")
    assert not button.has_css_class("warning")
    assert not button.local_only.get_visible()
