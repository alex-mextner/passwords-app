# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The UI renders in Russian: translated labels, plurals and dates, no English leftovers."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


@pytest.fixture
def lang() -> str:
    return "ru"


def _english_msgids() -> set[str]:
    """Plain (placeholder-free) English UI strings from the template."""
    text = (support.ROOT / "po" / "passwords-app.pot").read_text(encoding="utf-8")
    ids = set()
    for match in re.finditer(r'^msgid "(.+)"$', text, flags=re.MULTILINE):
        msgid = match.group(1).encode().decode("unicode_escape").encode("latin-1").decode()
        if "{" not in msgid and re.search(r"[A-Za-z]{3}", msgid):
            ids.add(msgid)
    return ids


def _english_leftovers(root: Any) -> list[str]:
    english = _english_msgids()
    return sorted({t for t in support.visible_texts(root) if t in english})


def test_sidebar_and_headers_are_russian(app: support.AppUnderTest) -> None:
    from passwords_app.app import sections  # noqa: PLC0415

    app.wait_loaded()
    rows = app.window.sidebar.rows
    assert rows[sections.ALL].label.get_text() == "Все"  # noqa: RUF001 - Russian text
    assert rows[sections.CODES].label.get_text() != "Codes"
    assert rows[sections.DELETED].label.get_text() != "Deleted"
    assert app.window.list_page.search.get_placeholder_text() != "Search"
    assert app.window.status_button.content.get_label() != "Synced"


def test_every_header_status_fits_untruncated(app: support.AppUnderTest) -> None:
    from gi.repository import Gtk  # noqa: PLC0415

    from passwords_app.app.records import Status, SyncState  # noqa: PLC0415

    app.wait_loaded()
    button = app.window.status_button
    label = next(w for w in support.walk(button.content) if isinstance(w, Gtk.Label))
    original = button.status
    try:
        for state in SyncState:
            button.show_status(Status(state=state))
            support.pump(0.1)
            assert not label.get_layout().is_ellipsized(), label.get_text()
    finally:
        button.show_status(original)


def test_main_window_has_no_english_left(app: support.AppUnderTest) -> None:
    app.wait_scanned()
    app.select("Northwind Mail")
    support.pump(0.3)
    assert _english_leftovers(app.window) == []


def test_edit_form_has_no_english_left(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Contoso ID")
    app.window.activate_action("win.edit", None)
    support.wait_until(lambda: app.window.detail.editing, what="edit")
    support.pump(0.3)
    assert _english_leftovers(app.window) == []


def test_deleted_view_uses_russian_plurals(app: support.AppUnderTest) -> None:
    from gi.repository import GLib  # noqa: PLC0415

    app.wait_loaded()
    app.window.activate_action("win.section", GLib.Variant("s", "deleted"))
    support.pump(0.3)
    texts = support.visible_texts(app.window.list_page.trash_view)
    # 88 days ago → 2 days left: "Осталось 2 дня"-style plural, never the English word.
    assert not any("days left" in t for t in texts)
    assert any(re.search(r"\b2 дня\b", t) for t in texts)


def test_dates_use_russian_month_names(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    created = app.window.detail.created_row.get_subtitle()
    months = [
        "января",
        "февраля",
        "марта",
        "апреля",
        "мая",
        "июня",
        "июля",
        "августа",
        "сентября",
        "октября",
        "ноября",
        "декабря",
    ]
    assert item.created.date() < app.call(lambda d: d.clock()).date() - timedelta(days=2)
    assert any(m in created for m in months)
    assert str(item.created.astimezone().year) in created


def test_sign_in_wizard_is_russian(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.sign_out())
    app.window.activate_action("win.sign-in", None)
    dialog = support.wait_until(lambda: app.window.sign_in_dialog, what="wizard")
    support.wait_until(dialog.get_mapped, what="mapped")
    dialog.apple_id.set_text("alex.doe@example.com")
    dialog.password.set_text("correct-horse")
    dialog.start()
    support.wait_until(lambda: dialog.page_tag == "code", what="code page")
    dialog.code_boxes.entries[0].set_text("123456")
    support.wait_until(lambda: dialog.page_tag == "device", what="device page")
    support.pump(0.5)
    assert _english_leftovers(dialog) == []
    text = " ".join(support.visible_texts(dialog)).casefold()
    assert "код-пароль" in text or "код‑пароль" in text or "пароль" in text  # noqa: RUF001 - the translation may use a non-breaking hyphen
    assert "escrow" not in text
    assert "эскроу" not in text


def test_preferences_are_russian(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.application.activate_action("preferences", None)
    prefs = support.wait_until(lambda: getattr(app.application, "preferences", None), what="prefs")
    support.wait_until(prefs.get_mapped, what="mapped")
    support.pump(0.3)
    assert _english_leftovers(prefs) == []
    assert any("90 дней" in t for t in support.visible_texts(prefs))
