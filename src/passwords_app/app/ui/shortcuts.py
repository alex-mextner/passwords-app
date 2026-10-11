# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Keyboard shortcuts (spec §8) and the Shortcuts dialog that documents them.

The table is the single source: the application registers accelerators from it and the
dialog lists the same entries, so the help can never drift from the behavior.
"""

from __future__ import annotations

from dataclasses import dataclass

from gi.repository import Adw

from passwords_app.app.i18n import _, pgettext


@dataclass(frozen=True, slots=True)
class Shortcut:
    action: str
    accels: tuple[str, ...]
    title: str
    section: str
    # Accelerators that would steal ordinary text editing keys (Ctrl+C, Delete, Ctrl+Z) are
    # handled by the window in the bubble phase, after a focused text field had its chance.
    bubble: bool = False


def shortcuts() -> list[Shortcut]:
    general = _("General")
    item = _("Selected Password")
    nav = _("Navigation")
    return [
        Shortcut("win.search", ("<Control>f",), _("Search"), general),
        Shortcut("win.new-password", ("<Control>n",), _("New Password"), general),
        Shortcut("win.sync-now", ("<Control>r",), _("Sync Now"), general),
        Shortcut("app.preferences", ("<Control>comma",), _("Preferences"), general),
        Shortcut("app.shortcuts", ("<Control>question",), _("Keyboard Shortcuts"), general),
        Shortcut("app.quit", ("<Control>q",), _("Quit"), general),
        Shortcut("win.copy-password", ("<Control>c",), _("Copy Password"), item, bubble=True),
        Shortcut("win.copy-username", ("<Control><Shift>c",), _("Copy User Name"), item),
        Shortcut("win.copy-code", ("<Control><Alt>c",), _("Copy Verification Code"), item),
        Shortcut("win.reveal", ("<Control>i",), _("Show or Hide Password"), item),
        Shortcut("win.edit", ("<Control>e",), _("Edit"), item),
        Shortcut("win.save-edit", ("<Control>s",), _("Save Changes"), item),
        Shortcut("win.cancel-edit", ("Escape",), _("Cancel Editing"), item, bubble=True),
        Shortcut("win.delete", ("Delete",), _("Delete"), item, bubble=True),
        Shortcut("win.undo", ("<Control>z",), _("Undo Delete"), item, bubble=True),
        Shortcut("win.section::all", ("<Control>1",), _("All Passwords"), nav),
        Shortcut("win.section::codes", ("<Control>2",), _("Codes"), nav),
        Shortcut("win.section::security", ("<Control>3",), _("Security"), nav),
        Shortcut(
            "win.section::deleted", ("<Control>4",), pgettext("sidebar section", "Deleted"), nav
        ),
    ]


def accelerators(sections: list[Adw.ShortcutsSection]) -> set[str]:
    """Every accelerator listed in `sections`."""
    return {
        item.get_accelerator()
        for section in sections
        for item in section
        if isinstance(item, Adw.ShortcutsItem)
    }


def build_dialog() -> tuple[Adw.ShortcutsDialog, list[Adw.ShortcutsSection]]:
    """Build the dialog and return its sections (AdwShortcutsDialog cannot list them)."""
    dialog = Adw.ShortcutsDialog()
    sections: dict[str, Adw.ShortcutsSection] = {}
    for entry in shortcuts():
        section = sections.get(entry.section)
        if section is None:
            section = sections[entry.section] = Adw.ShortcutsSection.new(entry.section)
            dialog.add(section)
        section.add(Adw.ShortcutsItem.new(entry.title, " ".join(entry.accels)))
    nav = sections[_("Navigation")]
    nav.add(Adw.ShortcutsItem.new(_("Move Between Items"), "Up Down"))
    nav.add(Adw.ShortcutsItem.new(_("Next Pane"), "Tab"))
    nav.add(Adw.ShortcutsItem.new(_("Back"), "<Alt>Left"))
    return dialog, list(sections.values())
