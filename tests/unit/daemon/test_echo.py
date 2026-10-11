# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Recognizing the keyring's change signals for a cycle's own writes."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from tests.fakes.memory_stores import make_credential

from passwords_app.daemon.echo import ECHO_WINDOW, Echo, WriteJournal, fingerprint, settled
from passwords_app.sync.ports import LocalSnapshot, RejectedLocalItem

if TYPE_CHECKING:
    from passwords_app.core.model import Credential

NOW = 500.0


def snap(*items: Credential, rejected: tuple[RejectedLocalItem, ...] = ()) -> LocalSnapshot:
    return LocalSnapshot({c.id: c for c in items}, rejected)


def test_fingerprint_ignores_timestamps_but_not_content() -> None:
    a = make_credential("A")
    later = dataclasses.replace(a, modified=a.modified.replace(year=2030))
    assert fingerprint(snap(a)) == fingerprint(snap(later))
    assert fingerprint(snap(a)) != fingerprint(snap(dataclasses.replace(a, notes="n")))


def test_fingerprint_includes_rejected_items() -> None:
    bad = RejectedLocalItem("/org/freedesktop/secrets/collection/x/9", "odd label", "no URL")
    assert fingerprint(snap()) != fingerprint(snap(rejected=(bad,)))


def test_journal_expects_its_writes_on_top_of_the_first_read() -> None:
    a, b, c = make_credential("A"), make_credential("B"), make_credential("C")
    journal = WriteJournal()
    journal.read(snap(a, b))
    journal.read(snap(a))  # later reads (e.g. a re-read after writes) do not move the base
    edited = dataclasses.replace(a, notes="from iCloud")
    journal.upserted(edited)
    journal.upserted(c)
    journal.deleted("B")
    journal.deleted("NEVER-THERE")
    assert journal.expected() == fingerprint(snap(edited, c))


def test_journal_without_a_read_expects_nothing() -> None:
    journal = WriteJournal()
    journal.upserted(make_credential("A"))
    assert journal.expected() is None


def test_settled_echo_when_the_keyring_holds_exactly_the_cycle_result() -> None:
    a, b = make_credential("A"), make_credential("B")
    journal = WriteJournal()
    journal.read(snap(a))
    journal.upserted(b)
    echo = settled(journal, snap(a, b), NOW)
    assert echo == Echo(fingerprint(snap(a, b)), NOW + ECHO_WINDOW)


def test_no_echo_when_someone_else_changed_the_keyring_during_the_cycle() -> None:
    a, b = make_credential("A"), make_credential("B")
    journal = WriteJournal()
    journal.read(snap(a))
    journal.upserted(b)
    assert settled(journal, snap(a, b, make_credential("USER")), NOW) is None
    assert settled(journal, snap(dataclasses.replace(a, notes="user"), b), NOW) is None


def test_no_echo_without_an_after_snapshot() -> None:
    journal = WriteJournal()
    journal.read(snap())
    assert settled(journal, None, NOW) is None


def test_echo_matches_only_its_content_and_only_inside_the_window() -> None:
    a = make_credential("A")
    echo = Echo(fingerprint(snap(a)), NOW + ECHO_WINDOW)
    assert echo.matches(snap(a), NOW)
    assert not echo.matches(snap(dataclasses.replace(a, notes="user")), NOW)
    assert not echo.matches(snap(a), NOW + ECHO_WINDOW)
    assert echo.active(NOW + ECHO_WINDOW - 0.1)
    assert not echo.active(NOW + ECHO_WINDOW)
