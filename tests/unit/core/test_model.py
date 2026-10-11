# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Credential/TrashEntry invariants the sync layer relies on."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from tests.fakes.memory_stores import make_credential

from passwords_app.core.model import Credential, TrashEntry

NAIVE = datetime(2026, 1, 1)  # noqa: DTZ001 - the invalid input under test


@pytest.mark.parametrize("field", ["id", "url"])
def test_required_text_fields_must_be_non_empty(field: str) -> None:
    with pytest.raises(ValueError, match=f"{field} must be non-empty"):
        make_credential("A", **{field: ""}) if field != "id" else make_credential("")


@pytest.mark.parametrize("field", ["created", "modified"])
def test_timestamps_must_be_timezone_aware(field: str) -> None:
    with pytest.raises(ValueError, match=f"{field} must be timezone-aware"):
        make_credential("A", **{field: NAIVE})


def test_empty_username_and_password_are_allowed() -> None:
    c = make_credential("A", username="", password="")
    assert (c.username, c.password) == ("", "")


def test_content_hash_ignores_id_and_timestamps() -> None:
    a = make_credential("A")
    b = dataclasses.replace(a, id="B", modified=a.modified + timedelta(days=1))
    assert a.content_hash() == b.content_hash()


@pytest.mark.parametrize(
    "change",
    [
        {"title": ""},
        {"notes": ""},
        {"otpauth": ""},
        {"group": ""},
        {"alt_urls": ("",)},
    ],
)
def test_content_hash_distinguishes_none_from_empty(change: dict[str, object]) -> None:
    a = make_credential("A")
    assert a.content_hash() != dataclasses.replace(a, **change).content_hash()  # type: ignore[arg-type]


def test_content_hash_is_order_sensitive_for_alt_urls() -> None:
    a = make_credential("A", alt_urls=("https://x.example", "https://y.example"))
    b = dataclasses.replace(a, alt_urls=("https://y.example", "https://x.example"))
    assert a.content_hash() != b.content_hash()


def test_trash_entry_requires_aware_deletion_time() -> None:
    with pytest.raises(ValueError, match="deleted_at"):
        TrashEntry("T", make_credential("A"), NAIVE, "conflict")


def test_trash_entry_expiry() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    e = TrashEntry("T", make_credential("A"), at, "deleted-both")
    assert e.expires_at(timedelta(days=90)) == datetime(2026, 4, 1, tzinfo=UTC)


def test_credential_is_immutable() -> None:
    c: Credential = make_credential("A")
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.password = "x"  # type: ignore[misc]
