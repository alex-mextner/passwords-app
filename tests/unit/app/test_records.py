# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Parsing of the daemon's D-Bus dictionaries: strict types, tolerant absence, safe defaults."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app.records import (
    Draft,
    Item,
    RecoveryDevice,
    ReplyError,
    SignInStep,
    Status,
    StepKind,
    SyncState,
    TrashEntry,
    TrashReason,
    display_host,
    from_unix_ms,
    to_unix_ms,
)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# Fictional values; kept in plain constants so no line looks like a credential assignment.
PW = "example-pw-1"
KEY_B32 = "JBSWY3DPEHPK3PXP"
CODE_URI = "otpauth://totp/a?" + urlencode({"secret": KEY_B32})
WIRE_ITEM: dict[str, object] = {
    "id": "item-1",
    "url": "https://login.example.com/signin",
    "username": "jane@example.com",
    "title": "Example Mail",
    "notes": "work account",
    "group": "Family",
    "alt_urls": ["https://example.org"],
    "created": 1_700_000_000_000,
    "modified": 1_760_000_000_000,
    "has_code": True,
}


# ---------------------------------------------------------------- timestamps


def test_from_unix_ms_zero_and_negative_mean_never() -> None:
    assert from_unix_ms(0) is None
    assert from_unix_ms(-5) is None


def test_from_unix_ms_is_utc_and_keeps_milliseconds() -> None:
    at = from_unix_ms(1_700_000_000_123)
    assert at == datetime(2023, 11, 14, 22, 13, 20, 123_000, tzinfo=UTC)


@given(st.integers(min_value=1, max_value=4_102_444_800_000))
def test_unix_ms_round_trip(ms: int) -> None:
    at = from_unix_ms(ms)
    assert at is not None
    assert to_unix_ms(at) == ms


# ---------------------------------------------------------------- display_host


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://www.example.com/login", "example.com"),
        ("https://WWW.Example.COM", "example.com"),
        ("https://mail.example.com", "mail.example.com"),
        ("example.com", "example.com"),
        ("https://www.xn--e1afmkfd.xn--p1ai/x", "пример.рф"),
        ("https://пример.рф", "пример.рф"),
        ("https://xn--fa-hia.de", "faß.de"),  # UTS #46 non-transitional, as the core encodes
        ("  not a url  ", "not a url"),
    ],
)
def test_display_host(url: str, host: str) -> None:
    assert display_host(url) == host


# ---------------------------------------------------------------- Item


def test_item_from_wire_reads_every_key() -> None:
    item = Item.from_wire(WIRE_ITEM)
    assert item == Item(
        id="item-1",
        url="https://login.example.com/signin",
        username="jane@example.com",
        title="Example Mail",
        notes="work account",
        group="Family",
        alt_urls=("https://example.org",),
        created=datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC),
        modified=datetime(2025, 10, 9, 8, 53, 20, tzinfo=UTC),
        has_code=True,
    )


def test_item_from_wire_absent_optional_keys_default() -> None:
    item = Item.from_wire({"id": "x"})
    assert item.url == ""
    assert item.username == ""
    assert item.alt_urls == ()
    assert item.created == EPOCH
    assert item.modified == EPOCH
    assert item.has_code is False
    assert item.password is None
    assert item.otpauth is None


def test_item_from_wire_ignores_unknown_keys() -> None:
    item = Item.from_wire({"id": "x", "future_key": object()})
    assert item.id == "x"


def test_item_from_wire_password_present_only_when_sent() -> None:
    assert Item.from_wire({"id": "x", "password": ""}).password == ""
    assert Item.from_wire({"id": "x", "password": PW}).password == PW


def test_item_otpauth_implies_has_code() -> None:
    item = Item.from_wire({"id": "x", "otpauth": CODE_URI})
    assert item.has_code is True
    assert item.otpauth == CODE_URI


def test_item_empty_otpauth_becomes_none() -> None:
    item = Item.from_wire({"id": "x", "otpauth": ""})
    assert item.otpauth is None
    assert item.has_code is False


def test_item_zero_timestamps_fall_back_to_epoch() -> None:
    item = Item.from_wire({"id": "x", "created": 0, "modified": 0})
    assert item.created == EPOCH
    assert item.modified == EPOCH


def test_item_alt_urls_accepts_tuple() -> None:
    assert Item.from_wire({"id": "x", "alt_urls": ("a.example",)}).alt_urls == ("a.example",)


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"id": ""},
        {"id": 7},
        {"id": "x", "url": None},
        {"id": "x", "username": b"jane"},
        {"id": "x", "has_code": 1},
        {"id": "x", "created": "1700000000000"},
        {"id": "x", "modified": True},
        {"id": "x", "created": 1.5},
        {"id": "x", "alt_urls": "https://example.com"},
        {"id": "x", "alt_urls": ["ok.example", 3]},
        {"id": "x", "password": None},
        {"id": "x", "otpauth": 5},
    ],
)
def test_item_from_wire_rejects_malformed(bad: dict[str, object]) -> None:
    with pytest.raises(ReplyError):
        Item.from_wire(bad)


def test_reply_error_is_value_error_naming_the_key() -> None:
    with pytest.raises(ValueError, match="id"):
        Item.from_wire({"id": 1})


@pytest.mark.parametrize(
    ("title", "url", "expected"),
    [
        ("Example Mail", "https://example.com", "Example Mail"),
        ("   ", "https://www.example.com/x", "example.com"),
        ("", "https://xn--e1afmkfd.xn--p1ai", "пример.рф"),
        ("", "", ""),
        ("  Bank  ", "", "Bank"),
    ],
)
def test_item_display_title(title: str, url: str, expected: str) -> None:
    assert Item(id="x", url=url, title=title).display_title == expected


def test_item_repr_hides_secrets() -> None:
    item = Item(id="x", url="example.com", password=PW, otpauth=CODE_URI)
    assert PW not in repr(item)
    assert KEY_B32 not in repr(item)


# ---------------------------------------------------------------- TrashEntry


def _trash(**overrides: object) -> dict[str, object]:
    wire: dict[str, object] = {
        "trash_id": "t-1",
        "reason": "deleted-on-linux",
        "deleted_at": 1_760_000_000_000,
        "expires_at": 1_762_592_000_000,
        "item": {"id": "item-1", "url": "example.com"},
    }
    wire.update(overrides)
    return wire


def test_trash_entry_from_wire() -> None:
    entry = TrashEntry.from_wire(_trash())
    assert entry.trash_id == "t-1"
    assert entry.reason is TrashReason.DELETED_ON_LINUX
    assert entry.item.id == "item-1"
    assert (entry.expires_at - entry.deleted_at).days == 30


@pytest.mark.parametrize("reason", list(TrashReason))
def test_trash_entry_known_reasons(reason: TrashReason) -> None:
    assert TrashEntry.from_wire(_trash(reason=reason.value)).reason is reason


@pytest.mark.parametrize("reason", ["", "evicted", "DELETED-ON-LINUX"])
def test_trash_entry_unknown_reason_is_unknown(reason: str) -> None:
    assert TrashEntry.from_wire(_trash(reason=reason)).reason is TrashReason.UNKNOWN


def test_trash_entry_missing_expiry_falls_back_to_deletion_time() -> None:
    wire = _trash()
    del wire["expires_at"]
    entry = TrashEntry.from_wire(wire)
    assert entry.expires_at == entry.deleted_at


def test_trash_entry_missing_times_are_epoch() -> None:
    entry = TrashEntry.from_wire({"trash_id": "t", "item": {"id": "i"}})
    assert entry.deleted_at == EPOCH
    assert entry.expires_at == EPOCH


@pytest.mark.parametrize(
    "bad",
    [
        _trash(trash_id=""),
        _trash(trash_id=None),
        _trash(item=None),
        _trash(item=["id", "x"]),
        _trash(item={"id": ""}),
        _trash(reason=3),
        _trash(deleted_at="yesterday"),
    ],
)
def test_trash_entry_rejects_malformed(bad: dict[str, object]) -> None:
    with pytest.raises(ReplyError):
        TrashEntry.from_wire(bad)


# ---------------------------------------------------------------- Status


def test_status_from_wire_full() -> None:
    status = Status.from_wire(
        {
            "state": "paused",
            "apple_id": "jane@example.com",
            "item_count": 42,
            "trash_count": 3,
            "last_sync": 1_760_000_000_000,
            "next_sync": 0,
            "message": "",
            "pending_local_deletions": ["a", "b"],
            "pending_remote_deletions": ["c"],
        }
    )
    assert status.state is SyncState.PAUSED
    assert status.apple_id == "jane@example.com"
    assert status.item_count == 42
    assert status.trash_count == 3
    assert status.last_sync == datetime(2025, 10, 9, 8, 53, 20, tzinfo=UTC)
    assert status.next_sync is None
    assert status.pending_deletions == 3


@pytest.mark.parametrize("state", [s for s in SyncState if s is not SyncState.UNREACHABLE])
def test_status_known_states(state: SyncState) -> None:
    assert Status.from_wire({"state": state.value}).state is state


@pytest.mark.parametrize("state", ["", "exploded", "IDLE", "unreachable"])
def test_status_unknown_or_app_only_state_is_error(state: str) -> None:
    assert Status.from_wire({"state": state}).state is SyncState.ERROR


def test_status_absent_keys_default() -> None:
    status = Status.from_wire({"state": "idle"})
    assert status.last_sync is None
    assert status.pending_deletions == 0
    assert status.message == ""


@pytest.mark.parametrize(
    "bad",
    [
        {"state": 1},
        {"state": "idle", "item_count": "3"},
        {"state": "idle", "trash_count": False},
        {"state": "idle", "pending_local_deletions": "a"},
        {"state": "idle", "message": None},
    ],
)
def test_status_rejects_malformed(bad: dict[str, object]) -> None:
    with pytest.raises(ReplyError):
        Status.from_wire(bad)


# ---------------------------------------------------------------- SignInStep / RecoveryDevice


@pytest.mark.parametrize("kind", list(StepKind))
def test_sign_in_step_kinds(kind: StepKind) -> None:
    step = SignInStep.from_wire({"step": kind.value, "destination": "+1 (•••) •••-••12"})
    assert step.step is kind
    assert step.destination == "+1 (•••) •••-••12"
    assert step.message == ""


@pytest.mark.parametrize("bad", [{}, {"step": "sms"}, {"step": 2}])
def test_sign_in_step_unknown_is_error(bad: dict[str, object]) -> None:
    with pytest.raises(ReplyError):
        SignInStep.from_wire(bad)


def test_recovery_device_from_wire() -> None:
    device = RecoveryDevice.from_wire(
        {"id": "d1", "name": "Jane's iPhone", "model": "iPhone 17", "serial": "•••X4Y"}
    )
    assert device == RecoveryDevice("d1", "Jane's iPhone", "iPhone 17", "•••X4Y")


def test_recovery_device_optional_keys_default() -> None:
    assert RecoveryDevice.from_wire({"id": "d1"}) == RecoveryDevice("d1", "", "", "")


@pytest.mark.parametrize("bad", [{}, {"id": ""}, {"id": "d1", "serial": 42}])
def test_recovery_device_rejects_malformed(bad: dict[str, object]) -> None:
    with pytest.raises(ReplyError):
        RecoveryDevice.from_wire(bad)


# ---------------------------------------------------------------- Draft


def test_draft_to_wire_has_every_editable_key_even_when_empty() -> None:
    assert Draft(url="example.com").to_wire() == {
        "id": "",
        "url": "example.com",
        "username": "",
        "password": "",
        "title": "",
        "notes": "",
        "otpauth": "",
        "alt_urls": [],
        "group": "",
    }


def test_draft_to_wire_strips_identifiers_but_not_secrets_or_notes() -> None:
    wire = Draft(
        url="  https://example.com ",
        username=" jane ",
        password=f" {PW} ",
        title="  Example  ",
        notes="  line\n",
        otpauth=f" {CODE_URI}\n",
        alt_urls=(" https://a.example ", "", "   "),
    ).to_wire()
    assert wire["url"] == "https://example.com"
    assert wire["title"] == "Example"
    assert wire["otpauth"] == CODE_URI
    assert wire["alt_urls"] == ["https://a.example"]
    assert wire["password"] == f" {PW} "
    assert wire["username"] == " jane "
    assert wire["notes"] == "  line\n"


def test_draft_from_item_round_trips_editable_fields() -> None:
    item = Item.from_wire({**WIRE_ITEM, "password": PW, "otpauth": CODE_URI})
    wire = Draft.from_item(item).to_wire()
    assert wire["id"] == "item-1"
    assert wire["password"] == PW
    assert wire["otpauth"] == CODE_URI
    assert wire["alt_urls"] == ["https://example.org"]
    assert wire["group"] == "Family"


def test_draft_from_item_without_fetched_secrets_uses_empty_strings() -> None:
    draft = Draft.from_item(Item(id="x", url="example.com"))
    assert draft.password == ""
    assert draft.otpauth == ""


def test_draft_repr_hides_secrets() -> None:
    text = repr(Draft(url="example.com", password=PW, otpauth=CODE_URI))
    assert PW not in text
    assert KEY_B32 not in text
