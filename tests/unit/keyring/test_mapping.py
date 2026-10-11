# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Credential ⇄ keyring item: lossless round trip, Seahorse edits, adoption, rejection."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from passwords_app.core.model import Credential
from passwords_app.keyring.mapping import (
    SCHEMA,
    ItemRejectedError,
    StoredItem,
    display_host,
    item_content,
    make_label,
    needs_created,
    read_item,
)

T0 = datetime(2026, 3, 1, 9, 30, 15, 123456, tzinfo=UTC)
T1 = datetime(2026, 9, 1, 18, 0, tzinfo=UTC)
WRITTEN_AT = 1_790_000_000
E = "\u2014"
FAKE_PW = "FAKE_PASSWORD_1"
OTP_URI = "otpauth://totp/Example:alice?issuer=Example&secret=" + "A" * 16


def cred(**changes: object) -> Credential:
    base = Credential(
        id="0E6C5D0B-2C55-4E5A-9F7E-6B6C1C0A9D11",
        url="https://example.com",
        username="alice",
        password=FAKE_PW,
        created=T0,
        modified=T1,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def stored_from(
    credential: Credential,
    *,
    label: str | None = None,
    modified: int = WRITTEN_AT,
    drop: tuple[str, ...] = (),
    extra: dict[str, str] | None = None,
) -> StoredItem:
    content = item_content(credential, written_at=WRITTEN_AT)
    attributes = {k: v for k, v in content.attributes.items() if k not in drop}
    attributes.update(extra or {})
    return StoredItem(
        ref="/org/freedesktop/secrets/collection/x/1",
        label=content.label if label is None else label,
        attributes=attributes,
        secret=content.secret,
        created=WRITTEN_AT,
        modified=modified,
    )


def seahorse_item(
    label: str, value: bytes = b"FAKE", attributes: dict[str, str] | None = None
) -> StoredItem:
    return StoredItem(
        ref="/org/freedesktop/secrets/collection/x/7",
        label=label,
        attributes={"xdg:schema": "org.gnome.keyring.Note", **(attributes or {})},
        secret=value,
        created=1_700_000_000,
        modified=1_700_000_500,
    )


def never_called() -> str:
    msg = "an item with pa-id must not get a new id"
    raise AssertionError(msg)


ODD_TEXT = "пароль\twith\nnewline and \u0000 nul"


ROUND_TRIP = [
    pytest.param(cred(), id="minimal"),
    pytest.param(
        cred(
            title="Work mail",
            notes="line one\nline two",
            otpauth=OTP_URI,
            alt_urls=("https://mail.example.com", "https://example.org/login"),
            group="SHARED-GROUP-1",
        ),
        id="every-field",
    ),
    pytest.param(cred(username=""), id="empty-username"),
    pytest.param(cred(title="example.com"), id="title-equal-to-host"),
    pytest.param(cred(title=""), id="empty-title"),
    pytest.param(cred(notes=""), id="empty-notes-is-not-none"),
    pytest.param(cred(otpauth=""), id="empty-otpauth-is-not-none"),
    pytest.param(cred(group=""), id="empty-group-is-not-none"),
    pytest.param(cred(alt_urls=("https://a.example",)), id="one-alt-url"),
    pytest.param(cred(url="https://192.168.1.1:8443/admin"), id="ip-port-url"),
    pytest.param(cred(url="https://[2001:db8::1]:8080"), id="ipv6-url"),
    pytest.param(cred(url="https://пример.рф", username="алиса"), id="idn-cyrillic"),
    pytest.param(cred(title="🔑 Bank 🏦", username="😀"), id="emoji"),
    pytest.param(cred(password="p" * 10_000), id="long-password"),
    pytest.param(cred(password=""), id="empty-password"),
    pytest.param(cred(password=ODD_TEXT), id="odd-password"),
    pytest.param(cred(username="a — b"), id="username-with-separator"),
    pytest.param(cred(title="Mail — personal"), id="title-with-separator"),
    pytest.param(cred(notes="x" * 5000), id="long-notes"),
    pytest.param(
        cred(
            created=datetime(2020, 1, 1, 12, tzinfo=timezone(timedelta(hours=3))),
            modified=datetime(2021, 6, 1, 1, 2, 3, 4, tzinfo=timezone(timedelta(hours=-7))),
        ),
        id="non-utc-timestamps",
    ),
    pytest.param(cred(url="http://localhost:3000"), id="localhost-port"),
    pytest.param(cred(url="android://hash@com.example.app/"), id="non-web-url"),
]


@pytest.mark.parametrize("credential", ROUND_TRIP)
def test_round_trip_is_lossless(credential: Credential) -> None:
    read = read_item(stored_from(credential), new_id=never_called)
    assert read.adopted is False
    assert read.credential == credential
    assert read.credential.content_hash() == credential.content_hash()


def test_attributes_follow_the_spec_table() -> None:
    content = item_content(
        cred(notes="n", otpauth=OTP_URI, alt_urls=("https://a", "https://b")),
        written_at=WRITTEN_AT,
    )
    assert content.attributes == {
        "xdg:schema": SCHEMA,
        "pa-id": "0E6C5D0B-2C55-4E5A-9F7E-6B6C1C0A9D11",
        "url": "https://example.com",
        "server": "example.com",
        "username": "alice",
        "notes": "n",
        "otpauth": OTP_URI,
        "alt-urls": "https://a\nhttps://b",
        "created": "2026-03-01T09:30:15.123456+00:00",
        "modified": "2026-09-01T18:00:00+00:00",
        "pa-synced": str(WRITTEN_AT),
    }
    assert content.secret == FAKE_PW.encode()


def test_password_is_never_an_attribute_or_label() -> None:
    content = item_content(cred(), written_at=WRITTEN_AT)
    assert all(FAKE_PW not in value for value in content.attributes.values())
    assert FAKE_PW not in content.label


def test_absent_optional_fields_leave_no_attribute() -> None:
    attributes = item_content(cred(), written_at=WRITTEN_AT).attributes
    for name in ("title", "notes", "otpauth", "group", "alt-urls"):
        assert name not in attributes


def test_server_attribute_is_the_bare_host() -> None:
    attributes = item_content(
        cred(url="https://Bob@Login.Example.com:8443/x"), written_at=WRITTEN_AT
    ).attributes
    assert attributes["server"] == "login.example.com"


def test_url_without_host_has_no_server_attribute() -> None:
    attributes = item_content(cred(url="https://["), written_at=WRITTEN_AT).attributes
    assert "server" not in attributes


@pytest.mark.parametrize(
    "alt_urls", [("",), ("https://a\nhttps://b",), ("https://ok", "")], ids=repr
)
def test_unrepresentable_alt_urls_are_refused(alt_urls: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="alternative URLs"):
        item_content(cred(alt_urls=alt_urls), written_at=WRITTEN_AT)


@pytest.mark.parametrize(
    "changes",
    [
        {"notes": "before\x00after"},
        {"username": "al\x00ice"},
        {"title": "T\x00"},
        {"group": "\ud800"},
        {"otpauth": "otpauth://totp/x?secret=\x00"},
    ],
    ids=repr,
)
def test_text_dbus_cannot_carry_is_refused(changes: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="NUL"):
        item_content(cred(**changes), written_at=WRITTEN_AT)


@pytest.mark.parametrize(
    ("title", "url", "username", "label"),
    [
        (None, "https://example.com", "alice", f"example.com {E} alice"),
        ("Work", "https://example.com", "alice", f"Work {E} alice"),
        (None, "https://example.com", "", "example.com"),
        ("Work", "https://example.com", "", "Work"),
        ("", "https://example.com", "bob", f"example.com {E} bob"),
        (None, "https://example.com:8443/login", "bob", f"example.com:8443 {E} bob"),
        (None, "https://bob@example.com", "bob", f"example.com {E} bob"),
        (None, "https://[::1]:8080", "root", f"[::1]:8080 {E} root"),
        (None, "https://пример.рф", "алиса", f"пример.рф {E} алиса"),
        (None, "not a url", "x", f"not a url {E} x"),
    ],
)
def test_label_shape(title: str | None, url: str, username: str, label: str) -> None:
    assert make_label(title, url, username) == label


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://example.com/path", "example.com"),
        ("https://user:pw@example.com", "example.com"),
        ("http://10.0.0.1:81", "10.0.0.1:81"),
        ("https://[", "https://["),
        ("example.com", "example.com"),
    ],
)
def test_display_host(url: str, host: str) -> None:
    assert display_host(url) == host


def test_our_labels_parse_back_to_the_same_site_and_user() -> None:
    # A label of ours that lost its attributes (copied around) still adopts correctly.
    original = cred(url="https://example.com:8443", username="alice")
    item = seahorse_item(item_content(original, written_at=WRITTEN_AT).label)
    adopted = read_item(item, new_id=lambda: "NEW").credential
    assert (adopted.url, adopted.username) == (original.url, original.username)


class TestSeahorseEditsOfOurItems:
    def test_renamed_label_becomes_the_title(self) -> None:
        item = stored_from(cred(), label=f"My bank {E} alice")
        assert read_item(item, new_id=never_called).credential.title == "My bank"

    def test_renamed_label_without_username_suffix_is_taken_whole(self) -> None:
        item = stored_from(cred(), label="Personal bank")
        assert read_item(item, new_id=never_called).credential.title == "Personal bank"

    def test_label_reset_to_host_clears_the_title(self) -> None:
        item = stored_from(cred(title="Old"), label="example.com")
        assert read_item(item, new_id=never_called).credential.title is None

    def test_blank_label_clears_the_title(self) -> None:
        item = stored_from(cred(title="Old"), label="   ")
        assert read_item(item, new_id=never_called).credential.title is None

    def test_username_and_url_come_from_attributes_not_label(self) -> None:
        item = stored_from(cred(), label=f"other.example {E} mallory")
        read = read_item(item, new_id=never_called).credential
        assert (read.url, read.username) == ("https://example.com", "alice")
        assert read.title == f"other.example {E} mallory"

    def test_edit_long_after_our_write_bumps_modified(self) -> None:
        edited_at = WRITTEN_AT + 3600
        item = stored_from(cred(modified=T0), modified=edited_at)
        modified = read_item(item, new_id=never_called).credential.modified
        assert modified == datetime.fromtimestamp(edited_at, UTC)

    def test_our_own_write_does_not_count_as_an_edit(self) -> None:
        item = stored_from(cred(modified=T0), modified=WRITTEN_AT + 1)
        assert read_item(item, new_id=never_called).credential.modified == T0

    def test_bump_never_moves_modified_backwards(self) -> None:
        future = datetime.fromtimestamp(WRITTEN_AT + 10_000, UTC)
        item = stored_from(cred(modified=future), modified=WRITTEN_AT + 3600)
        assert read_item(item, new_id=never_called).credential.modified == future

    def test_missing_bookkeeping_falls_back_to_item_times(self) -> None:
        item = stored_from(cred(), drop=("created", "modified", "pa-synced"))
        read = read_item(item, new_id=never_called).credential
        assert read.created == datetime.fromtimestamp(WRITTEN_AT, UTC)
        assert read.modified == datetime.fromtimestamp(WRITTEN_AT, UTC)

    def test_garbage_sync_marker_is_treated_as_never_synced(self) -> None:
        item = stored_from(cred(modified=T0), modified=WRITTEN_AT, extra={"pa-synced": "x"})
        modified = read_item(item, new_id=never_called).credential.modified
        assert modified == datetime.fromtimestamp(WRITTEN_AT, UTC)

    def test_missing_username_attribute_reads_as_empty(self) -> None:
        item = stored_from(cred(username=""), drop=("username",))
        assert read_item(item, new_id=never_called).credential.username == ""

    def test_unknown_attributes_are_ignored(self) -> None:
        item = stored_from(cred(), extra={"chrome-something": "1", "xdg:schema": "other"})
        assert read_item(item, new_id=never_called).credential == cred()


class TestAdoption:
    def test_seahorse_item_is_adopted_from_its_label(self) -> None:
        read = read_item(seahorse_item("alice @ example.com", b"FAKE1"), new_id=lambda: "NEW-ID")
        assert read.adopted is True
        assert read.credential == Credential(
            id="NEW-ID",
            url="https://example.com",
            username="alice",
            password=b"FAKE1".decode(),
            created=datetime.fromtimestamp(1_700_000_000, UTC),
            modified=datetime.fromtimestamp(1_700_000_500, UTC),
        )

    def test_bare_url_label_is_adopted_with_empty_username(self) -> None:
        read = read_item(seahorse_item("https://router.example/admin"), new_id=lambda: "N")
        assert (read.credential.url, read.credential.username) == (
            "https://router.example/admin",
            "",
        )

    def test_our_schema_without_id_is_adopted_from_attributes(self) -> None:
        item = seahorse_item(
            "anything at all",
            attributes={"xdg:schema": SCHEMA, "url": "https://x.example", "username": "bob"},
        )
        read = read_item(item, new_id=lambda: "N").credential
        assert (read.url, read.username, read.title) == (
            "https://x.example",
            "bob",
            "anything at all",
        )

    def test_foreign_schema_url_attribute_is_not_trusted(self) -> None:
        item = seahorse_item("alice @ real.example", attributes={"url": "https://other.example"})
        assert read_item(item, new_id=lambda: "N").credential.url == "https://real.example"

    def test_empty_pa_id_counts_as_missing(self) -> None:
        item = seahorse_item("alice @ example.com", attributes={"pa-id": ""})
        assert read_item(item, new_id=lambda: "FRESH").credential.id == "FRESH"

    def test_our_schema_without_id_keeps_every_known_field(self) -> None:
        full = cred(
            title="Work",
            notes="line1\nline2",
            otpauth=OTP_URI,
            alt_urls=("https://a.example", "https://b.example"),
            group="Team",
        )
        item = stored_from(full, drop=("pa-id",))
        read = read_item(item, new_id=lambda: "NEW-ID")
        assert read.adopted is True
        adopted = read.credential
        assert (adopted.title, adopted.notes, adopted.otpauth, adopted.alt_urls, adopted.group) == (
            full.title,
            full.notes,
            full.otpauth,
            full.alt_urls,
            full.group,
        )

    def test_our_schema_without_id_that_cannot_be_written_back_is_rejected(self) -> None:
        item = seahorse_item(
            "restored",
            attributes={
                "xdg:schema": SCHEMA,
                "url": "https://x.example",
                "alt-urls": "https://a.example\n",
            },
        )
        with pytest.raises(ItemRejectedError, match="alternative URLs"):
            read_item(item, new_id=lambda: "N")

    def test_each_adoption_asks_for_a_new_id(self) -> None:
        ids = iter(["A", "B"])
        first = read_item(seahorse_item("a @ example.com"), new_id=lambda: next(ids))
        second = read_item(seahorse_item("b @ example.com"), new_id=lambda: next(ids))
        assert (first.credential.id, second.credential.id) == ("A", "B")


class TestRejection:
    @pytest.mark.parametrize(
        "label", ["Chrome Safe Storage", "alice@example.com", "", "ftp://example.com"]
    )
    def test_unparseable_seahorse_label(self, label: str) -> None:
        with pytest.raises(ItemRejectedError):
            read_item(seahorse_item(label), new_id=lambda: "N")

    def test_reason_is_the_label_problem(self) -> None:
        with pytest.raises(ItemRejectedError, match="no website"):
            read_item(seahorse_item("Gmail"), new_id=lambda: "N")

    @pytest.mark.parametrize("value", [b"\xff\xfe", b"\x80", b"ok\xc3("], ids=repr)
    def test_binary_secret(self, value: bytes) -> None:
        with pytest.raises(ItemRejectedError, match="not text"):
            read_item(seahorse_item("a @ example.com", value), new_id=lambda: "N")

    def test_our_item_without_url(self) -> None:
        item = stored_from(cred(), drop=("url",))
        with pytest.raises(ItemRejectedError, match="'url'"):
            read_item(item, new_id=never_called)

    @pytest.mark.parametrize("name", ["created", "modified"])
    @pytest.mark.parametrize("value", ["yesterday", "", "2026-13-01T00:00:00+00:00"])
    def test_malformed_timestamp(self, name: str, value: str) -> None:
        item = stored_from(cred(), extra={name: value})
        with pytest.raises(ItemRejectedError, match=name):
            read_item(item, new_id=never_called)

    @pytest.mark.parametrize("name", ["created", "modified"])
    def test_naive_timestamp(self, name: str) -> None:
        item = stored_from(cred(), extra={name: "2026-01-01T00:00:00"})
        with pytest.raises(ItemRejectedError, match="time zone"):
            read_item(item, new_id=never_called)


class TestLazyCreated:
    """A fetch skips reading `Created` for items untouched since our write."""

    @pytest.mark.parametrize(
        ("drop", "extra", "modified", "expected"),
        [
            pytest.param((), {}, WRITTEN_AT, False, id="untouched"),
            pytest.param((), {}, WRITTEN_AT + 2, False, id="within-slack"),
            pytest.param((), {}, WRITTEN_AT + 3, True, id="edited-after-sync"),
            pytest.param(("pa-id",), {}, WRITTEN_AT, True, id="no-id"),
            pytest.param((), {"pa-id": ""}, WRITTEN_AT, True, id="empty-id"),
            pytest.param(("created",), {}, WRITTEN_AT, True, id="no-created"),
            pytest.param(("modified",), {}, WRITTEN_AT, True, id="no-modified"),
            pytest.param(("pa-synced",), {}, WRITTEN_AT, True, id="never-synced"),
            pytest.param((), {"pa-synced": "soon"}, WRITTEN_AT, True, id="garbage-marker"),
        ],
    )
    def test_needs_created(
        self, drop: tuple[str, ...], extra: dict[str, str], modified: int, expected: bool
    ) -> None:
        attributes = stored_from(cred(), drop=drop, extra=extra).attributes
        assert needs_created(attributes, modified) is expected

    def test_rename_within_the_slack_still_becomes_the_title(self) -> None:
        # Modified cannot tell this rename from our own write; the label read must.
        item = replace(stored_from(cred(), label=f"Work VPN {E} alice"), created=None)
        assert read_item(item, new_id=never_called).credential.title == "Work VPN"

    def test_unread_created_without_attribute_is_rejected(self) -> None:
        item = replace(stored_from(cred(), drop=("created",)), created=None)
        with pytest.raises(ItemRejectedError, match="'created' is missing"):
            read_item(item, new_id=never_called)

    def test_adoption_without_created_falls_back_to_modified(self) -> None:
        item = replace(seahorse_item("a @ example.com"), created=None)
        adopted = read_item(item, new_id=lambda: "N").credential
        assert adopted.created == adopted.modified
