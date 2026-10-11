# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Credential <-> D-Bus item dicts: which keys appear where, and what Save accepts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from dbus_fast import Variant
from tests.fakes.memory_stores import make_credential
from tests.unit.daemon.otp_fixtures import RFC_SEED, otpauth_uri

from passwords_app.core.model import Credential, TrashEntry
from passwords_app.daemon.errors import InvalidError
from passwords_app.daemon.items import (
    ITEM_KEYS,
    apply_edit,
    from_ms,
    item_dict,
    parse_edit,
    to_ms,
    trash_dict,
)

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
OTPAUTH = otpauth_uri(issuer="Example")
NEW_ID = "00000000-0000-4000-8000-000000000001"
SECRET_PW = "correct-horse-battery"  # noqa: S105 - test data


def plain(d: dict[str, Variant]) -> dict[str, Any]:
    return {k: v.value for k, v in d.items()}


def sigs(d: dict[str, Variant]) -> dict[str, str]:
    return {k: v.signature for k, v in d.items()}


def s(value: str) -> Variant:
    return Variant("s", value)


def create(**values: Variant) -> Credential:
    base = {"url": s("https://example.com"), "username": s("alice"), "password": s("pw")}
    base.update(values)
    return apply_edit(parse_edit(base), None, new_id=NEW_ID, now=NOW)


# ---------------------------------------------------------------- timestamps


@pytest.mark.parametrize(
    ("dt", "ms"),
    [
        (datetime(1970, 1, 1, tzinfo=UTC), 0),
        (datetime(2026, 1, 1, tzinfo=UTC), 1_767_225_600_000),
        (datetime(2026, 1, 1, 0, 0, 0, 999_000, tzinfo=UTC), 1_767_225_600_999),
        (datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC), 1_767_225_600_999),
    ],
)
def test_to_ms_truncates_to_milliseconds(dt: datetime, ms: int) -> None:
    assert to_ms(dt) == ms


def test_to_ms_converts_other_timezones_to_utc() -> None:
    local = datetime(2026, 1, 1, 3, 0, tzinfo=UTC).astimezone()
    assert to_ms(local) == to_ms(datetime(2026, 1, 1, 3, 0, tzinfo=UTC))


@pytest.mark.parametrize("ms", [0, 1, 1_767_225_600_123, 4_102_444_800_000])
def test_from_ms_round_trips(ms: int) -> None:
    assert to_ms(from_ms(ms)) == ms
    assert from_ms(ms).tzinfo is UTC


# ---------------------------------------------------------------- item_dict


def test_item_dict_without_secrets_has_exactly_the_public_keys() -> None:
    c = make_credential("A", otpauth=OTPAUTH, title="Mail", notes="n", group="G")
    assert set(item_dict(c)) == set(ITEM_KEYS) - {"password", "otpauth"}


def test_item_dict_with_secrets_adds_password_and_otpauth() -> None:
    c = make_credential("A", otpauth=OTPAUTH)
    d = plain(item_dict(c, secrets=True))
    assert d["password"] == "pw-A"  # noqa: S105 - test data
    assert d["otpauth"] == OTPAUTH


def test_item_dict_never_carries_password_or_seed_by_default() -> None:
    c = make_credential("A", password=SECRET_PW, otpauth=OTPAUTH)
    flat = repr(item_dict(c))
    assert SECRET_PW not in flat
    assert RFC_SEED not in flat


def test_item_dict_signatures_match_the_interface() -> None:
    c = make_credential("A", alt_urls=("https://b.example.com",))
    assert sigs(item_dict(c, secrets=True)) == {
        "id": "s",
        "url": "s",
        "username": "s",
        "title": "s",
        "notes": "s",
        "alt_urls": "as",
        "group": "s",
        "created": "x",
        "modified": "x",
        "has_code": "b",
        "password": "s",
        "otpauth": "s",
    }


def test_item_dict_maps_none_to_empty_strings() -> None:
    d = plain(item_dict(make_credential("A"), secrets=True))
    assert (d["title"], d["notes"], d["group"], d["otpauth"]) == ("", "", "", "")


@pytest.mark.parametrize(("otpauth", "has_code"), [(None, False), (OTPAUTH, True)])
def test_has_code_reflects_otpauth(otpauth: str | None, *, has_code: bool) -> None:
    assert plain(item_dict(make_credential("A", otpauth=otpauth)))["has_code"] is has_code


def test_item_dict_values() -> None:
    c = make_credential(
        "A",
        url="https://mail.example.com",
        username="bob",
        title="Mail",
        notes="note",
        alt_urls=("https://a.example.com", "https://b.example.com"),
        group="Family",
        modified=60,
    )
    d = plain(item_dict(c))
    assert d["id"] == "A"
    assert d["url"] == "https://mail.example.com"
    assert d["username"] == "bob"
    assert d["title"] == "Mail"
    assert d["notes"] == "note"
    assert d["alt_urls"] == ["https://a.example.com", "https://b.example.com"]
    assert d["group"] == "Family"
    assert d["created"] == to_ms(c.created)
    assert d["modified"] == to_ms(c.created) + 60_000


# ---------------------------------------------------------------- trash_dict


def test_trash_dict_layout_and_expiry() -> None:
    c = make_credential("A", password=SECRET_PW, otpauth=OTPAUTH)
    entry = TrashEntry("T1", c, NOW, "deleted-in-icloud")
    d = trash_dict(entry, timedelta(days=90))
    assert sigs(d) == {
        "trash_id": "s",
        "reason": "s",
        "deleted_at": "x",
        "expires_at": "x",
        "item": "a{sv}",
    }
    values = plain(d)
    assert values["trash_id"] == "T1"
    assert values["reason"] == "deleted-in-icloud"
    assert values["deleted_at"] == to_ms(NOW)
    assert values["expires_at"] == to_ms(NOW + timedelta(days=90))
    item = values["item"]
    assert "password" not in item
    assert "otpauth" not in item
    assert item["id"].value == "A"
    assert item["has_code"].value is True
    assert SECRET_PW not in repr(d)


@pytest.mark.parametrize(
    "reason", ["deleted-in-icloud", "deleted-on-linux", "deleted-both", "conflict"]
)
def test_trash_dict_passes_every_reason_through(reason: Any) -> None:
    entry = TrashEntry("T", make_credential("A"), NOW, reason)
    assert plain(trash_dict(entry, timedelta(days=1)))["reason"] == reason


# ---------------------------------------------------------------- parse_edit: shape


@pytest.mark.parametrize(
    "key", ["password_hint", "ID", "Url", "pass", "favorite", "", "item", "trash_id"]
)
def test_unknown_keys_are_rejected(key: str) -> None:
    with pytest.raises(InvalidError, match="unknown key"):
        parse_edit({key: s("x")})


@pytest.mark.parametrize(
    ("key", "variant"),
    [
        ("id", Variant("i", 1)),
        ("url", Variant("as", ["https://example.com"])),
        ("username", Variant("b", True)),  # noqa: FBT003 - D-Bus boolean literal
        ("password", Variant("ay", b"pw")),
        ("title", Variant("u", 3)),
        ("notes", Variant("x", 3)),
        ("otpauth", Variant("as", [])),
        ("alt_urls", s("https://example.com")),
        ("group", Variant("o", "/x")),
        ("created", s("2026-01-01")),
        ("modified", Variant("t", 1)),
        ("has_code", s("true")),
    ],
)
def test_wrong_types_are_rejected(key: str, variant: Variant) -> None:
    with pytest.raises(InvalidError, match=key):
        parse_edit({key: variant})


@pytest.mark.parametrize("key", ["created", "modified", "has_code"])
def test_read_only_keys_are_accepted_but_ignored(key: str) -> None:
    value = Variant("b", True) if key == "has_code" else Variant("x", 0)  # noqa: FBT003
    c = create(**{key: value})
    assert c.created == NOW
    assert c.modified == NOW


def test_error_messages_never_echo_values() -> None:
    with pytest.raises(InvalidError) as info:
        parse_edit({"password": Variant("as", [SECRET_PW])})
    assert SECRET_PW not in str(info.value)
    with pytest.raises(InvalidError) as info:
        parse_edit({SECRET_PW: s(SECRET_PW)})
    assert SECRET_PW not in str(info.value)


@pytest.mark.parametrize(("raw", "expected"), [(None, None), ("", None), ("ID-9", "ID-9")])
def test_target_id(raw: str | None, expected: str | None) -> None:
    values = {} if raw is None else {"id": s(raw)}
    assert parse_edit(values).item_id == expected


# ---------------------------------------------------------------- apply_edit: create


def test_create_builds_a_credential_with_the_new_id_and_now() -> None:
    c = create(title=s("Mail"), notes=s("n"))
    assert c.id == NEW_ID
    assert c.created == c.modified == NOW
    assert (c.username, c.password, c.title, c.notes) == ("alice", "pw", "Mail", "n")


@pytest.mark.parametrize("missing", ["url", "password"])
def test_create_requires_url_and_password(missing: str) -> None:
    values = {"url": s("https://example.com"), "username": s("a"), "password": s("pw")}
    del values[missing]
    with pytest.raises(InvalidError, match=missing):
        apply_edit(parse_edit(values), None, new_id=NEW_ID, now=NOW)


def test_create_allows_an_empty_username() -> None:
    assert create(username=s("")).username == ""


def test_create_defaults_username_to_empty() -> None:
    values = {"url": s("https://example.com"), "password": s("pw")}
    assert apply_edit(parse_edit(values), None, new_id=NEW_ID, now=NOW).username == ""


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("example.com", "https://example.com"),
        ("https://Example.COM/", "https://example.com"),
        ("https://example.com:443/login?next=/x#frag", "https://example.com/login"),
        ("http://192.168.1.1:8080", "http://192.168.1.1:8080"),
        ("https://someone@example.com", "https://example.com"),
        ("https://пример.рф", "https://xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_urls_are_normalized(raw: str, normalized: str) -> None:
    assert create(url=s(raw)).url == normalized


@pytest.mark.parametrize("raw", ["", "   ", "https://", "mailto:x@example.com"])
def test_unusable_urls_are_invalid(raw: str) -> None:
    with pytest.raises(InvalidError, match="url"):
        create(url=s(raw))


def test_empty_password_is_invalid() -> None:
    with pytest.raises(InvalidError, match="password"):
        create(password=s(""))


@pytest.mark.parametrize("key", ["title", "notes", "group", "otpauth"])
def test_empty_optional_strings_become_none(key: str) -> None:
    assert getattr(create(**{key: s("")}), key) is None


def test_valid_otpauth_is_kept_verbatim() -> None:
    assert create(otpauth=s(OTPAUTH)).otpauth == OTPAUTH


@pytest.mark.parametrize(
    "bad",
    [
        otpauth_uri(kind="hotp"),
        otpauth_uri(seed=None),
        otpauth_uri(seed="!!!"),
        "https://example.com",
        otpauth_uri(digits="12"),
    ],
)
def test_invalid_otpauth_is_rejected_without_echoing_it(bad: str) -> None:
    with pytest.raises(InvalidError, match="verification code") as info:
        create(otpauth=s(bad))
    assert RFC_SEED not in str(info.value)


def test_alt_urls_are_normalized_and_deduplicated_in_order() -> None:
    c = create(
        alt_urls=Variant(
            "as", ["b.example.com", "https://a.example.com/", "https://b.example.com", ""]
        )
    )
    assert c.alt_urls == ("https://b.example.com", "https://a.example.com")


def test_alt_urls_reject_garbage() -> None:
    with pytest.raises(InvalidError, match="alt_urls"):
        create(alt_urls=Variant("as", ["mailto:x@example.com"]))


# ---------------------------------------------------------------- apply_edit: update


def test_update_keeps_omitted_fields_and_bumps_modified() -> None:
    old = make_credential("ID-1", title="Old", notes="keep", otpauth=OTPAUTH)
    new = apply_edit(parse_edit({"id": s("ID-1"), "title": s("New")}), old, new_id=NEW_ID, now=NOW)
    assert new.id == "ID-1"
    assert new.title == "New"
    assert new.notes == "keep"
    assert new.otpauth == OTPAUTH
    assert new.password == old.password
    assert new.created == old.created
    assert new.modified == NOW


def test_update_can_clear_optional_fields() -> None:
    old = make_credential("ID-1", title="Old", otpauth=OTPAUTH, alt_urls=("https://x.example",))
    changes = {
        "id": s("ID-1"),
        "title": s(""),
        "otpauth": s(""),
        "alt_urls": Variant("as", []),
    }
    new = apply_edit(parse_edit(changes), old, new_id=NEW_ID, now=NOW)
    assert (new.title, new.otpauth, new.alt_urls) == (None, None, ())


def test_update_rejects_emptying_the_password() -> None:
    old = make_credential("ID-1")
    with pytest.raises(InvalidError, match="password"):
        apply_edit(parse_edit({"id": s("ID-1"), "password": s("")}), old, new_id=NEW_ID, now=NOW)


def test_update_without_changes_keeps_modified() -> None:
    old = make_credential("ID-1", title="Same")
    new = apply_edit(parse_edit({"id": s("ID-1"), "title": s("Same")}), old, new_id=NEW_ID, now=NOW)
    assert new == old


def test_update_against_a_different_item_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="does not match"):
        apply_edit(parse_edit({"id": s("A")}), make_credential("B"), new_id=NEW_ID, now=NOW)
