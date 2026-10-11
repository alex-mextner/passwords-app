# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""CloudKit record codec: hand-built wire fixtures, encoder/parser identity, change feeds."""

from __future__ import annotations

import math
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from passwords_app.icloud.proto import codec as pb
from passwords_app.icloud.transport import ckks

ZONE = ckks.ZoneId("Passwords", "_owner")


def _identifier(name: str, type_: int) -> bytes:
    return pb.Writer().string(1, name).uint64(2, type_).finish()


def _value(field: int, raw: bytes | int | str) -> bytes:
    w = pb.Writer()
    if isinstance(raw, bytes):
        w.bytes(field, raw)
    elif isinstance(raw, str):
        w.string(field, raw)
    else:
        w.uint64(field, raw)
    return w.finish()


def _ref_value(name: str, ref_type: int = 3) -> bytes:
    rec_id = pb.Writer().message(1, _identifier(name, 1)).finish()
    ref = pb.Writer().uint64(1, ref_type).message(2, rec_id).finish()
    return pb.Writer().uint64(1, 5).message(9, ref).finish()


def _record(
    name: str, rtype: str, fields: list[tuple[str, bytes]], etag: str | None = None
) -> bytes:
    rec_id = (
        pb.Writer()
        .message(1, _identifier(name, 1))
        .message(2, ckks.record_zone_identifier(ZONE.name, ZONE.owner))
    )
    w = pb.Writer().string(1, etag).message(2, rec_id).message(3, pb.Writer().string(1, rtype))
    for fname, fval in fields:
        w.message(7, pb.Writer().message(1, _identifier(fname, 0)).message(2, fval))
    return w.finish()


# --- identifiers ---------------------------------------------------------------------------------


def test_zone_identifier_names_zone_and_owner() -> None:
    f = pb.decode_fields(ckks.record_zone_identifier("Passwords", "USER-1"))
    zone = pb.decode_fields(pb.first_bytes(f, 1) or b"")
    owner = pb.decode_fields(pb.first_bytes(f, 2) or b"")
    assert (pb.first_str(zone, 1), pb.first_int(zone, 2)) == ("Passwords", ckks.ID_TYPE_RECORD_ZONE)
    assert (pb.first_str(owner, 1), pb.first_int(owner, 2)) == ("USER-1", ckks.ID_TYPE_USER)


def test_zone_identifier_round_trips() -> None:
    raw = ckks.record_zone_identifier("group-1", "_someone")
    assert ckks.parse_zone_identifier(raw) == ckks.ZoneId("group-1", "_someone")


def test_record_identifier_carries_record_type_and_zone() -> None:
    f = pb.decode_fields(ckks.record_identifier("ABC", ZONE))
    ident = pb.decode_fields(pb.first_bytes(f, 1) or b"")
    assert (pb.first_str(ident, 1), pb.first_int(ident, 2)) == ("ABC", ckks.ID_TYPE_RECORD)
    assert ckks.parse_zone_identifier(pb.first_bytes(f, 2) or b"") == ZONE


# --- parsing hand-built records ------------------------------------------------------------------


def test_parses_item_record_fields_by_type() -> None:
    raw = _record(
        "UUID-item",
        "item",
        [
            ("wrappedkey", _value(7, "d3JhcA==")),
            ("data", _value(2, b"\x00\x01iv+ct")),
            ("encver", _value(4, 2)),
            ("parentkeyref", _ref_value("classC-uuid")),
        ],
        etag="tag-7",
    )
    rec = ckks.parse_record(raw)
    assert (rec.record_name, rec.type, rec.etag, rec.zone) == ("UUID-item", "item", "tag-7", ZONE)
    assert rec.get_str("wrappedkey") == "d3JhcA=="
    assert rec.get_bytes("data") == b"\x00\x01iv+ct"
    assert rec.get_int("encver") == 2
    assert rec.get_ref("parentkeyref") == "classC-uuid"


def test_reference_keeps_its_action() -> None:
    rec = ckks.parse_record(_record("k", "currentkey", [("parentkeyref", _ref_value("K1", 2))]))
    assert rec.fields["parentkeyref"] == ckks.CKReference("K1", ckks.REF_WEAK)


def test_negative_int64_is_signed() -> None:
    rec = ckks.parse_record(_record("i", "item", [("n", _value(4, -5 & (2**64 - 1)))]))
    assert rec.get_int("n") == -5


def test_double_and_date_values() -> None:
    double_bits = int.from_bytes(struct.pack("<d", 2.5), "little")
    date = pb.Writer().message(6, pb.Writer().double(1, 1687305600.0)).finish()
    raw = _record(
        "i", "item", [("score", pb.Writer().uint64(5, double_bits).finish()), ("when", date)]
    )
    rec = ckks.parse_record(raw)
    assert rec.fields["score"] == 2.5
    assert rec.fields["when"] == ckks.CKDate(1687305600.0)


def test_unknown_value_kind_is_kept_raw() -> None:
    asset = pb.Writer().uint64(1, 6).message(10, pb.Writer().string(1, "asset")).finish()
    rec = ckks.parse_record(_record("i", "item", [("blob", asset)]))
    assert rec.fields["blob"] == ckks.CKRaw(asset)


def test_typed_getters_reject_other_types() -> None:
    rec = ckks.CloudKitRecord(
        "r", "item", {"s": "x", "b": b"y", "i": 3, "r": ckks.CKReference("z")}
    )
    assert rec.get_bytes("s") is None
    assert rec.get_str("b") is None
    assert rec.get_int("s") is None
    assert rec.get_ref("s") is None
    assert rec.get_str("missing") is None


def test_record_without_identifier_has_empty_name() -> None:
    rec = ckks.parse_record(pb.Writer().message(3, pb.Writer().string(1, "item")).finish())
    assert (rec.record_name, rec.zone) == ("", None)


def test_truncated_record_raises() -> None:
    raw = _record("i", "item", [("data", _value(2, b"x" * 40))])
    with pytest.raises(pb.ProtoError):
        ckks.parse_record(raw[:-5])


# --- encoder -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "type_tag", "value_field"),
    [
        ("text", 3, 7),
        (b"\x00bytes", 1, 2),
        (42, 7, 4),
        (1.5, 8, 5),
        (ckks.CKDate(1.0), 2, 6),
        (ckks.CKReference("K"), 5, 9),
    ],
)
def test_encoder_tags_every_value_with_its_type(
    value: ckks.FieldValue, type_tag: int, value_field: int
) -> None:
    f = pb.decode_fields(ckks.encode_value(value, ZONE))
    assert pb.first_int(f, 1) == type_tag
    assert value_field in f


def test_reference_encodes_the_zone_of_its_record() -> None:
    raw = ckks.encode_value(ckks.CKReference("K", ckks.REF_VALIDATING), ZONE)
    ref = pb.first_message(pb.decode_fields(raw), 9) or {}
    assert pb.first_int(ref, 1) == ckks.REF_VALIDATING
    rid = pb.first_bytes(ref, 2) or b""
    assert ckks.parse_zone_identifier(pb.first_bytes(pb.decode_fields(rid), 2) or b"") == ZONE


def test_raw_value_is_written_verbatim() -> None:
    raw = b"\x08\x06\x52\x03abc"
    assert ckks.encode_value(ckks.CKRaw(raw), ZONE) == raw


def test_encoding_needs_a_zone() -> None:
    with pytest.raises(ValueError, match="zone"):
        ckks.encode_record(ckks.CloudKitRecord("r", "item", {}))


def test_encoded_hand_fixture_matches_parser() -> None:
    rec = ckks.CloudKitRecord(
        "UUID-item",
        "item",
        {"wrappedkey": "d3JhcA==", "parentkeyref": ckks.CKReference("classC-uuid")},
        etag="tag-7",
        zone=ZONE,
    )
    assert ckks.parse_record(ckks.encode_record(rec)) == rec


_names = st.text(st.characters(codec="utf-8", exclude_categories=["Cs"]), min_size=1, max_size=20)
_values: st.SearchStrategy[ckks.FieldValue] = st.one_of(
    st.text(max_size=40),
    st.binary(max_size=64),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.floats(allow_nan=False),
    st.builds(ckks.CKDate, st.floats(allow_nan=False, allow_infinity=False)),
    st.builds(ckks.CKReference, _names, st.sampled_from([1, 2, 3])),
)


@settings(max_examples=150, deadline=None)
@given(
    name=_names,
    rtype=st.sampled_from(["item", "synckey", "currentkey", "tlkshare"]),
    fields=st.dictionaries(_names, _values, max_size=8),
    etag=st.one_of(st.none(), st.text(min_size=1, max_size=12)),
)
def test_encode_then_parse_is_identity(
    name: str, rtype: str, fields: dict[str, ckks.FieldValue], etag: str | None
) -> None:
    rec = ckks.CloudKitRecord(name, rtype, fields, etag=etag, zone=ZONE)
    back = ckks.parse_record(ckks.encode_record(rec))
    assert back == rec
    for key, value in fields.items():  # -0.0 == 0.0, so check the bits of doubles too
        if isinstance(value, float):
            got = back.fields[key]
            assert isinstance(got, float)
            assert math.copysign(1, got) == math.copysign(1, value)


@settings(max_examples=60, deadline=None)
@given(fields=st.dictionaries(_names, _values, max_size=6))
def test_parse_then_encode_is_byte_identity(fields: dict[str, ckks.FieldValue]) -> None:
    raw = ckks.encode_record(ckks.CloudKitRecord("R", "item", fields, etag="e", zone=ZONE))
    assert ckks.encode_record(ckks.parse_record(raw)) == raw


# --- change feed ---------------------------------------------------------------------------------


def _page(changes: list[bytes], token: bytes | None, status: int) -> bytes:
    return ckks.build_changes_page(changes, token, status)


def test_change_feed_keeps_records_and_deletions_in_order() -> None:
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {"x": 1}, etag="e1", zone=ZONE))
    raw = _page(
        [ckks.build_change("A", ZONE, "e1", rec), ckks.build_change("B", ZONE, None, None)],
        b"TOK",
        3,
    )
    page = ckks.parse_retrieve_changes_response(raw)
    assert [(c.record_name, c.record is None) for c in page.changes] == [("A", False), ("B", True)]
    assert page.continuation_token == b"TOK"
    assert page.status == 3
    assert not page.more


def test_change_of_another_zone_is_refused() -> None:
    other = ckks.ZoneId("OtherZone", ZONE.owner)
    raw = _page([ckks.build_change("A", other, None, None)], b"new", 3)
    with pytest.raises(pb.ProtoError, match="zone OtherZone"):
        ckks.parse_retrieve_changes_response(raw, ZONE)
    assert ckks.parse_retrieve_changes_response(raw).changes[0].record_name == "A"


def test_record_of_another_zone_is_refused() -> None:
    other = ckks.ZoneId("OtherZone", ZONE.owner)
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {}, zone=other))
    raw = _page([pb.Writer().message(5, rec).finish()], None, 3)
    with pytest.raises(pb.ProtoError, match="zone OtherZone"):
        ckks.parse_retrieve_changes_response(raw, ZONE)


@pytest.mark.parametrize(
    "raw",
    [
        pb.Writer().uint64(1, 999).string(7, "opaque-payload").finish(),
        pb.Writer().uint64(1, 1).string(7, "tag says bytes").finish(),
        pb.Writer().uint64(1, 3).bytes(7, b"\xff\xfe").finish(),
    ],
    ids=["unknown-tag", "tag-payload-mismatch", "non-utf8-string"],
)
def test_value_not_matching_a_known_tag_round_trips_raw(raw: bytes) -> None:
    value = ckks.parse_value(raw)
    assert isinstance(value, ckks.CKRaw)
    assert ckks.encode_value(value, ZONE) == raw


def test_reference_action_zero_is_kept() -> None:
    raw = ckks.encode_value(ckks.CKReference("K", 0), ZONE)
    assert ckks.parse_value(raw, ZONE) == ckks.CKReference("K", 0)


def test_reference_into_another_zone_keeps_its_target() -> None:
    other = ckks.ZoneId("OtherZone", "_someone")
    ref = pb.Writer().uint64(1, 1).message(2, ckks.record_identifier("K", other))
    raw = pb.Writer().uint64(1, 5).message(9, ref).finish()
    value = ckks.parse_value(raw, ZONE)
    assert value == ckks.CKReference("K", 1, other)
    assert ckks.encode_value(value, ZONE) == raw
    assert ckks.parse_value(ckks.encode_value(ckks.CKReference("K"), ZONE), ZONE) == (
        ckks.CKReference("K")
    )


@pytest.mark.parametrize("num", [1, 2, 5])
def test_change_repeating_a_field_is_malformed(num: int) -> None:
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {}, zone=ZONE))
    one = {1: ckks.record_identifier("A", ZONE), 2: b"e", 5: rec}
    w = pb.Writer().message(1, one[1]).string(2, "e").message(5, rec)
    raw = w.bytes(num, one[num]).finish()
    with pytest.raises(pb.ProtoError, match=f"repeats its field {num}"):
        ckks.parse_retrieve_changes_response(_page([raw], None, 3))


def test_change_etag_fills_a_record_without_one() -> None:
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {}, zone=ZONE))
    page = ckks.parse_retrieve_changes_response(
        _page([ckks.build_change("A", ZONE, "e9", rec)], None, 3)
    )
    [change] = page.changes
    assert change.etag == "e9"
    assert change.record is not None
    assert change.record.etag == "e9"


def test_record_etag_wins_over_missing_change_etag() -> None:
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {}, etag="inner", zone=ZONE))
    page = ckks.parse_retrieve_changes_response(
        _page([ckks.build_change("A", ZONE, None, rec)], None, 3)
    )
    assert page.changes[0].etag == "inner"


def test_change_without_identifier_uses_record_name() -> None:
    rec = ckks.encode_record(ckks.CloudKitRecord("A", "item", {}, zone=ZONE))
    change = pb.Writer().message(5, rec).finish()
    page = ckks.parse_retrieve_changes_response(_page([change], None, 3))
    assert page.changes[0].record_name == "A"


def test_change_with_no_name_at_all_is_malformed() -> None:
    # Skipping it would let the caller adopt the page token and lose the change for good.
    with pytest.raises(pb.ProtoError, match="names no record"):
        ckks.parse_retrieve_changes_response(_page([pb.Writer().string(2, "e").finish()], None, 3))


@pytest.mark.parametrize(
    ("status", "token", "more"),
    [
        (ckks.STATUS_MORE, b"T", True),
        (ckks.STATUS_MORE, None, False),
        (3, b"T", False),
        (None, b"T", False),
    ],
)
def test_more_needs_status_and_token(status: int | None, token: bytes | None, more: bool) -> None:
    assert ckks.ChangesPage((), token, status).more is more


def test_caught_up_page_without_changes_is_an_empty_final_page() -> None:
    page = ckks.parse_retrieve_changes_response(
        ckks.build_changes_page([], None, ckks.STATUS_CAUGHT_UP)
    )
    assert (page.changes, page.continuation_token, page.more) == ((), None, False)


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (pb.Writer().uint64(4, 3).uint64(4, 1).bytes(2, b"next").finish(), "more than one status"),
        (pb.Writer().uint64(4, 1).bytes(2, b"a").bytes(2, b"b").finish(), "more than one"),
        (pb.Writer().uint64(4, 1).uint64(2, 5).finish(), "not bytes"),
    ],
)
def test_contradictory_page_header_is_malformed(raw: bytes, match: str) -> None:
    with pytest.raises(pb.ProtoError, match=match):
        ckks.parse_retrieve_changes_response(raw)


def test_empty_token_reads_as_no_token() -> None:
    raw = pb.Writer().uint64(4, ckks.STATUS_MORE).bytes(2, b"").finish()
    page = ckks.parse_retrieve_changes_response(raw)
    assert (page.continuation_token, page.more) == (None, False)


def test_retrieve_changes_request_fields() -> None:
    zid = ckks.record_zone_identifier("Passwords", "U")
    f = pb.decode_fields(ckks.build_retrieve_changes_request(zid, b"TOK", max_changes=10))
    assert (pb.first_bytes(f, 1), pb.first_bytes(f, 2), pb.first_int(f, 4)) == (b"TOK", zid, 10)


def test_first_fetch_sends_no_token() -> None:
    f = pb.decode_fields(ckks.build_retrieve_changes_request(ckks.record_zone_identifier("P", "U")))
    assert 1 not in f


# --- save and delete payloads --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("create", "semantics"), [(True, ckks.SAVE_CREATE), (False, ckks.SAVE_UPDATE)]
)
def test_save_request_round_trips(create: bool, semantics: int) -> None:
    rec = ckks.CloudKitRecord("A", "item", {"gen": 0}, etag=None if create else "e1", zone=ZONE)
    raw = ckks.build_save_request(rec, create=create)
    assert pb.first_int(pb.decode_fields(raw), 6) == semantics
    assert ckks.parse_save_request(raw) == (rec, create)


def test_update_carries_the_change_tag_it_is_conditional_on() -> None:
    rec = ckks.CloudKitRecord("A", "item", {}, etag="seen-tag", zone=ZONE)
    saved, _ = ckks.parse_save_request(ckks.build_save_request(rec, create=False))
    assert saved.etag == "seen-tag"


def test_save_request_without_record_is_rejected() -> None:
    with pytest.raises(ValueError, match="record"):
        ckks.parse_save_request(b"")


def test_delete_request_round_trips() -> None:
    raw = ckks.build_delete_request("A", ZONE)
    assert ckks.parse_delete_request(raw) == ("A", ZONE)


def test_delete_request_without_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="record id"):
        ckks.parse_delete_request(b"")


def test_save_response_carries_new_change_tag() -> None:
    assert ckks.parse_save_response(ckks.build_save_response("new")) == "new"
    assert ckks.parse_save_response(b"") is None


def test_password_zones_are_listed() -> None:
    assert {"Passwords", "Manatee"} <= set(ckks.KEYCHAIN_ZONES)
