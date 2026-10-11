# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Item records both ways: AAD v2, key hierarchy, and encrypt -> decrypt identity."""

# pyright: reportPrivateUsage=false
# The little-endian integer encoder is checked directly against the wire layout.

from __future__ import annotations

import base64
import dataclasses
import math
import os
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.fakes.cloudkit_server import ZoneKeys, ecies_encrypt_sf, keyed_archive

from passwords_app.icloud.keychain import crypto as kc
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.proto import codec as pb
from passwords_app.icloud.transport import ckks

ZONE = ckks.ZoneId("Passwords", "_owner")
KEYS = ZoneKeys.generate()
RING = KEYS.keyring(ZONE.name)
CLASS_A = KEYS.class_keys["classA"][0]
CLASS_C = KEYS.class_keys["classC"][0]
ATTRS: dict[str, object] = {
    "class": "inet",
    "agrp": "com.apple.cfnetwork",
    "pdmn": "ak",
    "acct": "alice",
    "srvr": "example.com",
    "v_Data": b"hunter2",
    "cdat": datetime(2024, 5, 6, 7, 8, 9, tzinfo=UTC),
}


# --- AAD -------------------------------------------------------------------------------------


def test_aad_fixed_keys_in_sorted_order() -> None:
    aad = pipeline.authenticated_data_v2("U-1", {}, encver=2, gen=7, parent_key_id="PK")
    # sorted keys: UUID, encver, gen, wrappedkey (uppercase sorts first)
    assert aad == [b"U-1", (2).to_bytes(8, "little"), (7).to_bytes(8, "little"), b"PK"]


def test_aad_includes_pcs_fields() -> None:
    fields: dict[str, ckks.FieldValue] = {
        "pcsservice": 5,
        "pcspublicidentity": b"ident",
        "pcspublickey": b"pub",
        "wrappedkey": "ignored",
        "data": b"ignored",
    }
    aad = pipeline.authenticated_data_v2("U", fields, encver=2, gen=0, parent_key_id="C")
    assert b"ident" in aad
    assert b"pub" in aad
    assert (5).to_bytes(8, "little") in aad
    assert b"ignored" not in aad


def test_aad_negative_int_is_twos_complement() -> None:
    aad = pipeline.authenticated_data_v2("U", {"n": -1}, encver=2, gen=0, parent_key_id="C")
    assert b"\xff" * 8 in aad


def test_aad_encodes_dates_as_rfc3339_and_truncates_doubles() -> None:
    fields: dict[str, ckks.FieldValue] = {"cdat": ckks.CKDate(1687305600.0), "score": 3.9}
    aad = pipeline.authenticated_data_v2("U", fields, encver=2, gen=0, parent_key_id="C")
    assert b"2023-06-21T00:00:00Z" in aad
    assert (3).to_bytes(8, "little") in aad


def test_aad_skips_references_raw_values_and_server_fields() -> None:
    fields: dict[str, ckks.FieldValue] = {
        "parentkeyref": ckks.CKReference("C"),
        "other": ckks.CKReference("X"),
        "asset": ckks.CKRaw(b"\x01\x02"),
        "server_wascurrent": 1,
    }
    base = pipeline.authenticated_data_v2("U", {}, encver=2, gen=0, parent_key_id="C")
    assert pipeline.authenticated_data_v2("U", fields, encver=2, gen=0, parent_key_id="C") == base


def test_le8_masks_to_64_bits() -> None:
    assert pipeline._le8(0xFFFFFFFFFFFFFFFF) == b"\xff" * 8
    assert pipeline._le8(2) == b"\x02" + b"\x00" * 7


# --- key hierarchy ---------------------------------------------------------------------------


def test_keyring_unwraps_synckeys_and_indexes_current_keys() -> None:
    ring = pipeline.build_keyring(
        [r for r in KEYS.records(ZONE) if r.type == "synckey"],
        [r for r in KEYS.records(ZONE) if r.type == "currentkey"],
        {KEYS.tlk_id: KEYS.tlk},
    )
    assert ring.key(CLASS_A) == KEYS.class_keys["classA"][1]
    assert ring.current_key("Passwords", "classC") == CLASS_C


def test_synckeys_without_their_tlk_are_left_out() -> None:
    ring = pipeline.build_keyring(KEYS.records(ZONE), [], {"other-tlk": os.urandom(64)})
    assert ring.keys == {}
    with pytest.raises(kc.KeychainCryptoError, match="no class key"):
        ring.key(CLASS_A)


def test_a_synckey_that_does_not_open_is_left_out() -> None:
    good = [r for r in KEYS.records(ZONE) if r.type == "synckey"]
    bad = dataclasses.replace(
        good[0],
        record_name="POISON",
        fields={**good[0].fields, "wrappedkey": base64.b64encode(os.urandom(80)).decode()},
    )
    ring = pipeline.build_keyring([bad, *good], [], {KEYS.tlk_id: KEYS.tlk})
    assert "POISON" not in ring.keys
    assert {r.record_name for r in good} <= set(ring.keys)


@pytest.mark.parametrize(
    "value", [math.nan, math.inf, ckks.CKDate(math.nan), ckks.CKDate(1e300)], ids=str
)
def test_unauthenticatable_number_is_a_crypto_error(value: ckks.FieldValue) -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    bad = dataclasses.replace(rec, fields={**rec.fields, "score": value})
    with pytest.raises(kc.KeychainCryptoError, match="cannot be authenticated"):
        pipeline.decrypt_item(bad, RING)


def test_current_key_must_be_known() -> None:
    ring = pipeline.KeyRing({}, {("Passwords", "classA"): "missing"})
    with pytest.raises(kc.KeychainCryptoError, match="no current classA key"):
        ring.current_key("Passwords", "classA")
    with pytest.raises(kc.KeychainCryptoError):
        ring.current_key("Other", "classA")


def test_tlkshares_for_other_peers_and_poisoned_shares_are_skipped() -> None:
    mine = ec.generate_private_key(ec.SECP384R1())
    good = KEYS.share_for(ZONE, "me", mine.public_key())
    for_other = KEYS.share_for(ZONE, "someone", mine.public_key())
    poisoned = dataclasses.replace(
        good,
        record_name="bad",
        fields={**good.fields, "wrappedkey": base64.b64encode(b"junk").decode()},
    )
    wrong_key = KEYS.share_for(ZONE, "me", ec.generate_private_key(ec.SECP384R1()).public_key())
    tlks = pipeline.unwrap_tlkshares([poisoned, for_other, wrong_key, good], "me", mine)
    assert tlks == {KEYS.tlk_id: KEYS.tlk}


def test_share_that_opens_to_a_damaged_key_id_is_skipped() -> None:
    mine = ec.generate_private_key(ec.SECP384R1())
    good = KEYS.share_for(ZONE, "me", mine.public_key())
    serialized = pb.Writer().bytes(1, b"\xff\xff").bytes(4, b"k" * 32).finish()
    archive = keyed_archive(ecies_encrypt_sf(mine.public_key(), serialized))
    damaged = dataclasses.replace(
        good,
        record_name="damaged",
        fields={**good.fields, "wrappedkey": base64.b64encode(archive).decode()},
    )
    assert pipeline.unwrap_tlkshares([damaged, good], "me", mine) == {KEYS.tlk_id: KEYS.tlk}


@pytest.mark.parametrize(
    ("pdmn", "key_class"), [("ak", "classA"), ("ck", "classC"), ("dk", "classC")]
)
def test_key_class_follows_accessibility(pdmn: str, key_class: str) -> None:
    assert pipeline.key_class_for({"pdmn": pdmn}) == key_class


@pytest.mark.parametrize("pdmn", ["aku", "cku", None, 1])
def test_unknown_accessibility_has_no_key_class(pdmn: object) -> None:
    with pytest.raises(kc.KeychainCryptoError, match="key class"):
        pipeline.key_class_for({"pdmn": pdmn})


# --- encrypt / decrypt ---------------------------------------------------------------------------


def test_new_item_record_shape() -> None:
    rec = pipeline.encrypt_item(ATTRS, "REC-1", ZONE, RING)
    assert (rec.record_name, rec.type, rec.zone, rec.etag) == ("REC-1", "item", ZONE, None)
    assert rec.fields["parentkeyref"] == ckks.CKReference(CLASS_A, ckks.REF_VALIDATING)
    assert rec.get_int("gen") == 0
    assert rec.get_int("encver") == 2
    assert isinstance(rec.get_str("uploadver"), str)
    wrapped = rec.get_str("wrappedkey")
    assert wrapped is not None
    assert len(base64.b64decode(wrapped)) == kc.WRAPPED_KEY_SIZE


def test_class_c_item_uses_the_class_c_key() -> None:
    rec = pipeline.encrypt_item({**ATTRS, "pdmn": "ck"}, "R", ZONE, RING)
    assert rec.get_ref("parentkeyref") == CLASS_C


def test_round_trip_through_the_wire_encoding() -> None:
    rec = pipeline.encrypt_item(ATTRS, "REC-1", ZONE, RING)
    back = ckks.parse_record(ckks.encode_record(rec))
    assert pipeline.decrypt_item(back, RING) == ATTRS


def test_update_keeps_change_tag_gen_and_extra_fields() -> None:
    first = dataclasses.replace(
        pipeline.encrypt_item(ATTRS, "R", ZONE, RING),
        etag="tag-1",
        fields={
            **pipeline.encrypt_item(ATTRS, "R", ZONE, RING).fields,
            "gen": 4,
            "futurefield": "kept",
            "server_wascurrent": 1,
        },
    )
    second = pipeline.encrypt_item({**ATTRS, "v_Data": b"new"}, "R", ZONE, RING, previous=first)
    assert second.etag == "tag-1"
    assert second.get_int("gen") == 4
    assert second.fields["futurefield"] == "kept"
    assert "server_wascurrent" not in second.fields
    assert pipeline.decrypt_item(second, RING)["v_Data"] == b"new"


def test_extra_fields_are_authenticated() -> None:
    prev = ckks.CloudKitRecord("R", "item", {"futurefield": "kept"}, etag="t", zone=ZONE)
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING, previous=prev)
    tampered = dataclasses.replace(rec, fields={**rec.fields, "futurefield": "changed"})
    with pytest.raises(kc.KeychainCryptoError):
        pipeline.decrypt_item(tampered, RING)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gen", 9),
        ("encver", 1),
        ("encver", 0),
        ("wrappedkey", base64.b64encode(os.urandom(80)).decode()),
    ],
)
def test_tampered_metadata_fails_to_decrypt(field: str, value: ckks.FieldValue) -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    with pytest.raises(kc.KeychainCryptoError):
        pipeline.decrypt_item(dataclasses.replace(rec, fields={**rec.fields, field: value}), RING)


def test_renamed_record_fails_to_decrypt() -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    with pytest.raises(kc.KeychainCryptoError):
        pipeline.decrypt_item(dataclasses.replace(rec, record_name="OTHER"), RING)


@pytest.mark.parametrize("missing", ["data", "wrappedkey", "parentkeyref"])
def test_item_without_key_or_data_is_unreadable(missing: str) -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    fields = {k: v for k, v in rec.fields.items() if k != missing}
    with pytest.raises(kc.KeychainCryptoError, match="missing"):
        pipeline.decrypt_item(dataclasses.replace(rec, fields=fields), RING)


def test_non_base64_wrapped_key_is_unreadable() -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    with pytest.raises(kc.KeychainCryptoError, match="base64"):
        pipeline.decrypt_item(
            dataclasses.replace(rec, fields={**rec.fields, "wrappedkey": "@@"}), RING
        )


def test_item_from_unknown_class_key_is_unreadable() -> None:
    rec = pipeline.encrypt_item(ATTRS, "R", ZONE, RING)
    other = pipeline.KeyRing({}, {})
    with pytest.raises(kc.KeychainCryptoError, match="no class key"):
        pipeline.decrypt_item(rec, other)


def test_plaintext_that_is_not_a_dictionary_is_unreadable() -> None:
    item_key = kc.new_item_key()
    aad = pipeline.authenticated_data_v2("R", {}, encver=2, gen=0, parent_key_id=CLASS_A)
    fields: dict[str, ckks.FieldValue] = {
        "parentkeyref": ckks.CKReference(CLASS_A),
        "data": kc.encrypt_item(item_key, b"\x00not a plist", aad),
        "wrappedkey": base64.b64encode(kc.wrap_item_key(RING.key(CLASS_A), item_key)).decode(),
        "gen": 0,
        "encver": 2,
    }
    with pytest.raises(kc.KeychainCryptoError, match="property list"):
        pipeline.decrypt_item(ckks.CloudKitRecord("R", "item", fields, zone=ZONE), RING)


_plist_scalars = st.one_of(
    st.text(max_size=30),
    st.binary(max_size=40),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.booleans(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.datetimes(
        min_value=datetime(1990, 1, 1),  # noqa: DTZ001 - hypothesis needs naive bounds
        max_value=datetime(2100, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    ).map(lambda d: d.replace(microsecond=0)),
)
_plists = st.recursive(
    _plist_scalars,
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=12,
)


@settings(max_examples=80, deadline=None)
@given(
    extra=st.dictionaries(st.text(min_size=1, max_size=10), _plists, max_size=8),
    pdmn=st.sampled_from(["ak", "ck", "dk"]),
)
def test_encrypt_then_decrypt_is_identity_for_any_item(extra: dict[str, object], pdmn: str) -> None:
    attrs = {**extra, "pdmn": pdmn}
    rec = pipeline.encrypt_item(attrs, "R", ZONE, RING)
    assert pipeline.decrypt_item(ckks.parse_record(ckks.encode_record(rec)), RING) == attrs
