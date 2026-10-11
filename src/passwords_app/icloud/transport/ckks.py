# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""CloudKit records of the keychain zones: wire codec and the record operations' payloads.

A CKKS zone holds `tlkshare`, `synckey`, `currentkey`, `item` and `currentitem` records.
`parse_record` and `encode_record` are exact inverses over `CloudKitRecord`; values of a type
this client does not interpret travel as `CKRaw` so a rewrite never drops them.
Field numbers follow CloudKit's CloudDB protobuf (Record, Record.Field, Field.Value).
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from passwords_app.icloud.proto.codec import (
    Fields,
    ProtoError,
    Writer,
    all_bytes,
    as_double,
    as_int64,
    decode_fields,
    first_bytes,
    first_int,
    first_message,
    first_str,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

# Keychain CKKS zones (private DB). "Passwords" holds web logins and their sidecars.
KEYCHAIN_ZONES = (
    "Passwords",
    "Manatee",
    "Engram",
    "SecureObjectSync",
    "ProtectedCloudStorage",
    "CreditCards",
    "ApplePay",
    "WiFi",
    "Home",
    "Groups",
    "Contacts",
    "Mail",
    "LimitedPeersAllowed",
    "SE-PTC",
    "Photos",
)

ID_TYPE_RECORD = 1
ID_TYPE_RECORD_ZONE = 6
ID_TYPE_USER = 7

OP_TYPE_RECORD_SAVE = 210
OP_TYPE_RECORD_RETRIEVE_CHANGES = 213
OP_TYPE_RECORD_DELETE = 214
FIELD_RECORD_SAVE = 210
FIELD_RETRIEVE_CHANGES = 213
FIELD_RECORD_DELETE = 214

# RecordSaveRequest.saveSemantics: 2 creates a record, 3 updates one.
SAVE_CREATE = 2
SAVE_UPDATE = 3

# RetrieveChangesResponse.status: 1 = another page is waiting, 3 = caught up.
STATUS_MORE = 1
STATUS_CAUGHT_UP = 3

REF_WEAK = 2
REF_VALIDATING = 3

# Field.Value.type tags, always written alongside the value.
_T_BYTES, _T_DATE, _T_STRING, _T_REFERENCE, _T_INT64, _T_DOUBLE = 1, 2, 3, 5, 7, 8
_KNOWN_TAGS = frozenset({_T_BYTES, _T_DATE, _T_STRING, _T_REFERENCE, _T_INT64, _T_DOUBLE})


@dataclasses.dataclass(frozen=True, slots=True)
class CKDate:
    """A CloudKit date (UNIX seconds), distinct from a double: the item AAD encodes it as text."""

    time: float


@dataclasses.dataclass(frozen=True, slots=True)
class CKReference:
    """A reference to another record (e.g. `parentkeyref`).

    `zone` is None for the usual target in the referring record's own zone; it is set only when
    the server names another zone, so re-encoding keeps pointing where the server pointed.
    """

    record_name: str
    action: int = REF_VALIDATING
    zone: ZoneId | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class CKRaw:
    """A Field.Value this client does not interpret, kept byte-for-byte."""

    raw: bytes


FieldValue = str | bytes | int | float | CKDate | CKReference | CKRaw


@dataclasses.dataclass(frozen=True, slots=True)
class ZoneId:
    name: str
    owner: str


@dataclasses.dataclass(frozen=True, slots=True)
class CloudKitRecord:
    record_name: str
    type: str
    fields: Mapping[str, FieldValue]
    etag: str | None = None
    zone: ZoneId | None = None

    def get_bytes(self, name: str) -> bytes | None:
        v = self.fields.get(name)
        return v if isinstance(v, bytes) else None

    def get_str(self, name: str) -> str | None:
        v = self.fields.get(name)
        return v if isinstance(v, str) else None

    def get_int(self, name: str) -> int | None:
        v = self.fields.get(name)
        return v if isinstance(v, int) else None

    def get_ref(self, name: str) -> str | None:
        v = self.fields.get(name)
        return v.record_name if isinstance(v, CKReference) else None


@dataclasses.dataclass(frozen=True, slots=True)
class RecordChange:
    """One entry of a zone's change feed; `record` None means the record was deleted."""

    record_name: str
    etag: str | None
    record: CloudKitRecord | None


@dataclasses.dataclass(frozen=True, slots=True)
class ChangesPage:
    changes: tuple[RecordChange, ...]
    continuation_token: bytes | None
    status: int | None

    @property
    def more(self) -> bool:
        return self.status == STATUS_MORE and self.continuation_token is not None


# --- identifiers -----------------------------------------------------------------------------


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


def record_zone_identifier(zone: str, user_id: str) -> bytes:
    return (
        Writer()
        .message(1, _identifier(zone, ID_TYPE_RECORD_ZONE))
        .message(2, _identifier(user_id, ID_TYPE_USER))
        .finish()
    )


def record_identifier(record_name: str, zone: ZoneId) -> bytes:
    return (
        Writer()
        .message(1, _identifier(record_name, ID_TYPE_RECORD))
        .message(2, record_zone_identifier(zone.name, zone.owner))
        .finish()
    )


def _identifier_name(raw: bytes | None) -> str | None:
    return first_str(decode_fields(raw), 1) if raw is not None else None


def parse_zone_identifier(raw: bytes) -> ZoneId:
    """Inverse of `record_zone_identifier`."""
    zf = decode_fields(raw)
    return ZoneId(
        _identifier_name(first_bytes(zf, 1)) or "", _identifier_name(first_bytes(zf, 2)) or ""
    )


def _parse_record_id(raw: bytes) -> tuple[str, ZoneId | None]:
    f = decode_fields(raw)
    name = _identifier_name(first_bytes(f, 1)) or ""
    zone = first_bytes(f, 2)
    return name, parse_zone_identifier(zone) if zone is not None else None


# --- values ----------------------------------------------------------------------------------


def _double_bits(fields: Fields, field: int) -> float | None:
    bits = first_int(fields, field)
    return as_double(bits) if bits is not None else None


def _utf8(raw: bytes | None) -> str | None:
    """`raw` as text, or None when absent or not UTF-8 (then the value is kept as `CKRaw`)."""
    try:
        return raw.decode("utf-8") if raw is not None else None
    except UnicodeDecodeError:
        return None


def parse_value(raw: bytes, zone: ZoneId | None = None) -> FieldValue:
    """Record.Field.Value -> python value, by its type tag (or the field present, untagged).

    A type this module does not model, or a payload that disagrees with its tag, stays `CKRaw`
    so it re-encodes byte for byte instead of being rewritten under another type. A reference
    into a zone other than `zone` (the record's own) keeps that zone.
    """
    v = decode_fields(raw)
    tag = first_int(v, 1)
    if tag is not None and tag not in _KNOWN_TAGS:
        return CKRaw(raw)
    # Tried in this order, each only when the earlier ones found nothing.
    value: FieldValue | None = _scalar_value(v, tag)
    if value is None:
        value = _date_value(v, tag)
    if value is None:
        value = _reference_value(v, tag, zone)
    return CKRaw(raw) if value is None else value


def _scalar_value(v: Fields, tag: int | None) -> bytes | str | int | float | None:
    if tag in {None, _T_BYTES} and (b := first_bytes(v, 2)) is not None:
        return b
    if tag in {None, _T_STRING} and (s := _utf8(first_bytes(v, 7))) is not None:
        return s
    if tag in {None, _T_INT64} and (i := first_int(v, 4)) is not None:
        return as_int64(i)
    if tag in {None, _T_DOUBLE} and (d := _double_bits(v, 5)) is not None:
        return d
    return None


def _date_value(v: Fields, tag: int | None) -> CKDate | None:
    date = first_message(v, 6) if tag in {None, _T_DATE} else None
    if date is not None and (t := _double_bits(date, 1)) is not None:
        return CKDate(t)
    return None


def _reference_value(v: Fields, tag: int | None, zone: ZoneId | None) -> CKReference | None:
    ref = first_message(v, 9) if tag in {None, _T_REFERENCE} else None
    if ref is not None and (rid := first_bytes(ref, 2)) is not None:
        name, target = _parse_record_id(rid)
        foreign = target if target is not None and target != zone else None
        action = first_int(ref, 1)
        return CKReference(name, REF_VALIDATING if action is None else action, foreign)
    return None


def encode_value(value: FieldValue, zone: ZoneId) -> bytes:
    w = Writer()
    match value:
        case CKRaw(raw):
            return raw
        case str():
            w.uint64(1, _T_STRING).string(7, value)
        case bytes():
            w.uint64(1, _T_BYTES).bytes(2, value)
        case int():
            w.uint64(1, _T_INT64).uint64(4, value)
        case float():
            w.uint64(1, _T_DOUBLE).double(5, value)
        case CKDate(time):
            w.uint64(1, _T_DATE).message(6, Writer().double(1, time))
        case CKReference(name, action, target):
            ref = Writer().uint64(1, action).message(2, record_identifier(name, target or zone))
            w.uint64(1, _T_REFERENCE).message(9, ref)
    return w.finish()


# --- records ---------------------------------------------------------------------------------


def parse_record(raw: bytes) -> CloudKitRecord:
    f = decode_fields(raw)
    rid = first_bytes(f, 2)
    name, zone = _parse_record_id(rid) if rid is not None else ("", None)
    type_msg = first_message(f, 3)
    rtype = first_str(type_msg, 1, "") if type_msg is not None else ""
    fields: dict[str, FieldValue] = {}
    for fld in all_bytes(f, 7):
        ff = decode_fields(fld)
        fname = _identifier_name(first_bytes(ff, 1))
        val = first_bytes(ff, 2)
        if fname is not None and val is not None:
            fields[fname] = parse_value(val, zone)
    return CloudKitRecord(name, rtype, fields, etag=first_str(f, 1), zone=zone)


def encode_record(record: CloudKitRecord) -> bytes:
    """Inverse of `parse_record`; the record must carry its zone."""
    if record.zone is None:
        msg = "a record needs its zone to be encoded"
        raise ValueError(msg)
    w = (
        Writer()
        .string(1, record.etag)
        .message(2, record_identifier(record.record_name, record.zone))
        .message(3, Writer().string(1, record.type))
    )
    for name, value in record.fields.items():
        w.message(
            7,
            Writer()
            .message(1, Writer().string(1, name))
            .bytes(2, encode_value(value, record.zone)),
        )
    return w.finish()


# --- operations ------------------------------------------------------------------------------


def build_retrieve_changes_request(
    zone_identifier: bytes, continuation_token: bytes | None = None, max_changes: int = 500
) -> bytes:
    return (
        Writer()
        .bytes(1, continuation_token)
        .message(2, zone_identifier)
        .uint64(4, max_changes)
        .finish()
    )


def parse_retrieve_changes_response(raw: bytes, zone: ZoneId | None = None) -> ChangesPage:
    """One page of a zone's change feed; with `zone`, an entry naming another zone is refused.

    Only the zone name is compared: the owner is how CloudKit spells the account, which a reply
    need not spell the way the request did.
    """
    f = decode_fields(raw)
    # Every other reading of a page that lacks a known status, repeats its status or token, or
    # holds a non-message change would either end the sync early or advance the token past
    # changes never applied.
    for num, what in ((4, "status"), (2, "continuation token")):
        if len(f.get(num, [])) > 1:
            msg = f"change page carries more than one {what}"
            raise ProtoError(msg)
    status = first_int(f, 4)
    if status not in {STATUS_MORE, STATUS_CAUGHT_UP}:
        msg = f"change page has no known status (got {status})"
        raise ProtoError(msg)
    token = first_bytes(f, 2)
    if token is None and f.get(2):
        msg = "change page carries a continuation token that is not bytes"
        raise ProtoError(msg)
    entries = all_bytes(f, 1)
    if len(entries) != len(f.get(1, [])):
        msg = "change page holds an entry that is not a message"
        raise ProtoError(msg)
    changes = tuple(_parse_change(change, zone) for change in entries)
    # An empty token resumes nowhere; asking again with it could loop on the same page.
    return ChangesPage(changes, token or None, status)


def _require_zone(zone: ZoneId | None, *found: ZoneId | None) -> None:
    for z in found:
        if zone is not None and z is not None and z.name and z.name != zone.name:
            # Applying it would delete or overwrite the same-named login of this zone.
            msg = f"change page for {zone.name} carries an entry of zone {z.name}"
            raise ProtoError(msg)


def _parse_change(raw: bytes, zone: ZoneId | None) -> RecordChange:
    cf = decode_fields(raw)
    for num in (1, 2, 5):
        if len(cf.get(num, [])) > 1:
            # Picking one copy of a repeated id, tag or record could delete the wrong login.
            msg = f"change entry repeats its field {num}"
            raise ProtoError(msg)
    rid = first_bytes(cf, 1)
    etag = first_str(cf, 2)
    record = _change_record(cf, etag)
    name, change_zone = _parse_record_id(rid) if rid is not None else ("", None)
    _require_zone(zone, change_zone, record.zone if record is not None else None)
    name = _change_name(name, record)
    return RecordChange(name, etag or (record.etag if record else None), record)


def _change_record(cf: Fields, etag: str | None) -> CloudKitRecord | None:
    """Return a change entry's record (None for a deletion), carrying the entry's tag."""
    rec_raw = first_bytes(cf, 5)
    if rec_raw is None and cf.get(5):
        # Only an absent record means "deleted"; a field of the wrong wire type is damage,
        # and reading it as a deletion would drop the cached login for good.
        msg = "change entry carries a record field that is not a message"
        raise ProtoError(msg)
    record = parse_record(rec_raw) if rec_raw is not None else None
    if record is not None and record.etag is None and etag is not None:
        record = dataclasses.replace(record, etag=etag)
    return record


def _change_name(name: str, record: CloudKitRecord | None) -> str:
    """Return the record name a change entry is about, refusing one it contradicts or lacks."""
    if record is not None:
        if not record.record_name or not record.type:
            msg = "change entry carries a record without a name or type"
            raise ProtoError(msg)
        if name and name != record.record_name:
            msg = f"change for {name} carries record {record.record_name}"
            raise ProtoError(msg)
        name = record.record_name
    if not name:
        # Skipping it would still adopt the page's token, losing this change for good.
        msg = "change entry names no record"
        raise ProtoError(msg)
    return name


def build_save_request(record: CloudKitRecord, *, create: bool) -> bytes:
    """RecordSaveRequest: a create, or an update conditional on the record's change tag.

    The condition is the request's own field 4: Apple ignores the tag inside the record
    (Record field 1) and would overwrite a newer version. A stale tag fails the update with
    client error 15 (oplock), and so does creating a record that already exists.
    """
    return (
        Writer()
        .message(1, encode_record(record))
        .string(4, None if create else record.etag)
        .uint64(6, SAVE_CREATE if create else SAVE_UPDATE)
        .finish()
    )


def parse_save_request(raw: bytes) -> tuple[CloudKitRecord, bool, str | None]:
    """Return a save request's record, whether it creates, and the tag it is conditional on."""
    f = decode_fields(raw)
    rec = first_bytes(f, 1)
    if rec is None:
        msg = "save request without a record"
        raise ValueError(msg)
    return parse_record(rec), first_int(f, 6) == SAVE_CREATE, first_str(f, 4)


def build_delete_request(record_name: str, zone: ZoneId, etag: str | None) -> bytes:
    """RecordDeleteRequest, conditional (field 2) on `etag` unless it is None."""
    return Writer().message(1, record_identifier(record_name, zone)).string(2, etag).finish()


def parse_delete_request(raw: bytes) -> tuple[str, ZoneId | None, str | None]:
    f = decode_fields(raw)
    rid = first_bytes(f, 1)
    if rid is None:
        msg = "delete request without a record id"
        raise ValueError(msg)
    return (*_parse_record_id(rid), first_str(f, 2))


def parse_save_response(raw: bytes) -> str | None:
    """Return the new change tag from RecordSaveResponse.serverFields(4).etag(1)."""
    server = first_message(decode_fields(raw), 4)
    return first_str(server, 1) if server is not None else None


def build_save_response(etag: str) -> bytes:
    return Writer().message(4, Writer().string(1, etag)).finish()


def build_change(record_name: str, zone: ZoneId, etag: str | None, record: bytes | None) -> bytes:
    return (
        Writer()
        .message(1, record_identifier(record_name, zone))
        .string(2, etag)
        .message(5, record)
        .finish()
    )


def build_changes_page(changes: list[bytes], token: bytes | None, status: int) -> bytes:
    w = Writer()
    for c in changes:
        w.message(1, c)
    return w.bytes(2, token).uint64(4, status).finish()
