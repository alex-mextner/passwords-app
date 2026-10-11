# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Keychain item crypto over CloudKit records, both directions.

Read: tlkshare -> TLK -> class key (synckey) -> item key (wrappedkey) -> item plist (data).
Write is the exact inverse (Apple Security, CKKSItem.m / CKKSItemEncrypter.m): a fresh item key
wrapped by the zone's *current* key of the class `pdmn` selects, the plist sealed with the
item's authenticated metadata (AAD v2), `gen` kept from the previous version.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import plistlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from passwords_app.icloud.keychain import crypto as kc
from passwords_app.icloud.keychain import nska
from passwords_app.icloud.proto.codec import ProtoError, decode_fields, first_bytes, first_str
from passwords_app.icloud.transport.ckks import (
    REF_VALIDATING,
    CKDate,
    CKReference,
    CloudKitRecord,
    FieldValue,
    ZoneId,
)
from passwords_app.icloud.values import PLIST_ERRORS

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cryptography.hazmat.primitives.asymmetric import ec

ENCRYPTION_VERSION = 2
# Item-record fields that are never part of the per-item authenticated data.
_AAD_EXCLUDED = frozenset(
    {
        "gen",
        "pcspublickey",
        "UUID",
        "data",
        "pcsservice",
        "pcspublicidentity",
        "parentkeyref",
        "uploadver",
        "wrappedkey",
        "encver",
    }
)
# What a writer may set on an item record; every other non-server field is carried over.
_ITEM_FIELDS = frozenset({"data", "wrappedkey", "parentkeyref", "gen", "encver", "uploadver"})
# pdmn (accessibility) -> the key class that protects it (CKKSOutgoingQueueEntry.m).
_KEY_CLASS = {"ak": "classA", "dk": "classC", "ck": "classC"}
UPLOAD_VERSION = "Linux passwords-app"

ItemAttributes = dict[str, object]


def _le8(n: int) -> bytes:
    """64-bit two's-complement little-endian; masks so proto int64 negatives never overflow."""
    return (int(n) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def authenticated_data_v2(
    uuid: str, fields: Mapping[str, FieldValue], *, encver: int, gen: int, parent_key_id: str
) -> list[bytes]:
    """AES-SIV associated data of an `item` record: values of a by-key-sorted map."""
    aad: dict[str, bytes] = {
        "UUID": uuid.encode(),
        "encver": _le8(encver),
        "gen": _le8(gen),
        "wrappedkey": parent_key_id.encode(),  # the parent class key's id, not the wrapped key
    }
    aad.update(_pcs_aad(fields))
    for name, val in fields.items():
        if name in _AAD_EXCLUDED or name.startswith("server_"):
            continue
        value = _aad_value(val)
        if value is not None:
            aad[name] = value
    return [aad[k] for k in sorted(aad)]


def _pcs_aad(fields: Mapping[str, FieldValue]) -> dict[str, bytes]:
    """Return the PCS fields' associated data, which the general rule leaves out."""
    aad: dict[str, bytes] = {}
    service = fields.get("pcsservice")
    if isinstance(service, int):
        aad["pcsservice"] = _le8(service)
    for pcs in ("pcspublicidentity", "pcspublickey"):
        v = fields.get(pcs)
        if isinstance(v, bytes):
            aad[pcs] = v
    return aad


def _aad_value(val: FieldValue) -> bytes | None:
    """Return a field's associated-data bytes, or None for a value that is not authenticated."""
    match val:
        case str():
            return val.encode()
        case bytes():
            return val
        case CKDate(time):
            stamp = datetime.fromtimestamp(int(time), tz=UTC)
            return stamp.strftime("%Y-%m-%dT%H:%M:%SZ").encode()
        case float() | int():
            return _le8(int(val))
        case _:
            return None  # references and opaque values are not authenticated


def unwrap_tlkshares(
    tlkshares: Iterable[CloudKitRecord],
    our_peer_id: str,
    our_encryption_key: ec.EllipticCurvePrivateKey,
) -> dict[str, bytes]:
    """Return {tlk uuid: TLK} for every share addressed to us that opens with our key.

    A share's `wrappedkey` ECIES-decrypts to a `CuttlefishSerializedKey` {uuid(1), zoneName(2),
    keyclass(3), key(4)}. Shares that do not open are skipped: any peer can upload one, so a
    poisoned share must not block the others. A missing TLK surfaces later, when an item needs it.
    """
    tlks: dict[str, bytes] = {}
    for share in tlkshares:
        wrapped = share.get_str("wrappedkey")
        if share.get_str("receiver") != our_peer_id or not wrapped:
            continue
        try:
            ies = nska.expand(base64.b64decode(wrapped))
            serialized = kc.ecies_decrypt_sf(our_encryption_key, ies)
            f = decode_fields(serialized)
            key_id, tlk = first_str(f, 1), first_bytes(f, 4)
        except (binascii.Error, ValueError, kc.KeychainCryptoError, ProtoError, KeyError):
            continue
        if key_id and tlk:
            tlks[key_id] = tlk
    return tlks


@dataclasses.dataclass(frozen=True, slots=True)
class KeyRing:
    """Class keys by synckey id, and each zone's current key per class."""

    keys: Mapping[str, bytes]
    current: Mapping[tuple[str, str], str]  # (zone, key class) -> synckey id

    def key(self, key_id: str) -> bytes:
        key = self.keys.get(key_id)
        if key is None:
            msg = f"no class key {key_id}"
            raise kc.KeychainCryptoError(msg)
        return key

    def current_key(self, zone: str, key_class: str) -> str:
        key_id = self.current.get((zone, key_class))
        if key_id is None or key_id not in self.keys:
            msg = f"no current {key_class} key for zone {zone}"
            raise kc.KeychainCryptoError(msg)
        return key_id


def build_keyring(
    synckeys: Iterable[CloudKitRecord],
    currentkeys: Iterable[CloudKitRecord],
    tlks: Mapping[str, bytes],
) -> KeyRing:
    """Unwrap each synckey with its parent TLK and index the zones' `currentkey` pointers."""
    keys: dict[str, bytes] = {}
    for sk in synckeys:
        parent = sk.get_ref("parentkeyref")
        wrapped = sk.get_str("wrappedkey")
        tlk = tlks.get(parent) if parent else None
        if tlk is None or not wrapped:
            continue
        try:
            keys[sk.record_name] = kc.siv_unwrap(tlk, _b64(wrapped))
        except kc.KeychainCryptoError:
            # Any peer can upload a synckey; one that does not open must not take the others
            # down. Items under it then fail on their own, which still fails the zone read.
            continue
    current: dict[tuple[str, str], str] = {}
    for ck in currentkeys:
        target = ck.get_ref("parentkeyref")
        if target and ck.zone is not None:
            current[ck.zone.name, ck.record_name] = target
    return KeyRing(keys, current)


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        msg = "wrapped key is not base64"
        raise kc.KeychainCryptoError(msg) from e


def decrypt_item(record: CloudKitRecord, keyring: KeyRing) -> ItemAttributes:
    """Decrypt one `item` record into its attribute dictionary; raise if it cannot be read."""
    parent = record.get_ref("parentkeyref")
    data = record.get_bytes("data")
    wrapped = record.get_str("wrappedkey")
    if parent is None or data is None or not wrapped:
        msg = f"item {record.record_name} is missing its key or data"
        raise kc.KeychainCryptoError(msg)
    item_key = kc.siv_unwrap(keyring.key(parent), _b64(wrapped))
    encver = record.get_int("encver")
    gen = record.get_int("gen")
    try:
        aad = authenticated_data_v2(
            record.record_name,
            record.fields,
            # Default only an absent field: substituting for a present 0 would authenticate a
            # value other than the one the record carries.
            encver=ENCRYPTION_VERSION if encver is None else encver,
            gen=0 if gen is None else gen,
            parent_key_id=parent,
        )
    except (ValueError, OverflowError, OSError) as e:
        # A NaN, infinite or out-of-range number or date cannot be authenticated.
        msg = f"item {record.record_name} has a field that cannot be authenticated"
        raise kc.KeychainCryptoError(msg) from e
    plaintext = kc.decrypt_item(item_key, data, aad)
    try:
        attrs = plistlib.loads(plaintext, aware_datetime=True)
    except PLIST_ERRORS as e:
        msg = f"item {record.record_name} does not hold a property list"
        raise kc.KeychainCryptoError(msg) from e
    if not isinstance(attrs, dict):
        msg = f"item {record.record_name} is not a dictionary"
        raise kc.KeychainCryptoError(msg)
    return {str(k): v for k, v in cast("dict[object, object]", attrs).items()}


def key_class_for(attrs: Mapping[str, object]) -> str:
    pdmn = attrs.get("pdmn")
    key_class = _KEY_CLASS.get(pdmn) if isinstance(pdmn, str) else None
    if key_class is None:
        msg = f"accessibility {pdmn!r} has no key class"
        raise kc.KeychainCryptoError(msg)
    return key_class


def encrypt_item(
    attrs: Mapping[str, object],
    record_name: str,
    zone: ZoneId,
    keyring: KeyRing,
    *,
    previous: CloudKitRecord | None = None,
) -> CloudKitRecord:
    """Seal `attrs` into an `item` record; `previous` is the version being replaced, if any.

    An update keeps the previous record's change tag (so the save is conditional on it), its
    `gen`, and every extra non-server field, which then joins the authenticated data.
    """
    parent = keyring.current_key(zone.name, key_class_for(attrs))
    extra: dict[str, FieldValue] = {}
    gen = 0
    if previous is not None:
        gen = previous.get_int("gen") or 0
        extra = {
            k: v
            for k, v in previous.fields.items()
            if k not in _ITEM_FIELDS and not k.startswith("server_")
        }
    item_key = kc.new_item_key()
    aad = authenticated_data_v2(
        record_name, extra, encver=ENCRYPTION_VERSION, gen=gen, parent_key_id=parent
    )
    plaintext = plistlib.dumps(
        dict(attrs), fmt=plistlib.FMT_BINARY, sort_keys=True, aware_datetime=True
    )
    fields: dict[str, FieldValue] = {
        "parentkeyref": CKReference(parent, REF_VALIDATING),
        "uploadver": UPLOAD_VERSION,
        "data": kc.encrypt_item(item_key, plaintext, aad),
        "wrappedkey": base64.b64encode(kc.wrap_item_key(keyring.key(parent), item_key)).decode(),
        "gen": gen,
        "encver": ENCRYPTION_VERSION,
        **extra,
    }
    return CloudKitRecord(
        record_name,
        "item",
        fields,
        etag=previous.etag if previous is not None else None,
        zone=zone,
    )
