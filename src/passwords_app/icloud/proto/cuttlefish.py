# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Cuttlefish (Octagon trust service) wire messages used by the join and the view-key fetch.

The peer identity built in `octagon/keys.py` goes on the wire here; the CloudKit framing that
carries these as CKCode function invocations lives in `transport/cloudkit.py`.
"""

from __future__ import annotations

import dataclasses

from passwords_app.icloud.proto.codec import (
    Writer,
    all_bytes,
    decode_fields,
    first_bytes,
    first_int,
    first_message,
    first_str,
)


def encode_signed_info(info: bytes, signature: bytes) -> bytes:
    return Writer().bytes(1, info).bytes(2, signature).finish()


def parse_signed_info(raw: bytes) -> tuple[bytes, bytes]:
    f = decode_fields(raw)
    return first_bytes(f, 1) or b"", first_bytes(f, 2) or b""


@dataclasses.dataclass(frozen=True, slots=True)
class SignedBlob:
    info: bytes
    sig: bytes

    def encode(self) -> bytes:
        return encode_signed_info(self.info, self.sig)


@dataclasses.dataclass(frozen=True, slots=True)
class CuttlefishPeer:
    hash: str | None
    permanent_info: SignedBlob | None
    stable_info: SignedBlob | None
    dynamic_info: SignedBlob | None
    voucher: SignedBlob | None


def encode_cuttlefish_peer(
    peer_id: str,
    permanent: SignedBlob,
    stable: SignedBlob,
    dynamic: SignedBlob,
    voucher: SignedBlob | None = None,
) -> bytes:
    return (
        Writer()
        .string(1, peer_id)
        .message(2, permanent.encode())
        .message(3, stable.encode())
        .message(4, dynamic.encode())
        .message(5, voucher.encode() if voucher is not None else None)
        .finish()
    )


def _signed(raw: bytes | None) -> SignedBlob | None:
    return SignedBlob(*parse_signed_info(raw)) if raw is not None else None


def parse_cuttlefish_peer(raw: bytes) -> CuttlefishPeer:
    f = decode_fields(raw)
    return CuttlefishPeer(
        hash=first_str(f, 1),
        permanent_info=_signed(first_bytes(f, 2)),
        stable_info=_signed(first_bytes(f, 3)),
        dynamic_info=_signed(first_bytes(f, 4)),
        voucher=_signed(first_bytes(f, 5)),
    )


def encode_voucher(reason: int, beneficiary: str, sponsor: str) -> bytes:
    return Writer().uint64(1, reason).string(2, beneficiary).string(3, sponsor).finish()


@dataclasses.dataclass(frozen=True, slots=True)
class TlkShare:
    service: str = ""
    curve: int = 0
    epoch: int = 0
    key_id: str = ""
    poisoned: int = 0
    receiver: str = ""
    receiver_public_encryption_key: str = ""  # base64 SPKI
    sender: str = ""
    signature: str = ""  # base64
    version: int = 0
    wrapped_key: str = ""  # base64

    def encode(self) -> bytes:
        return (
            Writer()
            .string(1, self.service)
            .uint64(2, self.curve)
            .uint64(3, self.epoch)
            .string(4, self.key_id)
            .uint64(5, self.poisoned)
            .string(6, self.receiver)
            .string(7, self.receiver_public_encryption_key)
            .string(8, self.sender)
            .string(9, self.signature)
            .uint64(10, self.version)
            .string(11, self.wrapped_key)
            .finish()
        )

    @classmethod
    def parse(cls, raw: bytes) -> TlkShare:
        f = decode_fields(raw)
        return cls(
            service=first_str(f, 1, ""),
            curve=first_int(f, 2) or 0,
            epoch=first_int(f, 3) or 0,
            key_id=first_str(f, 4, ""),
            poisoned=first_int(f, 5) or 0,
            receiver=first_str(f, 6, ""),
            receiver_public_encryption_key=first_str(f, 7, ""),
            sender=first_str(f, 8, ""),
            signature=first_str(f, 9, ""),
            version=first_int(f, 10) or 0,
            wrapped_key=first_str(f, 11, ""),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ViewKey:
    key_id: str = ""
    top_level_key_id: str = ""
    key_number: int = 0
    key: str = ""
    hardware: str = ""

    def encode(self) -> bytes:
        return (
            Writer()
            .string(1, self.key_id)
            .string(2, self.top_level_key_id)
            .uint64(3, self.key_number)
            .string(4, self.key)
            .string(5, self.hardware)
            .finish()
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ViewKeys:
    service: str = ""
    top_level_key: ViewKey | None = None
    class_a: ViewKey | None = None
    class_c: ViewKey | None = None
    old_top_level_key: ViewKey | None = None

    def encode(self) -> bytes:
        w = Writer().string(1, self.service)
        for num, vk in (
            (2, self.top_level_key),
            (3, self.class_a),
            (4, self.class_c),
            (5, self.old_top_level_key),
        ):
            if vk is not None:
                w.message(num, vk.encode())
        return w.finish()


@dataclasses.dataclass(frozen=True, slots=True)
class FetchChanges:
    sync_token: str | None
    peers: tuple[CuttlefishPeer, ...]


def encode_fetch_changes_request(sync_token: str | None) -> bytes:
    return Writer().string(1, sync_token).finish()


def parse_fetch_changes_response(raw: bytes) -> FetchChanges:
    changes = first_message(decode_fields(raw), 1)
    if changes is None:
        return FetchChanges(None, ())
    peers: list[CuttlefishPeer] = []
    for change in all_bytes(changes, 2):
        add = first_bytes(decode_fields(change), 3)
        if add is not None:
            peers.append(parse_cuttlefish_peer(add))
    return FetchChanges(first_str(changes, 1), tuple(peers))


def encode_join_with_voucher_request(
    peer: bytes,
    shares: list[TlkShare] | None = None,
    keys: list[ViewKeys] | None = None,
    bottle: bytes | None = None,
    restore_point: str | None = None,
) -> bytes:
    """`peer` is an encoded CuttlefishPeer with its voucher SignedInfo populated by the sponsor."""
    w = Writer().string(1, restore_point).message(2, peer).message(3, bottle)
    for s in shares or []:
        w.message(4, s.encode())
    for k in keys or []:
        w.message(5, k.encode())
    return w.finish()


def encode_fetch_recoverable_tlkshares_request(peer_id: str) -> bytes:
    """Ask for every view TLKShare the peer can recover (incl. Passwords, with no plain one)."""
    return Writer().string(1, peer_id).finish()


@dataclasses.dataclass(frozen=True, slots=True)
class RecoverableShares:
    """The inner CloudKit Record protobufs (parse them with `ckks.parse_record`)."""

    share_records: tuple[bytes, ...]
    synckey_records: tuple[bytes, ...]


def _inner_record(cuttlefish_record: bytes | None) -> bytes | None:
    """CuttlefishRecord{inner(2): Record} -> the Record bytes."""
    if cuttlefish_record is None:
        return None
    return first_bytes(decode_fields(cuttlefish_record), 2)


def parse_recoverable_tlkshares_response(raw: bytes) -> RecoverableShares:
    shares: list[bytes] = []
    synckeys: list[bytes] = []
    for grp in all_bytes(decode_fields(raw), 1):
        g = decode_fields(grp)
        share = _inner_record(first_bytes(g, 3))
        if share is not None:
            shares.append(share)
        view_keys = first_message(g, 2)
        if view_keys is not None:
            for fn in (1, 2, 3):  # tlk, classA, classC synckey records
                rec = _inner_record(first_bytes(view_keys, fn))
                if rec is not None:
                    synckeys.append(rec)
    return RecoverableShares(tuple(shares), tuple(synckeys))


def encode_function_invoke_request(service: str, name: str, parameters: bytes) -> bytes:
    return Writer().string(1, service).string(2, name).bytes(3, parameters).finish()
