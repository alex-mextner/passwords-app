"""Cuttlefish and function-invoke wire messages for the sponsored-join path. Carries the
octagon/keys peer identity onto the wire; CloudKit container framing lives in transport/cloudkit.
See RESEARCH.md (Stages 2-4) for the field-number provenance."""

from __future__ import annotations

import dataclasses

from .codec import Writer, decode_fields, first, first_str


def encode_signed_info(info: bytes, signature: bytes) -> bytes:
    return Writer().bytes(1, info).bytes(2, signature).finish()


def parse_signed_info(raw: bytes) -> tuple[bytes, bytes]:
    f = decode_fields(raw)
    return first(f, 1, b""), first(f, 2, b"")


@dataclasses.dataclass
class SignedBlob:
    info: bytes
    sig: bytes

    def encode(self) -> bytes:
        return encode_signed_info(self.info, self.sig)


def encode_cuttlefish_peer(peer_id: str, permanent: SignedBlob, stable: SignedBlob,
                           dynamic: SignedBlob, voucher: SignedBlob | None = None) -> bytes:
    w = (Writer()
         .string(1, peer_id)
         .message(2, permanent.encode())
         .message(3, stable.encode())
         .message(4, dynamic.encode()))
    if voucher is not None:
        w.message(5, voucher.encode())
    return w.finish()


def parse_cuttlefish_peer(raw: bytes) -> dict:
    f = decode_fields(raw)
    out = {"hash": first_str(f, 1)}
    for key, num in (("permanent_info", 2), ("stable_info", 3), ("dynamic_info", 4),
                     ("voucher", 5)):
        blob = first(f, num)
        out[key] = SignedBlob(*parse_signed_info(blob)) if blob is not None else None
    return out


def encode_voucher(reason: int, beneficiary: str, sponsor: str) -> bytes:
    return Writer().uint64(1, reason).string(2, beneficiary).string(3, sponsor).finish()


@dataclasses.dataclass
class TlkShare:
    service: str = ""
    curve: int = 0
    epoch: int = 0
    key_id: str = ""
    poisoned: int = 0
    receiver: str = ""
    receiver_public_encryption_key: str = ""  # base64 SPKI
    sender: str = ""
    signature: str = ""            # base64
    version: int = 0
    wrapped_key: str = ""          # base64

    def encode(self) -> bytes:
        return (Writer()
                .string(1, self.service).uint64(2, self.curve).uint64(3, self.epoch)
                .string(4, self.key_id).uint64(5, self.poisoned).string(6, self.receiver)
                .string(7, self.receiver_public_encryption_key).string(8, self.sender)
                .string(9, self.signature).uint64(10, self.version)
                .string(11, self.wrapped_key).finish())

    @classmethod
    def parse(cls, raw: bytes) -> "TlkShare":
        f = decode_fields(raw)
        return cls(
            service=first_str(f, 1, ""), curve=first(f, 2, 0), epoch=first(f, 3, 0),
            key_id=first_str(f, 4, ""), poisoned=first(f, 5, 0), receiver=first_str(f, 6, ""),
            receiver_public_encryption_key=first_str(f, 7, ""), sender=first_str(f, 8, ""),
            signature=first_str(f, 9, ""), version=first(f, 10, 0),
            wrapped_key=first_str(f, 11, ""))


@dataclasses.dataclass
class ViewKey:
    key_id: str = ""
    top_level_key_id: str = ""
    key_number: int = 0
    key: str = ""
    hardware: str = ""

    def encode(self) -> bytes:
        return (Writer().string(1, self.key_id).string(2, self.top_level_key_id)
                .uint64(3, self.key_number).string(4, self.key).string(5, self.hardware)
                .finish())


@dataclasses.dataclass
class ViewKeys:
    service: str = ""
    top_level_key: ViewKey | None = None
    class_a: ViewKey | None = None
    class_c: ViewKey | None = None
    old_top_level_key: ViewKey | None = None

    def encode(self) -> bytes:
        w = Writer().string(1, self.service)
        for num, vk in ((2, self.top_level_key), (3, self.class_a), (4, self.class_c),
                        (5, self.old_top_level_key)):
            if vk is not None:
                w.message(num, vk.encode())
        return w.finish()


def encode_fetch_changes_request(sync_token: str | None) -> bytes:
    return Writer().string(1, sync_token).finish()


def parse_fetch_changes_response(raw: bytes) -> dict:
    f = decode_fields(raw)
    changes_blob = first(f, 1)
    if changes_blob is None:
        return {"sync_token": None, "peers": []}
    cf = decode_fields(changes_blob)
    peers = []
    for change in cf.get(2, []):
        chg = decode_fields(change)
        add = first(chg, 3)
        if add is not None:
            peers.append(parse_cuttlefish_peer(add))
    return {"sync_token": first_str(cf, 1), "peers": peers}


def encode_join_with_voucher_request(peer: bytes, shares: list[TlkShare] | None = None,
                                     keys: list[ViewKeys] | None = None,
                                     bottle: bytes | None = None,
                                     restore_point: str | None = None) -> bytes:
    """`peer` is an encoded CuttlefishPeer with its voucher SignedInfo populated by the sponsor."""
    w = (Writer().string(1, restore_point).message(2, peer).message(3, bottle))
    for s in (shares or []):
        w.message(4, s.encode())
    for k in (keys or []):
        w.message(5, k.encode())
    return w.finish()


def encode_fetch_recoverable_tlkshares_request(peer_id: str) -> bytes:
    """Asks the server for every view TLKShare our peer can recover, incl. user-controllable
    views (Passwords) that have no plain CKKS tlkshare addressed to us."""
    return Writer().string(1, peer_id).finish()


def parse_recoverable_tlkshares_response(raw: bytes) -> dict:
    """Returns the inner Record protobufs (parse with ckks.parse_record):
    {"share_records": [...], "synckey_records": [...]}."""
    f = decode_fields(raw)

    def inner(cuttlefish_record):     # CuttlefishRecord{ inner(2): Record } -> Record bytes
        return first(decode_fields(cuttlefish_record), 2) if cuttlefish_record is not None else None

    share_records, synckey_records = [], []
    for grp in f.get(1, []):
        g = decode_fields(grp)
        sh = inner(first(g, 3))
        if sh is not None:
            share_records.append(sh)
        vk = first(g, 2)
        if vk is not None:
            vf = decode_fields(vk)
            for fn in (1, 2, 3):      # tlk, classA, classB synckey records
                rec = inner(first(vf, fn))
                if rec is not None:
                    synckey_records.append(rec)
    return {"share_records": share_records, "synckey_records": synckey_records}


def encode_function_invoke_request(service: str, name: str, parameters: bytes) -> bytes:
    return Writer().string(1, service).string(2, name).bytes(3, parameters).finish()
