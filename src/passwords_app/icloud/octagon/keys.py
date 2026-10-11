# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Octagon peer key material: two P-384 key pairs and the signed peer descriptions.

A peer is identified by tphash(permanentInfo || signature); its permanent, stable and dynamic
info are TPPB protobufs signed with ECDSA-P384-SHA384 over UTF8(type name) || data. The byte
layout is pinned (field order, encodings) because Cuttlefish verifies the signatures.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import time
from typing import TYPE_CHECKING, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passwords_app.icloud.proto.codec import Writer, all_bytes, decode_fields, first_int, first_str
from passwords_app.icloud.values import Record, text

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


class _Digest(Protocol):
    def digest(self) -> bytes: ...


_TPHASH: dict[str, Callable[[bytes], _Digest]] = {
    "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384,
}

_CURVE = ec.SECP384R1()
_COORD = 48
_POINT_LEN = 1 + 2 * _COORD  # 0x04 || X || Y = 97


@dataclasses.dataclass(frozen=True, slots=True)
class PeerKey:
    """One P-384 key pair (a peer has two: signing + encryption)."""

    private_key: ec.EllipticCurvePrivateKey

    def public_x963(self) -> bytes:
        """`0x04 || X || Y` (97 bytes): SecKey's external form of the public key."""
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def public_spki(self) -> bytes:
        """SubjectPublicKeyInfo DER."""
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_x963(self) -> bytes:
        """`0x04 || X || Y || D` (145 bytes), the bytes Octagon stores as OTPrivateKey.keyData."""
        d = self.private_key.private_numbers().private_value
        return self.public_x963() + d.to_bytes(_COORD, "big")

    def sign_sha384(self, data: bytes) -> bytes:
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA384()))


def generate_peer_key() -> PeerKey:
    return PeerKey(ec.generate_private_key(_CURVE))


def load_peer_key_x963(blob: bytes) -> PeerKey:
    """Inverse of `PeerKey.private_x963`."""
    d = int.from_bytes(blob[_POINT_LEN:], "big")
    return PeerKey(ec.derive_private_key(d, _CURVE))


@dataclasses.dataclass(frozen=True, slots=True)
class PeerKeySet:
    """The two key pairs that make up one Octagon self-peer identity."""

    signing: PeerKey
    encryption: PeerKey

    @classmethod
    def generate(cls) -> PeerKeySet:
        return cls(signing=generate_peer_key(), encryption=generate_peer_key())

    def to_storage(self) -> Record:
        """Serializable form for the encrypted session store (hex of the X9.63 privates)."""
        return {
            "curve": "P-384",
            "signing_priv_x963": self.signing.private_x963().hex(),
            "encryption_priv_x963": self.encryption.private_x963().hex(),
        }

    @classmethod
    def from_storage(cls, d: Mapping[str, object]) -> PeerKeySet:
        signing, encryption = (
            text(dict(d), "signing_priv_x963"),
            text(dict(d), "encryption_priv_x963"),
        )
        if not signing or not encryption:
            msg = "the stored peer identity has no keys"
            raise ValueError(msg)
        return cls(
            signing=load_peer_key_x963(bytes.fromhex(signing)),
            encryption=load_peer_key_x963(bytes.fromhex(encryption)),
        )


def tphash(data: bytes, algo: str = "SHA256") -> str:
    """TPHashBuilder: `"<ALGO>:" + base64(digest)` (peer ids, policy and preapproval hashes)."""
    return f"{algo}:" + base64.b64encode(_TPHASH[algo](data).digest()).decode()


def derive_peer_id(permanent_info_data: bytes, sig: bytes, algo: str = "SHA256") -> str:
    """PeerID = tphash(data ++ sig): the randomized signature makes it unique per generation."""
    return tphash(permanent_info_data + sig, algo)


def prefixed_data(data: bytes, sig_type: str) -> bytes:
    """`prefixedData()`: UTF8(type name) ++ data, the domain separation of every TPPB signature."""
    return sig_type.encode("utf-8") + data


def munge_model_id(model_id: str) -> str:
    """`+[TPPeerPermanentInfo mungeModelID:]`: pass-through on production builds."""
    return model_id


PERMANENT_INFO_SIG_TYPE = "TPPB.PeerPermanentInfo"


def serialize_permanent_info_data(  # noqa: PLR0913, PLR0917 - one argument per proto field
    signing_spki: bytes,
    encryption_spki: bytes,
    machine_id: str,
    model_id: str,
    epoch: int,
    creation_time: int,
) -> bytes:
    return (
        Writer()
        .uint64(1, epoch)
        .bytes(2, signing_spki)
        .bytes(3, encryption_spki)
        .string(4, machine_id)
        .string(5, munge_model_id(model_id))
        .uint64(6, creation_time)
        .finish()
    )


@dataclasses.dataclass(frozen=True, slots=True)
class PermanentInfo:
    peer_id: str
    data: bytes  # the TPPBPeerPermanentInfo proto bytes
    sig: bytes  # ECDSA-P384-SHA384 over prefixedData(data, TPPB.PeerPermanentInfo)
    machine_id: str
    model_id: str
    epoch: int
    creation_time: int


def build_permanent_info(
    keys: PeerKeySet,
    machine_id: str,
    model_id: str,
    epoch: int = 1,
    creation_time: int | None = None,
) -> PermanentInfo:
    """Build the signed self-peer permanentInfo and derive its peerID."""
    if creation_time is None:
        creation_time = int(time.time())
    data = serialize_permanent_info_data(
        keys.signing.public_spki(),
        keys.encryption.public_spki(),
        machine_id,
        model_id,
        epoch,
        creation_time,
    )
    sig = keys.signing.sign_sha384(prefixed_data(data, PERMANENT_INFO_SIG_TYPE))
    return PermanentInfo(
        peer_id=derive_peer_id(data, sig),
        data=data,
        sig=sig,
        machine_id=machine_id,
        model_id=munge_model_id(model_id),
        epoch=epoch,
        creation_time=creation_time,
    )


STABLE_INFO_SIG_TYPE = "TPPB.PeerStableInfo"
UCV_FOLLOWING = 1  # UserControllableViewStatus enum value

_STABLE_INTS = {
    1: "clock",
    2: "frozen_policy_version",
    10: "flexible_policy_version",
    12: "user_controllable_views",
    19: "supports_repudiation",
}
_STABLE_TEXTS = {
    3: "frozen_policy_hash",
    5: "os_version",
    6: "device_name",
    9: "serial_number",
    11: "flexible_policy_hash",
}


@dataclasses.dataclass(frozen=True, slots=True)
class StablePolicy:
    """The policy and device fields of a stableInfo."""

    frozen_policy_version: int
    frozen_policy_hash: str
    flexible_policy_version: int
    flexible_policy_hash: str
    device_name: str
    serial_number: str
    os_version: str
    user_controllable_views: int = UCV_FOLLOWING
    supports_repudiation: bool = True


def serialize_stable_info_data(clock: int, policy: StablePolicy) -> bytes:
    return (
        Writer()
        .uint64(1, clock)
        .uint64(2, policy.frozen_policy_version)
        .string(3, policy.frozen_policy_hash)
        .string(5, policy.os_version)
        .string(6, policy.device_name)
        .string(9, policy.serial_number)
        .uint64(10, policy.flexible_policy_version)
        .string(11, policy.flexible_policy_hash)
        .uint64(12, policy.user_controllable_views)
        .bool(19, True if policy.supports_repudiation else None)
        .finish()
    )


@dataclasses.dataclass(frozen=True, slots=True)
class StableInfo:
    data: bytes  # TPPBPeerStableInfo proto bytes
    sig: bytes  # ECDSA-P384-SHA384 over prefixedData(data, "TPPB.PeerStableInfo")
    clock: int
    frozen_policy_version: int
    flexible_policy_version: int

    def to_storage(self) -> Record:
        return {
            "data": self.data.hex(),
            "sig": self.sig.hex(),
            "clock": self.clock,
            "frozen_policy_version": self.frozen_policy_version,
            "flexible_policy_version": self.flexible_policy_version,
        }


def build_stable_info(  # noqa: PLR0913 - the stableInfo fields, by keyword
    keys: PeerKeySet,
    *,
    clock: int,
    frozen_policy_version: int,
    frozen_policy_hash: str,
    flexible_policy_version: int,
    flexible_policy_hash: str,
    device_name: str,
    serial_number: str,
    os_version: str,
    user_controllable_views: int = UCV_FOLLOWING,
    supports_repudiation: bool = True,
) -> StableInfo:
    """Build and sign the peer's stableInfo."""
    policy = StablePolicy(
        frozen_policy_version,
        frozen_policy_hash,
        flexible_policy_version,
        flexible_policy_hash,
        device_name,
        serial_number,
        os_version,
        user_controllable_views,
        supports_repudiation,
    )
    data = serialize_stable_info_data(clock, policy)
    sig = keys.signing.sign_sha384(prefixed_data(data, STABLE_INFO_SIG_TYPE))
    return StableInfo(
        data=data,
        sig=sig,
        clock=clock,
        frozen_policy_version=frozen_policy_version,
        flexible_policy_version=flexible_policy_version,
    )


def parse_stable_info_data(data: bytes) -> Record:
    f = decode_fields(data)
    out: Record = {}
    for num, name in _STABLE_INTS.items():
        if (value := first_int(f, num)) is not None:
            out[name] = value
    for num, name in _STABLE_TEXTS.items():
        if (s := first_str(f, num)) is not None:
            out[name] = s
    return out


VOUCHER_SIG_TYPE = "TPPB.Voucher"
DYNAMIC_INFO_SIG_TYPE = "TPPB.PeerDynamicInfo"
_D_CLOCK, _D_INCLUDED, _D_EXCLUDED, _D_PREAPPROVALS = 1, 2, 3, 5


def serialize_dynamic_info_data(
    clock: int,
    included_peer_ids: list[str],
    excluded_peer_ids: list[str] | None = None,
    preapprovals: list[str] | None = None,
) -> bytes:
    """TPPBPeerDynamicInfo: the mutable trust graph (self + existing trusted peers)."""
    w = Writer().uint64(_D_CLOCK, clock)
    for pid in included_peer_ids:
        w.string(_D_INCLUDED, pid)
    for pid in excluded_peer_ids or []:
        w.string(_D_EXCLUDED, pid)
    for h in preapprovals or []:
        w.string(_D_PREAPPROVALS, h)
    return w.finish()


@dataclasses.dataclass(frozen=True, slots=True)
class DynamicInfo:
    data: bytes
    sig: bytes
    clock: int
    included_peer_ids: tuple[str, ...]

    def to_storage(self) -> Record:
        return {
            "data": self.data.hex(),
            "sig": self.sig.hex(),
            "clock": self.clock,
            "included_peer_ids": list(self.included_peer_ids),
        }


def build_dynamic_info(
    keys: PeerKeySet,
    clock: int,
    included_peer_ids: list[str],
    excluded_peer_ids: list[str] | None = None,
    preapprovals: list[str] | None = None,
) -> DynamicInfo:
    """Build and sign the peer's dynamicInfo."""
    data = serialize_dynamic_info_data(clock, included_peer_ids, excluded_peer_ids, preapprovals)
    sig = keys.signing.sign_sha384(prefixed_data(data, DYNAMIC_INFO_SIG_TYPE))
    return DynamicInfo(data=data, sig=sig, clock=clock, included_peer_ids=tuple(included_peer_ids))


def parse_dynamic_info_data(data: bytes) -> Record:
    f = decode_fields(data)
    out: Record = {
        "included": [b.decode("utf-8") for b in all_bytes(f, _D_INCLUDED)],
        "excluded": [b.decode("utf-8") for b in all_bytes(f, _D_EXCLUDED)],
        "preapprovals": [b.decode("utf-8") for b in all_bytes(f, _D_PREAPPROVALS)],
    }
    if (clock := first_int(f, _D_CLOCK)) is not None:
        out["clock"] = clock
    return out
