"""Octagon peer key material - two P-384 key pairs (signing + encryption) and the peerID
derived from a signed permanentInfo. Pure offline crypto, no network calls.

See RESEARCH.md "octagon/keys.py" for the byte-exact format pins (X9.63/SPKI encodings,
TPPBPeerPermanentInfo fields, ECDSA domain separation, peerID hash).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_TPHASH = {
    "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384,
}

_CURVE = ec.SECP384R1()
_COORD = 48
_POINT_LEN = 1 + 2 * _COORD          # 0x04 || X || Y      = 97


@dataclasses.dataclass
class PeerKey:
    """One P-384 key pair (a peer has two: signing + encryption)."""

    private_key: ec.EllipticCurvePrivateKey

    def public_x963(self) -> bytes:
        """`0x04 || X || Y` (97 bytes) - SecKey external rep of the public key."""
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def public_spki(self) -> bytes:
        """SubjectPublicKeyInfo DER - the standard X.509 public-key wrapper."""
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_x963(self) -> bytes:
        """`0x04 || X || Y || D` (145 bytes) - SecKeyCopyExternalRepresentation
        of a full EC key, i.e. the bytes Octagon stores as OTPrivateKey.keyData."""
        d = self.private_key.private_numbers().private_value
        return self.public_x963() + d.to_bytes(_COORD, "big")

    def sign_sha384(self, data: bytes) -> bytes:
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA384()))


def generate_peer_key() -> PeerKey:
    return PeerKey(ec.generate_private_key(_CURVE))


def load_peer_key_x963(blob: bytes) -> PeerKey:
    """Inverse of `PeerKey.private_x963` - reconstruct a key from stored OTPrivateKey bytes."""
    d = int.from_bytes(blob[_POINT_LEN:], "big")
    return PeerKey(ec.derive_private_key(d, _CURVE))


@dataclasses.dataclass
class PeerKeySet:
    """The two key pairs that make up one Octagon self-peer identity."""

    signing: PeerKey
    encryption: PeerKey

    @classmethod
    def generate(cls) -> "PeerKeySet":
        return cls(signing=generate_peer_key(), encryption=generate_peer_key())

    def to_storage(self) -> dict:
        """Serializable form for the encrypted session store (hex of the X9.63 privates)."""
        return {
            "curve": "P-384",
            "signing_priv_x963": self.signing.private_x963().hex(),
            "encryption_priv_x963": self.encryption.private_x963().hex(),
        }

    @classmethod
    def from_storage(cls, d: dict) -> "PeerKeySet":
        return cls(
            signing=load_peer_key_x963(bytes.fromhex(d["signing_priv_x963"])),
            encryption=load_peer_key_x963(bytes.fromhex(d["encryption_priv_x963"])),
        )


def tphash(data: bytes, algo: str = "SHA256") -> str:
    """TPHashBuilder: `"<ALGO>:" + base64(digest)`. Used for peerIDs, policy-doc and
    preapproval hashes throughout Octagon."""
    return f"{algo}:" + base64.b64encode(_TPHASH[algo](data).digest()).decode()


def derive_peer_id(permanent_info_data: bytes, sig: bytes, algo: str = "SHA256") -> str:
    """peerID = tphash(data ++ sig) - hashes the concatenation, not data alone. The randomized
    ECDSA sig makes peerID generated-once; verifiers only re-check peerID == hash(data||sig)."""
    return tphash(permanent_info_data + sig, algo)


PERMANENT_INFO_SIG_TYPE = "TPPB.PeerPermanentInfo"

_F_EPOCH, _F_SIGNING, _F_ENCRYPTION, _F_MACHINE, _F_MODEL, _F_CREATION = 1, 2, 3, 4, 5, 6
_WT_VARINT, _WT_LEN = 0, 2


def _pb_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _pb_tag(field: int, wire: int) -> bytes:
    return _pb_varint((field << 3) | wire)


def _pb_uint64(field: int, value: int) -> bytes:
    return _pb_tag(field, _WT_VARINT) + _pb_varint(value)


def _pb_len(field: int, data: bytes) -> bytes:
    return _pb_tag(field, _WT_LEN) + _pb_varint(len(data)) + data


def _pb_read_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift, val = 0, 0
    while True:
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7


def munge_model_id(model_id: str) -> str:
    """`+[TPPeerPermanentInfo mungeModelID:]` - pass-through on production builds."""
    return model_id


def serialize_permanent_info_data(signing_spki: bytes, encryption_spki: bytes,
                                  machine_id: str, model_id: str, epoch: int,
                                  creation_time: int) -> bytes:
    return b"".join([
        _pb_uint64(_F_EPOCH, epoch),
        _pb_len(_F_SIGNING, signing_spki),
        _pb_len(_F_ENCRYPTION, encryption_spki),
        _pb_len(_F_MACHINE, machine_id.encode("utf-8")),
        _pb_len(_F_MODEL, munge_model_id(model_id).encode("utf-8")),
        _pb_uint64(_F_CREATION, creation_time),
    ])


def _prefixed_data(data: bytes, sig_type: str) -> bytes:
    """`prefixedData()` - UTF8(sigTypeName) ++ data (domain separation for typesafe sigs)."""
    return sig_type.encode("utf-8") + data


@dataclasses.dataclass
class PermanentInfo:
    peer_id: str
    data: bytes          # the TPPBPeerPermanentInfo proto bytes
    sig: bytes           # ECDSA-P384-SHA384 over prefixedData(data, TPPB.PeerPermanentInfo)
    machine_id: str
    model_id: str
    epoch: int
    creation_time: int

    def to_storage(self) -> dict:
        return {
            "peer_id": self.peer_id,
            "data": self.data.hex(),
            "sig": self.sig.hex(),
            "machine_id": self.machine_id,
            "model_id": self.model_id,
            "epoch": self.epoch,
            "creation_time": self.creation_time,
        }


def build_permanent_info(keys: PeerKeySet, machine_id: str, model_id: str,
                         epoch: int = 1, creation_time: int | None = None) -> PermanentInfo:
    """Build the signed self-peer permanentInfo and derive its peerID."""
    if creation_time is None:
        creation_time = int(time.time())
    signing_spki = keys.signing.public_spki()
    encryption_spki = keys.encryption.public_spki()
    data = serialize_permanent_info_data(signing_spki, encryption_spki,
                                         machine_id, model_id, epoch, creation_time)
    sig = keys.signing.sign_sha384(_prefixed_data(data, PERMANENT_INFO_SIG_TYPE))
    peer_id = derive_peer_id(data, sig)
    return PermanentInfo(peer_id=peer_id, data=data, sig=sig, machine_id=machine_id,
                         model_id=munge_model_id(model_id), epoch=epoch,
                         creation_time=creation_time)


STABLE_INFO_SIG_TYPE = "TPPB.PeerStableInfo"

UCV_FOLLOWING = 1  # UserControllableViewStatus enum value

_S_CLOCK, _S_FROZEN_VERSION, _S_FROZEN_HASH = 1, 2, 3
_S_OSVERSION, _S_DEVICENAME, _S_SERIAL = 5, 6, 9
_S_FLEX_VERSION, _S_FLEX_HASH, _S_UCV = 10, 11, 12
_S_REPUDIATION = 19


def _pb_bool(field: int, value: bool) -> bytes:
    return _pb_uint64(field, 1 if value else 0)


def serialize_stable_info_data(clock: int, frozen_policy_version: int, frozen_policy_hash: str,
                               flexible_policy_version: int, flexible_policy_hash: str,
                               device_name: str, serial_number: str, os_version: str,
                               user_controllable_views: int = UCV_FOLLOWING,
                               supports_repudiation: bool = True) -> bytes:
    return b"".join([
        _pb_uint64(_S_CLOCK, clock),
        _pb_uint64(_S_FROZEN_VERSION, frozen_policy_version),
        _pb_len(_S_FROZEN_HASH, frozen_policy_hash.encode("utf-8")),
        _pb_len(_S_OSVERSION, os_version.encode("utf-8")),
        _pb_len(_S_DEVICENAME, device_name.encode("utf-8")),
        _pb_len(_S_SERIAL, serial_number.encode("utf-8")),
        _pb_uint64(_S_FLEX_VERSION, flexible_policy_version),
        _pb_len(_S_FLEX_HASH, flexible_policy_hash.encode("utf-8")),
        _pb_uint64(_S_UCV, user_controllable_views),
    ] + ([_pb_bool(_S_REPUDIATION, True)] if supports_repudiation else []))


@dataclasses.dataclass
class StableInfo:
    data: bytes          # TPPBPeerStableInfo proto bytes
    sig: bytes           # ECDSA-P384-SHA384 over prefixedData(data, "TPPB.PeerStableInfo")
    clock: int
    frozen_policy_version: int
    flexible_policy_version: int

    def to_storage(self) -> dict:
        return {"data": self.data.hex(), "sig": self.sig.hex(), "clock": self.clock,
                "frozen_policy_version": self.frozen_policy_version,
                "flexible_policy_version": self.flexible_policy_version}


def build_stable_info(keys: PeerKeySet, clock: int, frozen_policy_version: int,
                      frozen_policy_hash: str, flexible_policy_version: int,
                      flexible_policy_hash: str, device_name: str, serial_number: str,
                      os_version: str, user_controllable_views: int = UCV_FOLLOWING,
                      supports_repudiation: bool = True) -> StableInfo:
    """Build and sign the peer's stableInfo (attached to the permanentInfo's peerID)."""
    data = serialize_stable_info_data(
        clock, frozen_policy_version, frozen_policy_hash, flexible_policy_version,
        flexible_policy_hash, device_name, serial_number, os_version,
        user_controllable_views, supports_repudiation)
    sig = keys.signing.sign_sha384(_prefixed_data(data, STABLE_INFO_SIG_TYPE))
    return StableInfo(data=data, sig=sig, clock=clock,
                      frozen_policy_version=frozen_policy_version,
                      flexible_policy_version=flexible_policy_version)


def parse_stable_info_data(data: bytes) -> dict:
    pos, out, n = 0, {}, len(data)
    names_varint = {_S_CLOCK: "clock", _S_FROZEN_VERSION: "frozen_policy_version",
                    _S_FLEX_VERSION: "flexible_policy_version", _S_UCV: "user_controllable_views",
                    _S_REPUDIATION: "supports_repudiation"}
    names_str = {_S_FROZEN_HASH: "frozen_policy_hash", _S_OSVERSION: "os_version",
                 _S_DEVICENAME: "device_name", _S_SERIAL: "serial_number",
                 _S_FLEX_HASH: "flexible_policy_hash"}
    while pos < n:
        tag, pos = _pb_read_varint(data, pos)
        field, wire = tag >> 3, tag & 7
        if wire == _WT_VARINT:
            val, pos = _pb_read_varint(data, pos)
            if field in names_varint:
                out[names_varint[field]] = val
        elif wire == _WT_LEN:
            ln, pos = _pb_read_varint(data, pos)
            chunk = data[pos:pos + ln]
            pos += ln
            if field in names_str:
                out[names_str[field]] = chunk.decode("utf-8")
    return out


VOUCHER_SIG_TYPE = "TPPB.Voucher"
DYNAMIC_INFO_SIG_TYPE = "TPPB.PeerDynamicInfo"
_D_CLOCK, _D_INCLUDED, _D_EXCLUDED, _D_PREAPPROVALS = 1, 2, 3, 5


def serialize_dynamic_info_data(clock: int, included_peer_ids: list[str],
                                excluded_peer_ids: list[str] | None = None,
                                preapprovals: list[str] | None = None) -> bytes:
    """TPPBPeerDynamicInfo proto - the mutable trust graph (self + existing trusted peers)."""
    parts = [_pb_uint64(_D_CLOCK, clock)]
    for pid in included_peer_ids:
        parts.append(_pb_len(_D_INCLUDED, pid.encode("utf-8")))
    for pid in (excluded_peer_ids or []):
        parts.append(_pb_len(_D_EXCLUDED, pid.encode("utf-8")))
    for h in (preapprovals or []):
        parts.append(_pb_len(_D_PREAPPROVALS, h.encode("utf-8")))
    return b"".join(parts)


@dataclasses.dataclass
class DynamicInfo:
    data: bytes
    sig: bytes
    clock: int
    included_peer_ids: list[str]

    def to_storage(self) -> dict:
        return {"data": self.data.hex(), "sig": self.sig.hex(), "clock": self.clock,
                "included_peer_ids": list(self.included_peer_ids)}


def build_dynamic_info(keys: PeerKeySet, clock: int, included_peer_ids: list[str],
                       excluded_peer_ids: list[str] | None = None,
                       preapprovals: list[str] | None = None) -> DynamicInfo:
    """Build and sign the peer's dynamicInfo."""
    data = serialize_dynamic_info_data(clock, included_peer_ids, excluded_peer_ids, preapprovals)
    sig = keys.signing.sign_sha384(_prefixed_data(data, DYNAMIC_INFO_SIG_TYPE))
    return DynamicInfo(data=data, sig=sig, clock=clock,
                       included_peer_ids=list(included_peer_ids))


def parse_dynamic_info_data(data: bytes) -> dict:
    pos, n = 0, len(data)
    out: dict = {"included": [], "excluded": [], "preapprovals": []}
    while pos < n:
        tag, pos = _pb_read_varint(data, pos)
        field, wire = tag >> 3, tag & 7
        if wire == _WT_VARINT:
            val, pos = _pb_read_varint(data, pos)
            if field == _D_CLOCK:
                out["clock"] = val
        elif wire == _WT_LEN:
            ln, pos = _pb_read_varint(data, pos)
            chunk = data[pos:pos + ln]
            pos += ln
            if field == _D_INCLUDED:
                out["included"].append(chunk.decode("utf-8"))
            elif field == _D_EXCLUDED:
                out["excluded"].append(chunk.decode("utf-8"))
            elif field == _D_PREAPPROVALS:
                out["preapprovals"].append(chunk.decode("utf-8"))
    return out
