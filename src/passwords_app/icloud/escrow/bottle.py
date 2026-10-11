# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Open an escrow bottle and vouch for our peer with the identity inside it.

The bottle entropy (from the escrow SRP) derives, with HKDF-SHA384 salted by the account's
adsid, the AES-GCM key of the OTBottle; inside are the old peer's P-384 signing and encryption
keys. The signing key then signs a Voucher admitting our new peer. Pure offline crypto.
"""

from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.proto.codec import ProtoError, Writer, decode_fields, first_bytes
from passwords_app.icloud.proto.codec import first_message as _first_message
from passwords_app.icloud.proto.cuttlefish import SignedBlob, encode_voucher

# NIST P-384 group order n (public constant).
_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffff"
    "c7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    16,
)

_HKDF_INFO_SYM = b"Escrow Symmetric Key"
_HKDF_INFO_SIGNING = b"Escrow Signing Private Key"
_HKDF_INFO_ENCRYPTION = b"Escrow Encryption Private Key"
_EC_SEED_BYTES = 56


class EscrowError(AppleError):
    pass


def parse_ot_private_key(raw: bytes | None) -> bytes:
    """OTPrivateKey{keyType(1), keyData(2)} -> keyData (X9.63 EC private)."""
    key = first_bytes(decode_fields(raw), 2) if raw is not None else None
    if not key:
        msg = "bottle holds no private key"
        raise EscrowError(msg)
    return key


def parse_ot_internal_bottle(raw: bytes) -> tuple[bytes, bytes]:
    """OTInternalBottle{signingKey(3), encryptionKey(4)} -> (signing, encryption) X9.63."""
    f = decode_fields(raw)
    return parse_ot_private_key(first_bytes(f, 3)), parse_ot_private_key(first_bytes(f, 4))


def _text(raw: bytes | None) -> str:
    return raw.decode("utf-8", "replace") if raw else ""


@dataclasses.dataclass(frozen=True, slots=True)
class OTBottle:
    escrowed_signing_key: bytes  # SPKI DER (verification pubkey)
    escrowed_encryption_key: bytes  # SPKI DER
    ct: bytes
    auth_code: bytes
    iv: bytes
    peer_id: str = ""
    bottle_id: str = ""

    @classmethod
    def parse(cls, raw: bytes) -> OTBottle:
        try:
            f = decode_fields(raw)
            cf = _first_message(f, 12) or {}
        except ProtoError as e:
            msg = "malformed escrow bottle"
            raise EscrowError(msg) from e
        return cls(
            escrowed_signing_key=first_bytes(f, 8) or b"",
            escrowed_encryption_key=first_bytes(f, 9) or b"",
            ct=first_bytes(cf, 1) or b"",
            auth_code=first_bytes(cf, 2) or b"",
            iv=first_bytes(cf, 3) or b"",
            peer_id=_text(first_bytes(f, 1)),
            bottle_id=_text(first_bytes(f, 2)),
        )

    def encode(self) -> bytes:
        cipher = Writer().bytes(1, self.ct).bytes(2, self.auth_code).bytes(3, self.iv)
        return (
            Writer()
            .string(1, self.peer_id)
            .string(2, self.bottle_id)
            .bytes(8, self.escrowed_signing_key)
            .bytes(9, self.escrowed_encryption_key)
            .message(12, cipher)
            .finish()
        )


def _hkdf_sha384(entropy: bytes, adsid: str, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA384(), length=length, salt=adsid.encode("utf-8"), info=info
    ).derive(entropy)


def derive_symmetric_key(entropy: bytes, adsid: str) -> bytes:
    return _hkdf_sha384(entropy, adsid, _HKDF_INFO_SYM, 32)


def derive_ec_private_key(entropy: bytes, adsid: str, info: bytes) -> ec.EllipticCurvePrivateKey:
    """HKDF-SHA384 -> 56 bytes -> FIPS 186-4 B.5.1 (mod (n-1), +1) -> P-384 private key."""
    raw = _hkdf_sha384(entropy, adsid, info, _EC_SEED_BYTES)
    d = (int.from_bytes(raw, "big") % (_P384_ORDER - 1)) + 1
    return ec.derive_private_key(d, ec.SECP384R1())


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveredIdentity:
    peer_id: str
    signing_key: ok.PeerKey
    encryption_key: ok.PeerKey

    def make_voucher(self, beneficiary_peer_id: str, reason: int = 1) -> SignedBlob:
        """Sign Voucher{reason, beneficiary, sponsor=self}: our peer's ticket into the trust."""
        info = encode_voucher(reason, beneficiary_peer_id, self.peer_id)
        sig = self.signing_key.sign_sha384(ok.prefixed_data(info, ok.VOUCHER_SIG_TYPE))
        return SignedBlob(info=info, sig=sig)


def recover_identity(bottle: OTBottle, entropy: bytes, adsid: str) -> RecoveredIdentity:
    """Decrypt an OTBottle with the escrow entropy into the old peer's keys.

    Wrong entropy or adsid derives the wrong key, and the AES-GCM tag check rejects it.
    """
    key = derive_symmetric_key(entropy, adsid)
    try:
        plaintext = AESGCM(key).decrypt(bottle.iv, bottle.ct + bottle.auth_code, None)
    except (InvalidTag, ValueError) as e:
        msg = "the escrow bottle did not open with this entropy"
        raise EscrowError(msg) from e
    signing_x963, encryption_x963 = parse_ot_internal_bottle(plaintext)
    return RecoveredIdentity(
        peer_id=bottle.peer_id,
        signing_key=ok.load_peer_key_x963(signing_x963),
        encryption_key=ok.load_peer_key_x963(encryption_x963),
    )
