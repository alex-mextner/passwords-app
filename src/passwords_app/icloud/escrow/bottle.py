"""Escrow-recovery join: decrypt the EscrowBottle (after the gated SRP in escrow/srp) into the
recovered old peer keys, then sign a voucher that lets our new peer join. Pure offline crypto.

See RESEARCH.md "escrow/bottle.py" for the HKDF/AES-GCM derivation chain and voucher signing.
"""

from __future__ import annotations

import dataclasses

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..octagon import keys as ok
from ..proto.codec import Writer, decode_fields, first
from ..proto.cuttlefish import SignedBlob, encode_voucher
from ..errors import AppleError

# NIST P-384 group order n (public constant).
_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffff"
    "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)

_HKDF_INFO_SYM = b"Escrow Symmetric Key"
_HKDF_INFO_SIGNING = b"Escrow Signing Private Key"
_HKDF_INFO_ENCRYPTION = b"Escrow Encryption Private Key"


class EscrowError(AppleError):
    pass


def parse_ot_private_key(raw: bytes) -> bytes:
    """OTPrivateKey{ keyType(1), keyData(2) } -> keyData (X9.63 EC private)."""
    return first(decode_fields(raw), 2, b"")


def parse_ot_internal_bottle(raw: bytes) -> tuple[bytes, bytes]:
    """OTInternalBottle{ signingKey(3), encryptionKey(4) } -> (signing X9.63, encryption X9.63)."""
    f = decode_fields(raw)
    return parse_ot_private_key(first(f, 3)), parse_ot_private_key(first(f, 4))


@dataclasses.dataclass
class OTBottle:
    escrowed_signing_key: bytes      # SPKI DER (verification pubkey)
    escrowed_encryption_key: bytes   # SPKI DER
    ct: bytes
    auth_code: bytes
    iv: bytes
    peer_id: str = ""
    bottle_id: str = ""

    @classmethod
    def parse(cls, raw: bytes) -> "OTBottle":
        f = decode_fields(raw)
        cf = decode_fields(first(f, 12))
        return cls(
            escrowed_signing_key=first(f, 8, b""),
            escrowed_encryption_key=first(f, 9, b""),
            ct=first(cf, 1, b""), auth_code=first(cf, 2, b""), iv=first(cf, 3, b""),
            peer_id=(first(f, 1, b"") or b"").decode("utf-8", "replace"),
            bottle_id=(first(f, 2, b"") or b"").decode("utf-8", "replace"))

    def encode(self) -> bytes:
        cipher = (Writer().bytes(1, self.ct).bytes(2, self.auth_code).bytes(3, self.iv).finish())
        return (Writer()
                .string(1, self.peer_id).string(2, self.bottle_id)
                .bytes(8, self.escrowed_signing_key).bytes(9, self.escrowed_encryption_key)
                .message(12, cipher).finish())


def _hkdf_sha384(entropy: bytes, adsid: str, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=length,
                salt=adsid.encode("utf-8"), info=info).derive(entropy)


def derive_symmetric_key(entropy: bytes, adsid: str) -> bytes:
    return _hkdf_sha384(entropy, adsid, _HKDF_INFO_SYM, 32)


def derive_ec_private_key(entropy: bytes, adsid: str, info: bytes) -> ec.EllipticCurvePrivateKey:
    """HKDF-SHA384 -> 56 bytes -> FIPS 186-4 B.5.1 (mod (n-1), +1) -> P-384 private key."""
    raw = _hkdf_sha384(entropy, adsid, info, 56)
    d = (int.from_bytes(raw, "big") % (_P384_ORDER - 1)) + 1
    return ec.derive_private_key(d, ec.SECP384R1())


@dataclasses.dataclass
class RecoveredIdentity:
    peer_id: str
    signing_key: ok.PeerKey
    encryption_key: ok.PeerKey

    def make_voucher(self, beneficiary_peer_id: str, reason: int = 1) -> SignedBlob:
        """Sign a Voucher{reason, beneficiary, sponsor=self} with the recovered signing key -
        the credential our new peer presents to joinWithVoucher."""
        info = encode_voucher(reason, beneficiary_peer_id, self.peer_id)
        sig = self.signing_key.sign_sha384(
            ok._prefixed_data(info, ok.VOUCHER_SIG_TYPE))
        return SignedBlob(info=info, sig=sig)


def recover_identity(bottle: OTBottle, entropy: bytes, adsid: str) -> RecoveredIdentity:
    """Decrypt an OTBottle with the escrow entropy -> the recovered old peer's P-384 keys.
    Wrong entropy/adsid derives the wrong symmetric key and the AES-GCM tag check rejects it."""
    key = derive_symmetric_key(entropy, adsid)
    try:
        plaintext = AESGCM(key).decrypt(bottle.iv, bottle.ct + bottle.auth_code, None)
    except Exception as e:
        raise EscrowError(f"bottle AES-GCM decrypt failed: {e}") from e

    signing_x963, encryption_x963 = parse_ot_internal_bottle(plaintext)
    return RecoveredIdentity(
        peer_id=bottle.peer_id,
        signing_key=ok.load_peer_key_x963(signing_x963),
        encryption_key=ok.load_peer_key_x963(encryption_x963))
