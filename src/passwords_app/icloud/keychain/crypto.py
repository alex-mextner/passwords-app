"""iCloud Keychain decryption: SF-ECIES (P-384 / X9.63-KDF / AES-256-GCM) and AES-256-SIV
key unwrap. See RESEARCH.md "keychain/crypto.py"."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV

from ..errors import AppleError


class KeychainCryptoError(AppleError):
    pass


def x963_kdf(secret: bytes, shared_info: bytes, length: int,
             hashfn=hashlib.sha256) -> bytes:
    out = bytearray()
    counter = 1
    while len(out) < length:
        out += hashfn(secret + counter.to_bytes(4, "big") + shared_info).digest()
        counter += 1
    return bytes(out[:length])


def ecies_decrypt(private_key: ec.EllipticCurvePrivateKey, ephemeral_sender_pub: bytes,
                  ciphertext: bytes, auth_code: bytes) -> bytes:
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        private_key.curve, ephemeral_sender_pub)
    secret = private_key.exchange(ec.ECDH(), eph_pub)
    derived = x963_kdf(secret, ephemeral_sender_pub, 48)
    key, iv = derived[:32], derived[32:48]
    return AESGCM(key).decrypt(iv, ciphertext + auth_code, None)


def ecies_decrypt_sf(private_key: ec.EllipticCurvePrivateKey, ies: dict) -> bytes:
    """Decrypt an Apple `IESCiphertext` dict (unarchived from a TLKShare `wrappedkey`)."""
    eph = bytes(ies["SFEphemeralSenderPublicKeyExternaRepresentation"])
    ct = bytes(ies["SFCiphertext"])
    tag = bytes(ies["SFIESAuthenticationCode"])
    # SecurityFoundation appends 97+16 bytes of junk to the stored ciphertext; trim it.
    real_ct = ct[:-(97 + 16)] if len(ct) > 97 + 16 else ct
    return ecies_decrypt(private_key, eph, real_ct, tag)


def siv_unwrap(key64: bytes, wrapped: bytes, associated_data=None) -> bytes:
    return AESSIV(key64).decrypt(wrapped, list(associated_data or []))


def _strip_iso7816_padding(data: bytes) -> bytes:
    ptr = len(data)
    while ptr > 0:
        ptr -= 1
        if data[ptr] == 0x00:
            continue
        if data[ptr] == 0x80:
            return data[:ptr]
        raise KeychainCryptoError("bad ISO-7816-4 padding")
    return data


def decrypt_item(item_key64: bytes, data: bytes, aad_values=None) -> bytes:
    """Decrypt an `item` record's `data` (= randomIV(16) || SIV(tag||ciphertext)). The leading
    random IV is prepended as the first associated-data element."""
    iv = data[:16]
    headers = [iv] + list(aad_values or [])
    plaintext = siv_unwrap(item_key64, data[16:], headers)
    return _strip_iso7816_padding(plaintext)
