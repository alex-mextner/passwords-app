# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""iCloud Keychain primitives: SF-ECIES (P-384 / X9.63-KDF / AES-256-GCM) and AES-256-SIV.

Item layout (Apple Security, CKKSSIV.m / CKKSItemEncrypter.m): a random 64-byte item key is
SIV-wrapped by the class key with no nonce and no associated data; the item plist is padded to
a 20-byte block (ISO 7816-4 mark 0x80) and SIV-sealed under the item key with a random 16-byte
nonce as the first associated-data element; `data` = nonce || tag || ciphertext.
"""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV

from passwords_app.icloud.errors import AppleError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

ITEM_KEY_SIZE = 64
WRAPPED_KEY_SIZE = 80  # SIV tag (16) + 64-byte key
NONCE_SIZE = 16
PAD_BLOCK = 20
_PAD_MARK = 0x80
# SecurityFoundation appends a 97-byte public key and a 16-byte tag after the real ciphertext.
_SF_TRAILER = 97 + 16


class KeychainCryptoError(AppleError):
    """A key or item failed to decrypt, or its padding is malformed."""


def x963_kdf(secret: bytes, shared_info: bytes, length: int) -> bytes:
    """ANSI X9.63 KDF with SHA-256, the only hash SF-ECIES on P-384 uses."""
    out = bytearray()
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(secret + counter.to_bytes(4, "big") + shared_info).digest()
        counter += 1
    return bytes(out[:length])


def ecies_decrypt(
    private_key: ec.EllipticCurvePrivateKey,
    ephemeral_sender_pub: bytes,
    ciphertext: bytes,
    auth_code: bytes,
) -> bytes:
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(private_key.curve, ephemeral_sender_pub)
    secret = private_key.exchange(ec.ECDH(), eph_pub)
    derived = x963_kdf(secret, ephemeral_sender_pub, 48)
    key, iv = derived[:32], derived[32:48]
    try:
        return AESGCM(key).decrypt(iv, ciphertext + auth_code, None)
    except InvalidTag as e:
        msg = "ECIES ciphertext failed authentication"
        raise KeychainCryptoError(msg) from e


def ecies_decrypt_sf(private_key: ec.EllipticCurvePrivateKey, ies: Mapping[str, object]) -> bytes:
    """Decrypt an Apple `IESCiphertext` dict (unarchived from a TLKShare `wrappedkey`)."""
    eph, ct, tag = (
        ies.get("SFEphemeralSenderPublicKeyExternaRepresentation"),
        ies.get("SFCiphertext"),
        ies.get("SFIESAuthenticationCode"),
    )
    if not (isinstance(eph, bytes) and isinstance(ct, bytes) and isinstance(tag, bytes)):
        msg = "IESCiphertext is missing a field"
        raise KeychainCryptoError(msg)
    real_ct = ct[:-_SF_TRAILER] if len(ct) > _SF_TRAILER else ct
    return ecies_decrypt(private_key, eph, real_ct, tag)


def siv_unwrap(key64: bytes, wrapped: bytes, associated_data: Iterable[bytes] = ()) -> bytes:
    try:
        return AESSIV(key64).decrypt(wrapped, list(associated_data))
    except (InvalidTag, ValueError) as e:
        msg = "AES-SIV authentication failed"
        raise KeychainCryptoError(msg) from e


def siv_wrap(key64: bytes, plaintext: bytes, associated_data: Iterable[bytes] = ()) -> bytes:
    """AES-SIV seal: tag(16) || ciphertext. Wrapping a key passes no associated data."""
    return AESSIV(key64).encrypt(plaintext, list(associated_data))


def pad(data: bytes) -> bytes:
    """Apple's item padding: 1..20 bytes to the next 20-byte block, one extra block if short.

    The extra block hides the length of short secrets; the mark byte 0x80 starts the padding.
    """
    length = PAD_BLOCK - len(data) % PAD_BLOCK
    if len(data) < PAD_BLOCK:
        length += PAD_BLOCK
    return data + bytes([_PAD_MARK]) + bytes(length - 1)


def unpad(data: bytes) -> bytes:
    stripped = data.rstrip(b"\x00")
    if not stripped or stripped[-1] != _PAD_MARK:
        msg = "bad ISO-7816-4 padding"
        raise KeychainCryptoError(msg)
    return stripped[:-1]


def decrypt_item(item_key64: bytes, data: bytes, aad_values: Iterable[bytes] = ()) -> bytes:
    """Open an item record's `data`; the leading nonce is the first associated-data element."""
    if len(data) < NONCE_SIZE + 16:
        msg = "item data is too short"
        raise KeychainCryptoError(msg)
    nonce = data[:NONCE_SIZE]
    plaintext = siv_unwrap(item_key64, data[NONCE_SIZE:], [nonce, *aad_values])
    return unpad(plaintext)


def encrypt_item(
    item_key64: bytes,
    plaintext: bytes,
    aad_values: Iterable[bytes] = (),
    *,
    nonce: bytes | None = None,
) -> bytes:
    """Inverse of `decrypt_item`: nonce || SIV(pad(plaintext)) under the item key."""
    nonce = os.urandom(NONCE_SIZE) if nonce is None else nonce
    return nonce + siv_wrap(item_key64, pad(plaintext), [nonce, *aad_values])


def new_item_key() -> bytes:
    return os.urandom(ITEM_KEY_SIZE)


def wrap_item_key(class_key64: bytes, item_key64: bytes) -> bytes:
    wrapped = siv_wrap(class_key64, item_key64)
    if len(wrapped) != WRAPPED_KEY_SIZE:  # pragma: no cover - AES-SIV fixes the size
        msg = "wrapped item key has the wrong size"
        raise KeychainCryptoError(msg)
    return wrapped
