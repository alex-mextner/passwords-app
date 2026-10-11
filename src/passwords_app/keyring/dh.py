# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Transport encryption for secrets on the session bus (Secret Service ``dh-ietf1024-...``).

With the ``plain`` algorithm every password we read or write would cross the bus in clear,
visible to anything that can eavesdrop on it (``dbus-monitor``). The spec's algorithm is a
Diffie-Hellman exchange over the RFC 2409 1024-bit MODP group, HKDF-SHA256 (no salt, no
info) to a 128-bit key, then AES-128-CBC with PKCS#7 padding and a fresh IV per secret —
exactly what libsecret and gnome-keyring implement, so this interoperates with both.
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHM = "dh-ietf1024-sha256-aes128-cbc-pkcs7"

# RFC 2409 §6.2, Second Oakley Group.
_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)
_GENERATOR = 2
_KEY_BYTES = 128
_AES_KEY_BYTES = 16
_BLOCK_BYTES = 16


class SessionCryptoError(ValueError):
    """The peer sent a key or ciphertext that cannot be valid."""


class SessionCipher:
    """AES-128-CBC with the key agreed for one Secret Service session."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) != _AES_KEY_BYTES:
            msg = "session key must be 16 bytes"
            raise SessionCryptoError(msg)
        self._key = key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Return ``(iv, ciphertext)``; the IV is random for every call."""
        iv = os.urandom(_BLOCK_BYTES)
        padder = padding.PKCS7(_BLOCK_BYTES * 8).padder()
        padded = padder.update(plaintext) + padder.finalize()
        # nosemgrep: crypto-mode-without-authentication - Secret Service DH sessions are CBC
        encryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv)).encryptor()
        return iv, encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        if len(iv) != _BLOCK_BYTES:
            msg = "IV must be 16 bytes"
            raise SessionCryptoError(msg)
        if not ciphertext or len(ciphertext) % _BLOCK_BYTES:
            msg = "ciphertext is not a whole number of AES blocks"
            raise SessionCryptoError(msg)
        # nosemgrep: crypto-mode-without-authentication - Secret Service DH sessions are CBC
        decryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(_BLOCK_BYTES * 8).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            msg = "bad padding (wrong session key or corrupted secret)"
            raise SessionCryptoError(msg) from exc


class DhKeyExchange:
    """Our half of the exchange: send `public_key`, then `agree` on the peer's reply."""

    __slots__ = ("_private", "public_key")

    def __init__(self) -> None:
        self._private = secrets.randbelow(_PRIME - 3) + 2
        self.public_key = pow(_GENERATOR, self._private, _PRIME).to_bytes(_KEY_BYTES, "big")

    def agree(self, peer_public_key: bytes) -> SessionCipher:
        if len(peer_public_key) > _KEY_BYTES:
            msg = "peer public key is longer than the group"
            raise SessionCryptoError(msg)
        peer = int.from_bytes(peer_public_key, "big")
        # 0, 1 and p-1 (and anything outside the group) would force a known shared secret.
        if not 1 < peer < _PRIME - 1:
            msg = "peer public key is outside the safe range"
            raise SessionCryptoError(msg)
        shared = pow(peer, self._private, _PRIME).to_bytes(_KEY_BYTES, "big")
        key = HKDF(algorithm=hashes.SHA256(), length=_AES_KEY_BYTES, salt=None, info=b"").derive(
            shared
        )
        return SessionCipher(key)
