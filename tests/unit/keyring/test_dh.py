# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Secret Service transport crypto; interop with gnome-keyring is in the integration suite."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from passwords_app.keyring.dh import (
    ALGORITHM,
    DhKeyExchange,
    SessionCipher,
    SessionCryptoError,
)

PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)


def _hkdf_sha256_16(ikm: bytes) -> bytes:
    # RFC 5869 by hand: an independent check of the KDF parameters libsecret uses.
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, b"\x01", hashlib.sha256).digest()[:16]


def test_algorithm_name_is_the_encrypted_one() -> None:
    assert ALGORITHM == "dh-ietf1024-sha256-aes128-cbc-pkcs7"


def test_both_sides_agree_on_the_same_key() -> None:
    client, server = DhKeyExchange(), DhKeyExchange()
    to_server = client.agree(server.public_key)
    to_client = server.agree(client.public_key)
    iv, ciphertext = to_server.encrypt("пароль 🔑".encode())
    assert to_client.decrypt(iv, ciphertext).decode() == "пароль 🔑"


def test_key_matches_rfc5869_over_the_padded_shared_secret() -> None:
    client, server = DhKeyExchange(), DhKeyExchange()
    cipher = client.agree(server.public_key)
    shared = pow(int.from_bytes(server.public_key, "big"), client._private, PRIME).to_bytes(
        128, "big"
    )
    expected = SessionCipher(_hkdf_sha256_16(shared))
    iv, ciphertext = cipher.encrypt(b"x")
    assert expected.decrypt(iv, ciphertext) == b"x"


def test_public_key_is_always_full_width_and_in_range() -> None:
    for _ in range(20):
        key = DhKeyExchange().public_key
        assert len(key) == 128
        assert 1 < int.from_bytes(key, "big") < PRIME - 1


def test_each_exchange_uses_a_fresh_private_key() -> None:
    assert len({DhKeyExchange().public_key for _ in range(10)}) == 10


def test_short_peer_key_with_leading_zero_bytes_is_accepted() -> None:
    # gnome-keyring may send the minimal big-endian encoding.
    client = DhKeyExchange()
    client.agree((12345).to_bytes(2, "big"))


@pytest.mark.parametrize(
    "peer",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x00" * 128, id="zero"),
        pytest.param((1).to_bytes(128, "big"), id="one"),
        pytest.param((PRIME - 1).to_bytes(128, "big"), id="p-1"),
        pytest.param(PRIME.to_bytes(128, "big"), id="p"),
        pytest.param(b"\xff" * 128, id="above-p"),
        pytest.param(b"\x01" * 129, id="too-long"),
    ],
)
def test_degenerate_peer_keys_are_refused(peer: bytes) -> None:
    with pytest.raises(SessionCryptoError):
        DhKeyExchange().agree(peer)


@pytest.fixture
def cipher() -> SessionCipher:
    return SessionCipher(bytes(range(16)))


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 33, 1000])
def test_round_trip_across_block_boundaries(cipher: SessionCipher, size: int) -> None:
    plaintext = bytes(i % 251 for i in range(size))
    iv, ciphertext = cipher.encrypt(plaintext)
    assert len(ciphertext) == (size // 16 + 1) * 16  # PKCS#7 always adds padding
    assert cipher.decrypt(iv, ciphertext) == plaintext


def test_same_plaintext_encrypts_differently_each_time(cipher: SessionCipher) -> None:
    first, second = cipher.encrypt(b"same"), cipher.encrypt(b"same")
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_ciphertext_does_not_contain_the_plaintext(cipher: SessionCipher) -> None:
    secret = b"correct horse battery staple"
    _, ciphertext = cipher.encrypt(secret)
    assert secret not in ciphertext


@pytest.mark.parametrize("iv_size", [0, 8, 15, 17, 32])
def test_bad_iv_length_is_refused(cipher: SessionCipher, iv_size: int) -> None:
    _, ciphertext = cipher.encrypt(b"x")
    with pytest.raises(SessionCryptoError, match="IV"):
        cipher.decrypt(b"\0" * iv_size, ciphertext)


@pytest.mark.parametrize("size", [0, 1, 15, 17])
def test_partial_block_ciphertext_is_refused(cipher: SessionCipher, size: int) -> None:
    with pytest.raises(SessionCryptoError, match="blocks"):
        cipher.decrypt(b"\0" * 16, b"\0" * size)


def test_tampered_last_block_fails_padding(cipher: SessionCipher) -> None:
    iv, ciphertext = cipher.encrypt(b"exactly sixteen!")  # last block is pure padding
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
    with pytest.raises(SessionCryptoError, match="padding"):
        cipher.decrypt(iv, tampered)


@pytest.mark.parametrize("size", [0, 15, 17, 32])
def test_session_key_must_be_aes128(size: int) -> None:
    with pytest.raises(SessionCryptoError):
        SessionCipher(b"\0" * size)
