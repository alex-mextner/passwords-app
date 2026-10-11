# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Keychain primitives: X9.63 KDF, SF-ECIES, AES-SIV wrap, Apple's item padding and sealing."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.fakes.cloudkit_server import ecies_encrypt_sf

from passwords_app.icloud.keychain import crypto as kc

KEY = bytes(range(64))


def test_x963_kdf_known_vector() -> None:
    # ANSI X9.63 KDF (SHA-256) vector without SharedInfo.
    z = bytes.fromhex("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08")
    assert kc.x963_kdf(z, b"", 16).hex() == "443024c3dae66b95e6f5670601558f71"


def test_x963_kdf_longer_output_extends_shorter() -> None:
    out = kc.x963_kdf(b"secret", b"info", 48)
    assert len(out) == 48
    assert kc.x963_kdf(b"secret", b"info", 32) == out[:32]


def test_x963_kdf_depends_on_shared_info() -> None:
    assert kc.x963_kdf(b"s", b"a", 32) != kc.x963_kdf(b"s", b"b", 32)


# --- padding -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("length", "padded"),
    [(0, 40), (1, 40), (19, 40), (20, 40), (21, 40), (39, 40), (40, 60), (59, 60), (60, 80)],
)
def test_apple_padding_lengths(length: int, padded: int) -> None:
    # 20 - len % 20 bytes (1..20), plus one more block when the data is under 20 bytes.
    assert len(kc.pad(b"x" * length)) == padded


def test_padding_starts_with_mark_then_zeros() -> None:
    out = kc.pad(b"abc")
    assert out[:3] == b"abc"
    assert out[3] == 0x80
    assert set(out[4:]) == {0}


@given(st.binary(max_size=300))
def test_unpad_inverts_pad(data: bytes) -> None:
    assert kc.unpad(kc.pad(data)) == data


@pytest.mark.parametrize("bad", [b"", b"\x00\x00", b"abc\x00", b"abc\x81\x00"])
def test_unpad_rejects_missing_mark(bad: bytes) -> None:
    with pytest.raises(kc.KeychainCryptoError, match="padding"):
        kc.unpad(bad)


# --- AES-SIV -------------------------------------------------------------------------------------


def test_wrapped_item_key_is_80_bytes_and_unwraps() -> None:
    item_key = kc.new_item_key()
    wrapped = kc.wrap_item_key(KEY, item_key)
    assert len(wrapped) == kc.WRAPPED_KEY_SIZE
    assert kc.siv_unwrap(KEY, wrapped) == item_key


def test_key_wrap_is_deterministic_without_nonce() -> None:
    # SIV with no nonce and no AAD: wrapping the same key twice gives the same bytes.
    assert kc.siv_wrap(KEY, b"k" * 64) == kc.siv_wrap(KEY, b"k" * 64)


def test_unwrap_with_wrong_key_raises_crypto_error() -> None:
    wrapped = kc.wrap_item_key(KEY, kc.new_item_key())
    with pytest.raises(kc.KeychainCryptoError):
        kc.siv_unwrap(os.urandom(64), wrapped)


def test_new_item_keys_are_random_64_bytes() -> None:
    a, b = kc.new_item_key(), kc.new_item_key()
    assert len(a) == len(b) == 64
    assert a != b


# --- item sealing --------------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(plaintext=st.binary(max_size=500), aad=st.lists(st.binary(max_size=40), max_size=6))
def test_encrypt_then_decrypt_is_identity(plaintext: bytes, aad: list[bytes]) -> None:
    sealed = kc.encrypt_item(KEY, plaintext, aad)
    assert kc.decrypt_item(KEY, sealed, aad) == plaintext


def test_sealed_layout_is_nonce_then_tag_then_padded_ciphertext() -> None:
    nonce = b"N" * 16
    sealed = kc.encrypt_item(KEY, b"hello", [], nonce=nonce)
    assert sealed[:16] == nonce
    assert len(sealed) == 16 + 16 + len(kc.pad(b"hello"))


def test_nonce_is_authenticated_as_first_aad_element() -> None:
    sealed = bytearray(kc.encrypt_item(KEY, b"hello", [b"a"]))
    sealed[0] ^= 1
    with pytest.raises(kc.KeychainCryptoError):
        kc.decrypt_item(KEY, bytes(sealed), [b"a"])


@pytest.mark.parametrize("aad", [[b"b"], [b"a", b"x"], [], [b"A"]])
def test_associated_data_must_match(aad: list[bytes]) -> None:
    sealed = kc.encrypt_item(KEY, b"hello", [b"a"])
    with pytest.raises(kc.KeychainCryptoError):
        kc.decrypt_item(KEY, sealed, aad)


def test_associated_data_order_matters() -> None:
    sealed = kc.encrypt_item(KEY, b"x", [b"1", b"2"])
    with pytest.raises(kc.KeychainCryptoError):
        kc.decrypt_item(KEY, sealed, [b"2", b"1"])


def test_random_nonces_differ() -> None:
    assert kc.encrypt_item(KEY, b"x") != kc.encrypt_item(KEY, b"x")


def test_short_item_data_is_rejected() -> None:
    with pytest.raises(kc.KeychainCryptoError, match="too short"):
        kc.decrypt_item(KEY, b"\x00" * 20)


# --- SF-ECIES ------------------------------------------------------------------------------------


def test_ecies_round_trip_with_security_foundation_trailer() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    ies = ecies_encrypt_sf(key.public_key(), b"the tlk")
    assert kc.ecies_decrypt_sf(key, ies) == b"the tlk"


def test_ecies_to_another_key_fails_authentication() -> None:
    ies = ecies_encrypt_sf(ec.generate_private_key(ec.SECP384R1()).public_key(), b"tlk")
    with pytest.raises(kc.KeychainCryptoError):
        kc.ecies_decrypt_sf(ec.generate_private_key(ec.SECP384R1()), ies)


@pytest.mark.parametrize(
    "missing",
    ["SFEphemeralSenderPublicKeyExternaRepresentation", "SFCiphertext", "SFIESAuthenticationCode"],
)
def test_ecies_missing_field_is_an_error(missing: str) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    ies: dict[str, object] = dict(ecies_encrypt_sf(key.public_key(), b"x"))
    del ies[missing]
    with pytest.raises(kc.KeychainCryptoError, match="missing"):
        kc.ecies_decrypt_sf(key, ies)
