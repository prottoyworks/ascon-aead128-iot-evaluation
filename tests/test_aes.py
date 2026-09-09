"""Correctness tests for the AES-128-GCM wrapper."""

from __future__ import annotations

import os

import pytest

from src.aead_interface import AuthenticationError
from src.aes_gcm import AesGcmCipher, new_cipher
from src.config import QUICK
from src.sensor import generate_dataset
from src.serialization import split_reading


def test_declared_parameters_match_the_standard():
    assert AesGcmCipher.key_size == 16    # 128-bit key
    assert AesGcmCipher.nonce_size == 12  # 96-bit nonce, per SP 800-38D
    assert AesGcmCipher.tag_size == 16    # 128-bit tag


def test_generated_keys_have_the_right_length_and_differ():
    keys = {AesGcmCipher.generate_key() for _ in range(100)}
    assert all(len(k) == 16 for k in keys)
    # 100 identical 128-bit keys would mean the CSPRNG is broken.
    assert len(keys) == 100


def test_generated_nonces_differ():
    nonces = {AesGcmCipher.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000


def test_rejects_a_wrong_length_key():
    with pytest.raises(ValueError, match="16-byte key"):
        AesGcmCipher(b"tooshort")


def test_rejects_a_wrong_length_nonce(aes_cipher: AesGcmCipher):
    with pytest.raises(ValueError, match="12-byte nonce"):
        aes_cipher.encrypt(b"short", b"data", b"")


def test_simple_round_trip(aes_cipher: AesGcmCipher):
    plaintext = b"temperature=24.75"
    nonce = aes_cipher.generate_nonce()
    ciphertext = aes_cipher.encrypt(nonce, plaintext, b"")
    assert aes_cipher.decrypt(nonce, ciphertext, b"") == plaintext


def test_round_trip_with_associated_data(aes_cipher: AesGcmCipher):
    plaintext = b"payload"
    aad = b'{"device_id":"WH-001"}'
    nonce = aes_cipher.generate_nonce()
    ciphertext = aes_cipher.encrypt(nonce, plaintext, aad)
    assert aes_cipher.decrypt(nonce, ciphertext, aad) == plaintext


def test_round_trip_of_real_iot_messages():
    """Every synthetic message must survive an encrypt/decrypt cycle."""
    cipher = new_cipher()
    for reading in generate_dataset(QUICK)[:200]:
        aad, payload = split_reading(reading)
        result = cipher.seal(payload, aad)
        assert cipher.decrypt(result.nonce, result.ciphertext, aad) == payload


def test_one_hundred_random_round_trips():
    cipher = new_cipher()
    for _ in range(100):
        plaintext = os.urandom(int.from_bytes(os.urandom(1), "big") + 1)
        aad = os.urandom(16)
        result = cipher.seal(plaintext, aad)
        assert cipher.decrypt(result.nonce, result.ciphertext, aad) == plaintext


def test_empty_plaintext_round_trips(aes_cipher: AesGcmCipher):
    """An empty message is still authenticated -- output is exactly the tag."""
    nonce = aes_cipher.generate_nonce()
    ciphertext = aes_cipher.encrypt(nonce, b"", b"aad")
    assert len(ciphertext) == AesGcmCipher.tag_size
    assert aes_cipher.decrypt(nonce, ciphertext, b"aad") == b""


def test_ciphertext_expands_by_exactly_the_tag_length(aes_cipher: AesGcmCipher):
    for size in (0, 1, 15, 16, 17, 512, 4096):
        result = aes_cipher.seal(os.urandom(size), b"aad")
        assert result.expansion_bytes == AesGcmCipher.tag_size
        assert result.ciphertext_size == size + 16


def test_wire_overhead_includes_the_transmitted_nonce(aes_cipher: AesGcmCipher):
    result = aes_cipher.seal(os.urandom(64), b"aad")
    assert result.wire_overhead_bytes == 16 + 12  # tag + nonce


def test_encryption_is_randomised_by_the_nonce(aes_cipher: AesGcmCipher):
    """Two seals of identical plaintext must differ -- otherwise the nonce
    is not doing its job and equal messages would be linkable."""
    plaintext = b"same message every time"
    outputs = {aes_cipher.seal(plaintext, b"").ciphertext for _ in range(50)}
    assert len(outputs) == 50


def test_different_aad_produces_a_different_tag(aes_cipher: AesGcmCipher):
    nonce = aes_cipher.generate_nonce()
    plaintext = b"payload"
    a = aes_cipher.encrypt(nonce, plaintext, b"aad-one")
    b = aes_cipher.encrypt(nonce, plaintext, b"aad-two")
    # Same keystream, so the bodies match; only the tag can differ.
    assert a[:-16] == b[:-16]
    assert a[-16:] != b[-16:]


def test_decrypt_rejects_ciphertext_shorter_than_the_tag(aes_cipher: AesGcmCipher):
    nonce = aes_cipher.generate_nonce()
    with pytest.raises(AuthenticationError):
        aes_cipher.decrypt(nonce, b"\x00" * 8, b"")


def test_repr_does_not_leak_key_material(deterministic_key: bytes):
    cipher = AesGcmCipher(deterministic_key)
    text = repr(cipher)
    assert deterministic_key.hex() not in text
    assert "00112233" not in text
