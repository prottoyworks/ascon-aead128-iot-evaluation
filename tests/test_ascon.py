"""Correctness tests for the Ascon-AEAD128 wrapper.

These mirror ``test_aes.py`` case for case.  Running the same battery against
both ciphers is what makes the comparison fair: neither algorithm is held to a
weaker standard of correctness than the other.
"""

from __future__ import annotations

import os

import pytest

from src.aead_interface import AuthenticationError
from src.ascon_aead import AsconAead128Cipher, new_cipher
from src.config import QUICK
from src.sensor import generate_dataset
from src.serialization import split_reading
from tests.conftest import requires_ascon

pytestmark = requires_ascon


def test_declared_parameters_match_sp800_232():
    assert AsconAead128Cipher.key_size == 16    # 128-bit key
    assert AsconAead128Cipher.nonce_size == 16  # 128-bit nonce
    assert AsconAead128Cipher.tag_size == 16    # 128-bit tag


def test_nonce_is_longer_than_aes_gcm():
    """A documented difference between the two schemes, not an error."""
    from src.aes_gcm import AesGcmCipher

    assert AsconAead128Cipher.nonce_size > AesGcmCipher.nonce_size


def test_generated_keys_have_the_right_length_and_differ():
    keys = {AsconAead128Cipher.generate_key() for _ in range(100)}
    assert all(len(k) == 16 for k in keys)
    assert len(keys) == 100


def test_generated_nonces_differ():
    nonces = {AsconAead128Cipher.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000


def test_rejects_a_wrong_length_key():
    with pytest.raises(ValueError, match="16-byte key"):
        AsconAead128Cipher(b"tooshort")


def test_rejects_a_wrong_length_nonce(ascon_cipher: AsconAead128Cipher):
    with pytest.raises(ValueError, match="16-byte nonce"):
        ascon_cipher.encrypt(b"short", b"data", b"")


def test_simple_round_trip(ascon_cipher: AsconAead128Cipher):
    plaintext = b"temperature=24.75"
    nonce = ascon_cipher.generate_nonce()
    ciphertext = ascon_cipher.encrypt(nonce, plaintext, b"")
    assert ascon_cipher.decrypt(nonce, ciphertext, b"") == plaintext


def test_round_trip_with_associated_data(ascon_cipher: AsconAead128Cipher):
    plaintext = b"payload"
    aad = b'{"device_id":"WH-001"}'
    nonce = ascon_cipher.generate_nonce()
    ciphertext = ascon_cipher.encrypt(nonce, plaintext, aad)
    assert ascon_cipher.decrypt(nonce, ciphertext, aad) == plaintext


def test_round_trip_of_real_iot_messages():
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


def test_empty_plaintext_round_trips(ascon_cipher: AsconAead128Cipher):
    nonce = ascon_cipher.generate_nonce()
    ciphertext = ascon_cipher.encrypt(nonce, b"", b"aad")
    assert len(ciphertext) == AsconAead128Cipher.tag_size
    assert ascon_cipher.decrypt(nonce, ciphertext, b"aad") == b""


def test_block_boundary_sizes_round_trip(ascon_cipher: AsconAead128Cipher):
    """Ascon-AEAD128 has a 16-byte rate; padding bugs show up at the edges."""
    for size in (0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49):
        nonce = ascon_cipher.generate_nonce()
        for aad_size in (0, 1, 15, 16, 17):
            aad = os.urandom(aad_size)
            plaintext = os.urandom(size)
            ciphertext = ascon_cipher.encrypt(nonce, plaintext, aad)
            assert ascon_cipher.decrypt(nonce, ciphertext, aad) == plaintext


def test_ciphertext_expands_by_exactly_the_tag_length(ascon_cipher: AsconAead128Cipher):
    for size in (0, 1, 15, 16, 17, 512, 4096):
        result = ascon_cipher.seal(os.urandom(size), b"aad")
        assert result.expansion_bytes == AsconAead128Cipher.tag_size
        assert result.ciphertext_size == size + 16


def test_wire_overhead_includes_the_transmitted_nonce(ascon_cipher: AsconAead128Cipher):
    result = ascon_cipher.seal(os.urandom(64), b"aad")
    assert result.wire_overhead_bytes == 16 + 16  # tag + 128-bit nonce


def test_encryption_is_randomised_by_the_nonce(ascon_cipher: AsconAead128Cipher):
    plaintext = b"same message every time"
    outputs = {ascon_cipher.seal(plaintext, b"").ciphertext for _ in range(50)}
    assert len(outputs) == 50


def test_decrypt_raises_instead_of_returning_none(ascon_cipher: AsconAead128Cipher):
    """The reference implementation returns None on failure; the wrapper must
    convert that into an exception, or a caller could proceed with None."""
    nonce = ascon_cipher.generate_nonce()
    ciphertext = bytearray(ascon_cipher.encrypt(nonce, b"payload", b"aad"))
    ciphertext[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        ascon_cipher.decrypt(nonce, bytes(ciphertext), b"aad")


def test_decrypt_rejects_ciphertext_shorter_than_the_tag(ascon_cipher: AsconAead128Cipher):
    """Must be an AuthenticationError, not the reference code's AssertionError."""
    nonce = ascon_cipher.generate_nonce()
    with pytest.raises(AuthenticationError):
        ascon_cipher.decrypt(nonce, b"\x00" * 8, b"")


def test_repr_does_not_leak_key_material(deterministic_key: bytes):
    cipher = AsconAead128Cipher(deterministic_key)
    assert deterministic_key.hex() not in repr(cipher)


def test_output_differs_from_the_obsolete_v12_variants(ascon_cipher):
    """Guard against silently loading an Ascon v1.2 implementation.

    If the loader ever picked up the PyPI ``ascon`` package, this project would
    be measuring the wrong algorithm.  The loader rejects it, and the KAT suite
    proves conformance; this test is a third, cheap tripwire on the variant
    name actually reaching the reference code.
    """
    from src.ascon_loader import ASCON_VARIANT, load_ascon_module

    assert ASCON_VARIANT == "Ascon-AEAD128"
    module = load_ascon_module()
    with pytest.raises((AssertionError, KeyError)):
        module.ascon_encrypt(bytes(16), bytes(16), b"", b"", "Ascon-128")
