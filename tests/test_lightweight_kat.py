"""Conformance tests for the five added lightweight AEAD schemes.

These tests are the reason the extension's numbers can be believed.  A timing
measurement of an implementation that computes the wrong function measures
nothing, so every algorithm added to the comparison must first reproduce the
published test vectors of its specification, byte for byte, for every
combination of plaintext length 0-32 and associated-data length 0-32 -- 1089
vectors each.

The pure-Python AES-128-CCM has no NIST-LWC vector file of its own; its
correctness is established instead by exact agreement with OpenSSL, an
independent and widely validated implementation of the same standard.
"""

from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from src.aead_interface import AuthenticationError
from src.lightweight import BY_NAME
from src.lightweight.aes_ccm import AesCcmPythonCipher

KAT_DIR = Path(__file__).resolve().parent.parent / "third_party" / "lwc_kat"

#: algorithm name -> vector file shipped in third_party/lwc_kat/
KAT_FILES = {
    "TinyJAMBU-128": "TinyJAMBU-128.txt",
    "Xoodyak": "Xoodyak.txt",
    "Schwaemm256-128": "Schwaemm256-128.txt",
    "GIFT-COFB": "GIFT-COFB.txt",
}


def _parse_kat(path: Path):
    """Yield one dict per Count/Key/Nonce/PT/AD/CT block in a KAT file."""
    block: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            if block:
                yield block
                block = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            block[key.strip()] = value.strip()
    if block:
        yield block


@pytest.mark.conformance
@pytest.mark.parametrize("algorithm", sorted(KAT_FILES))
def test_matches_official_vectors(algorithm):
    """Every published vector must encrypt and decrypt exactly."""
    cipher_cls = BY_NAME[algorithm]
    path = KAT_DIR / KAT_FILES[algorithm]
    count = 0
    for vector in _parse_kat(path):
        key = bytes.fromhex(vector["Key"])
        nonce = bytes.fromhex(vector["Nonce"])
        plaintext = bytes.fromhex(vector["PT"])
        aad = bytes.fromhex(vector["AD"])
        expected = bytes.fromhex(vector["CT"])
        cipher = cipher_cls(key)
        assert cipher.encrypt(nonce, plaintext, aad) == expected, (
            f"{algorithm} vector {vector['Count']}: encryption mismatch"
        )
        assert cipher.decrypt(nonce, expected, aad) == plaintext, (
            f"{algorithm} vector {vector['Count']}: decryption mismatch"
        )
        count += 1
    assert count > 1000, f"expected the full vector file for {algorithm}, read {count}"


@pytest.mark.conformance
def test_aes_ccm_matches_openssl():
    """The pure-Python CCM must agree with OpenSSL byte for byte."""
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    rng = random.Random(20260908)
    for _ in range(40):
        key, nonce = os.urandom(16), os.urandom(12)
        plaintext = os.urandom(rng.randint(0, 512))
        aad = os.urandom(rng.randint(0, 96))
        mine = AesCcmPythonCipher(key).encrypt(nonce, plaintext, aad)
        reference = AESCCM(key, tag_length=16).encrypt(nonce, plaintext, aad)
        assert mine == reference
        assert AesCcmPythonCipher(key).decrypt(nonce, reference, aad) == plaintext


@pytest.mark.parametrize("algorithm", sorted(BY_NAME))
def test_roundtrip_over_many_sizes(algorithm):
    """Encryption followed by decryption must be the identity, at awkward sizes."""
    cipher_cls = BY_NAME[algorithm]
    cipher = cipher_cls(cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    for size in (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 1000):
        plaintext = bytes((i * 7 + 3) % 256 for i in range(size))
        ciphertext = cipher.encrypt(nonce, plaintext, b"warehouse-header")
        assert len(ciphertext) == size + cipher_cls.tag_size
        assert cipher.decrypt(nonce, ciphertext, b"warehouse-header") == plaintext


@pytest.mark.parametrize("algorithm", sorted(BY_NAME))
def test_tampering_is_always_rejected(algorithm):
    """Flipping any single bit of the ciphertext or tag must fail verification."""
    cipher_cls = BY_NAME[algorithm]
    cipher = cipher_cls(cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    aad = b"\x01WH-001\x00\x00\x00\x05\x01"
    plaintext = b'{"device_id":"WH-001","temperature":24.75}'
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    for index in range(len(ciphertext)):
        for bit in (0, 7):
            corrupted = bytearray(ciphertext)
            corrupted[index] ^= 1 << bit
            with pytest.raises(AuthenticationError):
                cipher.decrypt(nonce, bytes(corrupted), aad)


@pytest.mark.parametrize("algorithm", sorted(BY_NAME))
def test_associated_data_is_authenticated(algorithm):
    """The header travels in clear but must still be covered by the tag."""
    cipher_cls = BY_NAME[algorithm]
    cipher = cipher_cls(cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    aad = b"\x01WH-001\x00\x00\x00\x05\x01"
    ciphertext = cipher.encrypt(nonce, b"gas_level=115", aad)
    for index in range(len(aad)):
        tampered = bytearray(aad)
        tampered[index] ^= 0x01
        with pytest.raises(AuthenticationError):
            cipher.decrypt(nonce, ciphertext, bytes(tampered))


@pytest.mark.parametrize("algorithm", sorted(BY_NAME))
def test_wrong_key_is_rejected(algorithm):
    cipher_cls = BY_NAME[algorithm]
    cipher = cipher_cls(cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    ciphertext = cipher.encrypt(nonce, b"humidity=63.2", b"aad")
    for _ in range(10):
        other = cipher_cls(cipher_cls.generate_key())
        with pytest.raises(AuthenticationError):
            other.decrypt(nonce, ciphertext, b"aad")


@pytest.mark.parametrize("algorithm", sorted(BY_NAME))
def test_truncated_ciphertext_is_rejected(algorithm):
    cipher_cls = BY_NAME[algorithm]
    cipher = cipher_cls(cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    ciphertext = cipher.encrypt(nonce, b"temperature=24.75", b"aad")
    for cut in (1, 2, 8):
        with pytest.raises(AuthenticationError):
            cipher.decrypt(nonce, ciphertext[:-cut], b"aad")
