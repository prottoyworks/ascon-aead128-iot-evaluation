"""Defensive security tests: every tampering scenario must be rejected.

Each test is parameterised over both ciphers, so neither is held to a weaker
standard.  All data is generated inside the test; nothing external is touched.
"""

from __future__ import annotations

import os

import pytest

from src.aead_interface import AuthenticationError
from src.aes_gcm import AesGcmCipher
from src.ascon_aead import AsconAead128Cipher, is_available
from src.config import QUICK
from src.security_tests import run_all, write_results
from src.sensor import SensorFleet
from src.serialization import split_reading

CIPHERS = [pytest.param(AesGcmCipher, id="AES-128-GCM")]
if is_available():
    CIPHERS.append(pytest.param(AsconAead128Cipher, id="Ascon-AEAD128"))

parametrise_ciphers = pytest.mark.parametrize("cipher_cls", CIPHERS)


@parametrise_ciphers
def test_a_valid_message_is_accepted(cipher_cls):
    """The control. Without it, a cipher that rejects everything would pass."""
    cipher = cipher_cls(cipher_cls.generate_key())
    plaintext, aad = os.urandom(64), os.urandom(32)
    result = cipher.seal(plaintext, aad)
    assert cipher.decrypt(result.nonce, result.ciphertext, aad) == plaintext


@parametrise_ciphers
def test_b_ciphertext_tampering_is_rejected(cipher_cls):
    """Every single-bit flip in the encrypted body must fail verification."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    body_length = len(result.ciphertext) - cipher_cls.tag_size

    for position in range(body_length):
        for bit in range(8):
            corrupted = bytearray(result.ciphertext)
            corrupted[position] ^= 1 << bit
            with pytest.raises(AuthenticationError):
                cipher.decrypt(result.nonce, bytes(corrupted), aad)


@parametrise_ciphers
def test_b2_tag_tampering_is_rejected(cipher_cls):
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    for offset in range(cipher_cls.tag_size):
        corrupted = bytearray(result.ciphertext)
        corrupted[-1 - offset] ^= 0x80
        with pytest.raises(AuthenticationError):
            cipher.decrypt(result.nonce, bytes(corrupted), aad)


@parametrise_ciphers
def test_c_aad_tampering_is_rejected(cipher_cls):
    """AAD is readable but not modifiable -- the central AEAD property."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    for position in range(len(aad)):
        corrupted = bytearray(aad)
        corrupted[position] ^= 0x01
        with pytest.raises(AuthenticationError):
            cipher.decrypt(result.nonce, result.ciphertext, bytes(corrupted))


@parametrise_ciphers
def test_c2_device_impersonation_via_aad_is_rejected(cipher_cls):
    """The concrete WH-001 -> WH-999 scenario from the project brief."""
    reading = SensorFleet(QUICK).next_reading("WH-001", 0)
    cipher = cipher_cls(cipher_cls.generate_key())
    aad, payload = split_reading(reading)
    result = cipher.seal(payload, aad)

    forged = aad.replace(b'"WH-001"', b'"WH-999"')
    assert forged != aad, "Substitution did not apply; test would be vacuous."
    with pytest.raises(AuthenticationError):
        cipher.decrypt(result.nonce, result.ciphertext, forged)


@parametrise_ciphers
def test_c3_aad_removal_is_rejected(cipher_cls):
    """Stripping the AAD entirely must fail, not silently succeed."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    with pytest.raises(AuthenticationError):
        cipher.decrypt(result.nonce, result.ciphertext, b"")


@parametrise_ciphers
def test_d_wrong_key_is_rejected(cipher_cls):
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    for _ in range(50):
        attacker = cipher_cls(cipher_cls.generate_key())
        with pytest.raises(AuthenticationError):
            attacker.decrypt(result.nonce, result.ciphertext, aad)


@parametrise_ciphers
def test_d2_single_bit_key_difference_is_rejected(cipher_cls):
    """Not even a near-miss key may work."""
    key = cipher_cls.generate_key()
    cipher = cipher_cls(key)
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)

    for position in range(len(key)):
        wrong = bytearray(key)
        wrong[position] ^= 0x01
        with pytest.raises(AuthenticationError):
            cipher_cls(bytes(wrong)).decrypt(result.nonce, result.ciphertext, aad)


@parametrise_ciphers
def test_e_truncated_ciphertext_is_rejected_safely(cipher_cls):
    """Must raise AuthenticationError -- never crash, never return plaintext."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(128), aad)

    for cut in range(1, len(result.ciphertext)):
        with pytest.raises(AuthenticationError):
            cipher.decrypt(result.nonce, result.ciphertext[:cut], aad)


@parametrise_ciphers
def test_e2_extended_ciphertext_is_rejected(cipher_cls):
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    with pytest.raises(AuthenticationError):
        cipher.decrypt(result.nonce, result.ciphertext + b"\x00", aad)


@parametrise_ciphers
def test_f_wrong_nonce_is_rejected(cipher_cls):
    """The nonce is bound into the tag, so a substituted nonce fails."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)
    for _ in range(50):
        with pytest.raises(AuthenticationError):
            cipher.decrypt(cipher.generate_nonce(), result.ciphertext, aad)


@parametrise_ciphers
def test_g_cross_algorithm_ciphertext_is_rejected(cipher_cls):
    """A ciphertext from the other algorithm must not verify under this one.

    Relevant to the crypto-agility work planned for the thesis: an attacker who
    can substitute an algorithm label must not gain anything.
    """
    if not is_available():
        pytest.skip("Needs both ciphers installed.")
    other_cls = AsconAead128Cipher if cipher_cls is AesGcmCipher else AesGcmCipher

    key = os.urandom(16)  # same key length for both, so the swap is possible
    aad = os.urandom(32)
    foreign = other_cls(key).seal(os.urandom(64), aad)

    cipher = cipher_cls(key)
    nonce = foreign.nonce[: cipher_cls.nonce_size].ljust(cipher_cls.nonce_size, b"\x00")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce, foreign.ciphertext, aad)


@parametrise_ciphers
def test_failures_do_not_reveal_which_check_failed(cipher_cls):
    """A receiver that explains the failure is an oracle. Messages must match."""
    cipher = cipher_cls(cipher_cls.generate_key())
    aad = os.urandom(32)
    result = cipher.seal(os.urandom(64), aad)

    messages = set()
    corrupted = bytearray(result.ciphertext)
    corrupted[0] ^= 0x01
    for attempt in (
        lambda: cipher.decrypt(result.nonce, bytes(corrupted), aad),
        lambda: cipher.decrypt(result.nonce, result.ciphertext, os.urandom(32)),
        lambda: cipher_cls(cipher_cls.generate_key()).decrypt(
            result.nonce, result.ciphertext, aad
        ),
    ):
        with pytest.raises(AuthenticationError) as info:
            attempt()
        messages.add(str(info.value))
    assert len(messages) == 1, f"Distinguishable failure messages: {messages}"


def test_full_security_suite_reports_all_passes(tmp_path):
    """The suite that writes results/security_results.csv must pass cleanly."""
    config = QUICK.with_overrides(security_trials=10)
    results = run_all(config)
    assert results, "Security suite produced no results."

    failed = [r for r in results if not r.passed]
    assert not failed, "Failing scenarios: " + ", ".join(
        f"{r.algorithm}/{r.test_id}" for r in failed
    )

    path = write_results(results, tmp_path / "security_results.csv")
    text = path.read_text(encoding="utf-8")
    assert "algorithm,test_id,test_name" in text
    assert "AES-128-GCM" in text


def test_security_suite_covers_the_required_scenarios():
    results = run_all(QUICK.with_overrides(security_trials=5))
    names = {r.test_name for r in results}
    for required in (
        "valid_message",
        "ciphertext_tampering",
        "aad_tampering",
        "wrong_key",
        "truncated_ciphertext",
        "replay_exact_duplicate",
    ):
        assert required in names, f"Missing scenario: {required}"
