"""Defensive security experiments: demonstrating AEAD guarantees empirically.

Scope and ethics
----------------
Every routine in this file operates exclusively on data this process generated
moments earlier, under keys this process generated moments earlier, entirely in
memory.  Nothing here scans, connects to, or attacks any system.  The "attacker"
is a function that flips a bit in a byte string the test itself produced.  This
is the standard way to demonstrate a security property in a laboratory setting:
show that the defence fires when the defined condition occurs.

What each test establishes
--------------------------
================  =========================================================
Test              Property demonstrated
================  =========================================================
A  valid          Correctness: a genuine message is accepted (a rejection
                  rate of 100% would pass every other test trivially, so this
                  control is essential, not decorative)
B  ciphertext     Integrity of the encrypted payload
C  AAD            Integrity of the cleartext-but-authenticated metadata
D  wrong key      Authentication: only a key holder can produce a valid tag
E  truncation     Safe failure on malformed input -- no crash, no partial
                  plaintext returned
F  tag tamper     Integrity of the tag itself
G  nonce mismatch A correct tag under the wrong nonce still fails
================  =========================================================

Each test runs ``security_trials`` independent trials with fresh random keys,
nonces and messages.  One trial proves very little; a hundred consecutive
rejections is a result.  Note the asymmetry in what the trials can show: a
single unexpected *acceptance* would be a catastrophic finding, whereas a run
of rejections is consistent with (though not proof of) a sound implementation.
"""

from __future__ import annotations

import csv
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable

from .aead_interface import AeadCipher, AuthenticationError
from .aes_gcm import AesGcmCipher
from .ascon_aead import AsconAead128Cipher, is_available as ascon_available
from .config import SECURITY_RESULTS_CSV, ExperimentConfig
from .receiver import SecureReceiver, build_packet
from .replay_protection import StrictSequenceValidator
from .sensor import SensorFleet
from .serialization import split_reading

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"


@dataclass(frozen=True)
class SecurityTestResult:
    """One row of ``results/security_results.csv``."""

    algorithm: str
    test_id: str
    test_name: str
    property_tested: str
    trials: int
    expected_result: str
    actual_result: str
    unexpected_outcomes: int
    passed: bool
    notes: str


def _flip_random_bit(data: bytes, rng: secrets.SystemRandom) -> bytes:
    """Return `data` with exactly one bit flipped at a random position.

    Operates on a copy; the caller's bytes are unchanged.
    """
    if not data:
        raise ValueError("Cannot flip a bit in an empty byte string.")
    buffer = bytearray(data)
    index = rng.randrange(len(buffer))
    buffer[index] ^= 1 << rng.randrange(8)
    return bytes(buffer)


def _attempt(cipher: AeadCipher, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
    """Try to decrypt; return ACCEPTED or REJECTED.

    Any exception at all counts as a rejection, including ones the underlying
    library did not intend as authentication failures -- because from the
    receiver's point of view "did not yield plaintext" is the outcome that
    matters.  What must never happen is a return of plaintext.
    """
    try:
        cipher.decrypt(nonce, ciphertext, aad)
    except (AuthenticationError, ValueError, AssertionError):
        return REJECTED
    return ACCEPTED


def _run_trials(
    cipher_factory: Callable[[], AeadCipher],
    mutate: Callable[[AeadCipher, bytes, bytes, bytes, secrets.SystemRandom],
                     tuple[AeadCipher, bytes, bytes, bytes]],
    trials: int,
    expected: str,
) -> tuple[str, int]:
    """Run `trials` independent trials of one tampering scenario.

    Args:
        cipher_factory: Builds a cipher with a fresh random key.
        mutate: Given (cipher, nonce, ciphertext, aad, rng), returns the
            possibly-modified tuple to attempt decryption with.
        trials: Number of independent trials.
        expected: ACCEPTED or REJECTED.

    Returns:
        (observed_result, count_of_outcomes_differing_from_expected)
    """
    rng = secrets.SystemRandom()
    unexpected = 0
    for _ in range(trials):
        cipher = cipher_factory()
        # Random plaintext and AAD of varied length, so the result is not an
        # artefact of one particular message shape.
        plaintext = os.urandom(rng.randrange(1, 256))
        aad = os.urandom(rng.randrange(1, 64))
        nonce = cipher.generate_nonce()
        ciphertext = cipher.encrypt(nonce, plaintext, aad)

        args = mutate(cipher, nonce, ciphertext, aad, rng)
        if _attempt(*args) != expected:
            unexpected += 1
    observed = expected if unexpected == 0 else "MIXED"
    return observed, unexpected


# --------------------------------------------------------------------------
# Mutation strategies -- each models one threat
# --------------------------------------------------------------------------

def _no_change(cipher, nonce, ciphertext, aad, rng):
    return cipher, nonce, ciphertext, aad


def _tamper_ciphertext(cipher, nonce, ciphertext, aad, rng):
    # Flip a bit in the encrypted body, leaving the tag intact.
    body, tag = ciphertext[:-cipher.tag_size], ciphertext[-cipher.tag_size:]
    return cipher, nonce, _flip_random_bit(body, rng) + tag, aad


def _tamper_tag(cipher, nonce, ciphertext, aad, rng):
    body, tag = ciphertext[:-cipher.tag_size], ciphertext[-cipher.tag_size:]
    return cipher, nonce, body + _flip_random_bit(tag, rng), aad


def _tamper_aad(cipher, nonce, ciphertext, aad, rng):
    return cipher, nonce, ciphertext, _flip_random_bit(aad, rng)


def _wrong_key(cipher, nonce, ciphertext, aad, rng):
    # A completely independent key of the same length.
    return type(cipher)(type(cipher).generate_key()), nonce, ciphertext, aad


def _truncate(cipher, nonce, ciphertext, aad, rng):
    # Cut somewhere in the last portion so the tag is damaged or incomplete.
    cut = rng.randrange(1, min(len(ciphertext), cipher.tag_size + 1) + 1)
    return cipher, nonce, ciphertext[:-cut], aad


def _wrong_nonce(cipher, nonce, ciphertext, aad, rng):
    return cipher, cipher.generate_nonce(), ciphertext, aad


SCENARIOS: tuple[tuple[str, str, str, Callable, str], ...] = (
    ("A", "valid_message", "Correctness / availability", _no_change, ACCEPTED),
    ("B", "ciphertext_tampering", "Payload integrity", _tamper_ciphertext, REJECTED),
    ("C", "aad_tampering", "Metadata integrity", _tamper_aad, REJECTED),
    ("D", "wrong_key", "Authentication", _wrong_key, REJECTED),
    ("E", "truncated_ciphertext", "Safe failure on malformed input", _truncate, REJECTED),
    ("F", "tag_tampering", "Tag integrity", _tamper_tag, REJECTED),
    ("G", "nonce_mismatch", "Nonce binding", _wrong_nonce, REJECTED),
)


def run_algorithm_tests(
    algorithm_name: str,
    cipher_factory: Callable[[], AeadCipher],
    trials: int,
) -> list[SecurityTestResult]:
    """Run all tampering scenarios for one algorithm."""
    results: list[SecurityTestResult] = []
    for test_id, name, prop, mutate, expected in SCENARIOS:
        observed, unexpected = _run_trials(cipher_factory, mutate, trials, expected)
        results.append(
            SecurityTestResult(
                algorithm=algorithm_name,
                test_id=test_id,
                test_name=name,
                property_tested=prop,
                trials=trials,
                expected_result=expected,
                actual_result=observed,
                unexpected_outcomes=unexpected,
                passed=unexpected == 0,
                notes=f"{trials} independent trials, fresh key/nonce/message each.",
            )
        )
    return results


# --------------------------------------------------------------------------
# End-to-end tests through the receiver (including replay)
# --------------------------------------------------------------------------

def run_replay_test(
    algorithm_name: str, cipher_cls: type[AeadCipher], trials: int
) -> list[SecurityTestResult]:
    """Demonstrate that AEAD alone does not stop replay, but the receiver does.

    Two sub-tests share one setup, which is the point being made:

    * ``H`` -- a captured packet is re-delivered.  Its AEAD tag still verifies
      perfectly.  The *receiver* rejects it on sequence number alone.
    * ``I`` -- a stale (lower-numbered) packet is delivered.  Also rejected.
    """
    from .config import FULL

    fleet = SensorFleet(FULL)
    readings = [fleet.next_reading("WH-001", i * 5) for i in range(trials + 2)]

    replay_unexpected = 0
    stale_unexpected = 0
    aead_still_valid = 0

    for index in range(trials):
        # Sender and receiver must share the key, so it is generated here and
        # handed to both, rather than hidden inside an opaque factory.
        key = cipher_cls.generate_key()
        cipher = cipher_cls(key)
        receiver = SecureReceiver(validator=StrictSequenceValidator())
        receiver.provision("WH-001", cipher_cls.name, key)

        first = build_packet(cipher, readings[index])
        second = build_packet(cipher, readings[index + 1])

        if not receiver.receive(first).accepted:
            replay_unexpected += 1
            continue
        if not receiver.receive(second).accepted:
            replay_unexpected += 1
            continue

        # The captured packet's cryptography is still impeccable ...
        aad, _ = split_reading(readings[index + 1])
        try:
            cipher.decrypt(second.nonce, second.ciphertext, aad)
            aead_still_valid += 1
        except AuthenticationError:  # pragma: no cover - would be a real bug
            pass

        # ... yet the receiver must refuse it.
        if receiver.receive(second).accepted:
            replay_unexpected += 1
        if receiver.receive(first).accepted:
            stale_unexpected += 1

    return [
        SecurityTestResult(
            algorithm=algorithm_name,
            test_id="H",
            test_name="replay_exact_duplicate",
            property_tested="Freshness (protocol layer, not AEAD)",
            trials=trials,
            expected_result=REJECTED,
            actual_result=REJECTED if replay_unexpected == 0 else "MIXED",
            unexpected_outcomes=replay_unexpected,
            passed=replay_unexpected == 0,
            notes=(
                f"AEAD tag verified on {aead_still_valid}/{trials} replayed packets, "
                "confirming that replay defence comes from the sequence check, "
                "not from the cipher."
            ),
        ),
        SecurityTestResult(
            algorithm=algorithm_name,
            test_id="I",
            test_name="replay_stale_sequence",
            property_tested="Freshness (protocol layer, not AEAD)",
            trials=trials,
            expected_result=REJECTED,
            actual_result=REJECTED if stale_unexpected == 0 else "MIXED",
            unexpected_outcomes=stale_unexpected,
            passed=stale_unexpected == 0,
            notes="Out-of-order older sequence number delivered after a newer one.",
        ),
    ]


def run_aad_substitution_test(
    algorithm_name: str, cipher_cls: type[AeadCipher], trials: int
) -> SecurityTestResult:
    """The concrete WH-001 -> WH-999 device-impersonation scenario.

    This is the narrative version of test C: rather than flipping a random bit,
    an attacker performs a *semantically meaningful* edit, relabelling a
    warehouse reading as coming from a different sensor node.
    """
    from .config import FULL

    fleet = SensorFleet(FULL)
    unexpected = 0
    for index in range(trials):
        reading = fleet.next_reading("WH-001", index * 5)
        cipher = cipher_cls(cipher_cls.generate_key())
        aad, plaintext = split_reading(reading)
        sealed = cipher.seal(plaintext, aad)

        forged_aad = aad.replace(b'"WH-001"', b'"WH-999"')
        assert forged_aad != aad, "Test setup error: substitution did not apply."

        if _attempt(cipher, sealed.nonce, sealed.ciphertext, forged_aad) != REJECTED:
            unexpected += 1

    return SecurityTestResult(
        algorithm=algorithm_name,
        test_id="C2",
        test_name="aad_device_impersonation",
        property_tested="Metadata integrity (device identity)",
        trials=trials,
        expected_result=REJECTED,
        actual_result=REJECTED if unexpected == 0 else "MIXED",
        unexpected_outcomes=unexpected,
        passed=unexpected == 0,
        notes='device_id relabelled "WH-001" -> "WH-999" in the cleartext AAD.',
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def run_all(config: ExperimentConfig) -> list[SecurityTestResult]:
    """Run the whole defensive suite for every available algorithm."""
    cipher_classes: list[type[AeadCipher]] = [AesGcmCipher]
    if ascon_available():
        cipher_classes.append(AsconAead128Cipher)

    results: list[SecurityTestResult] = []
    for cipher_cls in cipher_classes:
        name = cipher_cls.name
        factory: Callable[[], AeadCipher] = (
            lambda cls=cipher_cls: cls(cls.generate_key())  # bind cls per iteration
        )
        results.extend(run_algorithm_tests(name, factory, config.security_trials))
        results.append(run_aad_substitution_test(name, cipher_cls, config.security_trials))
        results.extend(
            run_replay_test(name, cipher_cls, max(5, config.security_trials // 10))
        )
    return results


def write_results(
    results: Iterable[SecurityTestResult], path: Path = SECURITY_RESULTS_CSV
) -> Path:
    """Write security results to CSV."""
    rows = list(results)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    return path
