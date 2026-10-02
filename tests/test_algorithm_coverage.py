"""Guards that keep the comparison from silently shrinking back to two algorithms.

Why this file exists
--------------------
The project's title promises a comparison of Ascon-AEAD128 against *other
lightweight algorithms* and AES-128-GCM.  For a while the repository did not
keep that promise evenly: the timing study covered seven algorithms while the
conformance evidence and the defensive security suite covered two, because the
receiver's cipher registry had never been widened and nothing failed when it
was not.  That is the characteristic failure mode of a comparison -- it does
not break, it just quietly narrows.

Every test here asserts breadth rather than behaviour.  If someone adds a
cipher to ``src/lightweight`` and forgets to wire it in, or removes one from a
registry, these fail and say so.
"""

from __future__ import annotations

import pytest

from src.config import ALL_ALGORITHMS, LIGHTWEIGHT_ALGORITHMS
from src.lightweight import LIGHTWEIGHT_CIPHERS
from src.receiver import CIPHER_REGISTRY, SecureReceiver, build_packet
from src.replay_protection import StrictSequenceValidator
from src.sensor import SensorFleet


def test_every_algorithm_in_the_study_is_registered_with_the_receiver():
    """The registry is what makes the protocol-layer tests reach all seven."""
    missing = [name for name in ALL_ALGORITHMS if name not in CIPHER_REGISTRY]
    assert not missing, (
        f"These algorithms are evaluated but unknown to the receiver: {missing}. "
        "Protocol-layer security tests cannot cover them until they are in "
        "src/receiver.py's CIPHER_REGISTRY."
    )


def test_the_registry_does_not_drift_from_the_lightweight_package():
    """Adding a cipher to the package must register it, with no second edit."""
    for cipher in LIGHTWEIGHT_CIPHERS:
        assert CIPHER_REGISTRY.get(cipher.name) is cipher, (
            f"{cipher.name} is in src/lightweight but not wired into the receiver."
        )


def test_the_declared_names_match_the_implementations():
    """config.py and the cipher classes must agree on spelling."""
    declared = set(LIGHTWEIGHT_ALGORITHMS)
    implemented = {cipher.name for cipher in LIGHTWEIGHT_CIPHERS}
    assert declared == implemented, (
        f"config.LIGHTWEIGHT_ALGORITHMS says {sorted(declared)} but "
        f"src/lightweight provides {sorted(implemented)}."
    )


@pytest.mark.parametrize("algorithm", sorted(ALL_ALGORITHMS))
def test_a_real_reading_survives_the_whole_receiver_path(algorithm):
    """End to end, per algorithm: seal a reading, deliver it, get it back.

    This is the test that would have caught the narrowing.  It provisions the
    receiver exactly as the security suite does, so an algorithm that cannot be
    provisioned fails here rather than being skipped in silence.
    """
    from src.config import FULL

    cipher_cls = CIPHER_REGISTRY[algorithm]
    key = cipher_cls.generate_key()
    cipher = cipher_cls(key)

    receiver = SecureReceiver(validator=StrictSequenceValidator())
    receiver.provision("WH-001", algorithm, key)

    reading = SensorFleet(FULL).next_reading("WH-001", 0)
    result = receiver.receive(build_packet(cipher, reading))

    assert result.accepted, f"{algorithm}: a valid packet was refused"
    assert result.reading is not None
    assert result.reading.device_id == "WH-001"


@pytest.mark.parametrize("algorithm", sorted(ALL_ALGORITHMS))
def test_a_tampered_reading_is_refused_by_every_algorithm(algorithm):
    """Breadth for the negative case too, not only the happy path."""
    from src.config import FULL

    cipher_cls = CIPHER_REGISTRY[algorithm]
    key = cipher_cls.generate_key()
    cipher = cipher_cls(key)

    receiver = SecureReceiver(validator=StrictSequenceValidator())
    receiver.provision("WH-001", algorithm, key)

    packet = build_packet(cipher, SensorFleet(FULL).next_reading("WH-001", 0))
    corrupted = bytearray(packet.ciphertext)
    corrupted[0] ^= 0x01
    tampered = type(packet)(
        algorithm=packet.algorithm,
        aad=packet.aad,
        nonce=packet.nonce,
        ciphertext=bytes(corrupted),
    )

    assert not receiver.receive(tampered).accepted, (
        f"{algorithm}: a tampered packet was accepted"
    )
