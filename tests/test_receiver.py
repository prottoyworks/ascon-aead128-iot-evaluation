"""End-to-end tests for the gateway receiver pipeline."""

from __future__ import annotations

import pytest

from src.aes_gcm import AesGcmCipher
from src.ascon_aead import AsconAead128Cipher, is_available
from src.config import QUICK
from src.receiver import RejectionReason, SecureReceiver, build_packet
from src.replay_protection import StrictSequenceValidator
from src.sensor import SensorFleet
from src.serialization import SecurePacket

CIPHERS = [pytest.param(AesGcmCipher, id="AES-128-GCM")]
if is_available():
    CIPHERS.append(pytest.param(AsconAead128Cipher, id="Ascon-AEAD128"))

parametrise_ciphers = pytest.mark.parametrize("cipher_cls", CIPHERS)


@pytest.fixture
def readings():
    fleet = SensorFleet(QUICK)
    return [fleet.next_reading("WH-001", index * 5) for index in range(20)]


def _channel(cipher_cls):
    """Build a matched sender/receiver pair sharing one key."""
    key = cipher_cls.generate_key()
    cipher = cipher_cls(key)
    receiver = SecureReceiver(validator=StrictSequenceValidator())
    receiver.provision("WH-001", cipher_cls.name, key)
    return cipher, receiver


@parametrise_ciphers
def test_genuine_message_is_accepted_and_recovered(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    result = receiver.receive(build_packet(cipher, readings[0]))
    assert result.accepted
    assert result.reading == readings[0]


@parametrise_ciphers
def test_a_stream_of_messages_is_accepted_in_order(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    for reading in readings:
        result = receiver.receive(build_packet(cipher, reading))
        assert result.accepted, result.detail
        assert result.reading == reading
    assert receiver.stats["accepted"] == len(readings)


@parametrise_ciphers
def test_replayed_packet_is_rejected(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    packet = build_packet(cipher, readings[0])
    assert receiver.receive(packet).accepted
    assert receiver.receive(build_packet(cipher, readings[1])).accepted

    replayed = receiver.receive(packet)
    assert not replayed.accepted
    assert replayed.reason in (RejectionReason.REPLAY, RejectionReason.PRE_FILTER_STALE)


@parametrise_ciphers
def test_tampered_ciphertext_is_rejected(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    packet = build_packet(cipher, readings[0])
    corrupted = bytearray(packet.ciphertext)
    corrupted[0] ^= 0x01
    result = receiver.receive(
        SecurePacket(packet.algorithm, packet.aad, packet.nonce, bytes(corrupted))
    )
    assert not result.accepted
    assert result.reason is RejectionReason.AUTHENTICATION_FAILED


@parametrise_ciphers
def test_tampered_aad_is_rejected(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    packet = build_packet(cipher, readings[0])
    # Change the sequence number upward: passes the pre-filter, fails the tag.
    forged_aad = packet.aad.replace(
        f'"sequence":{readings[0].sequence}'.encode(),
        f'"sequence":{readings[0].sequence + 5}'.encode(),
    )
    assert forged_aad != packet.aad
    result = receiver.receive(
        SecurePacket(packet.algorithm, forged_aad, packet.nonce, packet.ciphertext)
    )
    assert not result.accepted
    assert result.reason is RejectionReason.AUTHENTICATION_FAILED


@parametrise_ciphers
def test_unknown_device_is_rejected(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    fleet = SensorFleet(QUICK)
    stranger = fleet.next_reading("WH-002", 0)
    result = receiver.receive(build_packet(cipher, stranger))
    assert not result.accepted
    assert result.reason is RejectionReason.AUTHENTICATION_FAILED


@parametrise_ciphers
def test_unknown_algorithm_label_is_rejected(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    packet = build_packet(cipher, readings[0])
    result = receiver.receive(
        SecurePacket("ROT13", packet.aad, packet.nonce, packet.ciphertext)
    )
    assert not result.accepted
    assert result.reason is RejectionReason.UNKNOWN_ALGORITHM


@parametrise_ciphers
def test_malformed_aad_is_rejected(cipher_cls):
    _cipher, receiver = _channel(cipher_cls)
    result = receiver.receive(
        SecurePacket(cipher_cls.name, b"\xff not json", b"\x00" * 12, b"\x00" * 32)
    )
    assert not result.accepted
    assert result.reason is RejectionReason.MALFORMED


@parametrise_ciphers
def test_forged_high_sequence_does_not_lock_out_the_device(cipher_cls, readings):
    """The two-phase commit discipline, tested end to end."""
    cipher, receiver = _channel(cipher_cls)
    assert receiver.receive(build_packet(cipher, readings[0])).accepted

    # An attacker forges a packet claiming a very high sequence number.
    packet = build_packet(cipher, readings[1])
    forged_aad = packet.aad.replace(
        f'"sequence":{readings[1].sequence}'.encode(), b'"sequence":2147483647'
    )
    forged = SecurePacket(packet.algorithm, forged_aad, packet.nonce, packet.ciphertext)
    assert not receiver.receive(forged).accepted

    # The genuine next message must still be accepted.
    assert receiver.receive(build_packet(cipher, readings[1])).accepted


@parametrise_ciphers
def test_provision_rejects_an_unsupported_algorithm(cipher_cls):
    receiver = SecureReceiver()
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        receiver.provision("WH-001", "DES", b"\x00" * 16)


@parametrise_ciphers
def test_receiver_records_rejection_statistics(cipher_cls, readings):
    cipher, receiver = _channel(cipher_cls)
    packet = build_packet(cipher, readings[0])
    receiver.receive(packet)
    receiver.receive(packet)  # replay
    assert receiver.stats["accepted"] == 1
    assert sum(v for k, v in receiver.stats.items() if k != "accepted") == 1


@parametrise_ciphers
def test_prefilter_can_be_disabled_without_changing_the_verdict(cipher_cls, readings):
    """The pre-filter is an optimisation; correctness must not depend on it."""
    for prefilter in (True, False):
        key = cipher_cls.generate_key()
        cipher = cipher_cls(key)
        receiver = SecureReceiver(
            validator=StrictSequenceValidator(), enable_prefilter=prefilter
        )
        receiver.provision("WH-001", cipher_cls.name, key)
        packet = build_packet(cipher, readings[0])
        assert receiver.receive(packet).accepted
        assert not receiver.receive(packet).accepted


@pytest.mark.skipif(not is_available(), reason="needs both ciphers")
def test_receiver_handles_both_algorithms_simultaneously(readings):
    """Crypto-agility in miniature: one receiver, two algorithms, one device."""
    receiver = SecureReceiver(validator=StrictSequenceValidator())
    ciphers = {}
    for cipher_cls in (AesGcmCipher, AsconAead128Cipher):
        key = cipher_cls.generate_key()
        receiver.provision("WH-001", cipher_cls.name, key)
        ciphers[cipher_cls.name] = cipher_cls(key)

    assert receiver.receive(build_packet(ciphers["AES-128-GCM"], readings[0])).accepted
    assert receiver.receive(build_packet(ciphers["Ascon-AEAD128"], readings[1])).accepted
