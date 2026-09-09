"""Tests for deterministic serialisation and the AAD / payload split."""

from __future__ import annotations

import json

import pytest

from src.config import QUICK
from src.sensor import SensorFleet, generate_dataset
from src.serialization import (
    AAD_FIELDS,
    PAYLOAD_FIELDS,
    SecurePacket,
    build_aad,
    build_payload,
    canonical_json_bytes,
    parse_json_bytes,
    reassemble,
    split_reading,
)


def test_canonical_json_is_key_order_independent():
    """The same mapping must encode identically however it was built."""
    a = canonical_json_bytes({"b": 2, "a": 1, "c": 3})
    b = canonical_json_bytes({"c": 3, "a": 1, "b": 2})
    assert a == b


def test_canonical_json_has_no_insignificant_whitespace():
    encoded = canonical_json_bytes({"a": 1, "b": "x"})
    assert b" " not in encoded
    assert encoded == b'{"a":1,"b":"x"}'


def test_canonical_json_is_stable_across_calls(sample_reading):
    """Byte-for-byte stability is what lets the receiver rebuild the AAD."""
    assert build_aad(sample_reading) == build_aad(sample_reading)
    assert build_payload(sample_reading) == build_payload(sample_reading)


def test_serialisation_is_utf8_decodable(sample_reading):
    aad, payload = split_reading(sample_reading)
    json.loads(aad.decode("utf-8"))
    json.loads(payload.decode("utf-8"))


def test_aad_contains_exactly_the_metadata_fields(sample_reading):
    decoded = parse_json_bytes(build_aad(sample_reading))
    assert set(decoded) == set(AAD_FIELDS)


def test_payload_contains_exactly_the_measurement_fields(sample_reading):
    decoded = parse_json_bytes(build_payload(sample_reading))
    assert set(decoded) == set(PAYLOAD_FIELDS)


def test_aad_and_payload_do_not_overlap(sample_reading):
    """A field in both places would be authenticated twice and could disagree."""
    aad = set(parse_json_bytes(build_aad(sample_reading)))
    payload = set(parse_json_bytes(build_payload(sample_reading)))
    assert aad.isdisjoint(payload)


def test_sensitive_measurements_are_not_in_the_cleartext_aad(sample_reading):
    """The confidentiality claim depends on this."""
    aad_text = build_aad(sample_reading).decode()
    for field in ("temperature", "humidity", "gas_level", "timestamp"):
        assert field not in aad_text


def test_reassemble_reconstructs_the_original_reading():
    for reading in generate_dataset(QUICK)[:100]:
        aad, payload = split_reading(reading)
        assert reassemble(aad, payload) == reading


def test_reassemble_rejects_non_json():
    with pytest.raises(ValueError):
        reassemble(b"not json", b"{}")


def test_reassemble_rejects_a_missing_field(sample_reading):
    aad, payload = split_reading(sample_reading)
    incomplete = canonical_json_bytes({"temperature": 20.0})
    with pytest.raises(ValueError, match="missing required field"):
        reassemble(aad, incomplete)


def test_reassemble_rejects_a_json_array():
    with pytest.raises(ValueError, match="not an object"):
        reassemble(b"[1,2,3]", b"{}")


def test_packet_wire_size_counts_every_transmitted_byte():
    packet = SecurePacket("AES-128-GCM", b"aad", b"n" * 12, b"c" * 40)
    assert packet.wire_size == 3 + 12 + 40


def test_peek_sequence_reads_unverified_metadata(sample_reading):
    aad, _ = split_reading(sample_reading)
    packet = SecurePacket("AES-128-GCM", aad, b"n" * 12, b"c" * 40)
    assert packet.peek_sequence() == (sample_reading.device_id, sample_reading.sequence)


def test_peek_sequence_returns_none_on_malformed_aad():
    """A malformed peek must not raise -- the receiver relies on that."""
    packet = SecurePacket("AES-128-GCM", b"\xff\xfe garbage", b"n" * 12, b"c" * 40)
    assert packet.peek_sequence() is None


def test_message_sizes_are_realistic_for_constrained_iot():
    """Sanity-check that a serialised warehouse reading is a small payload."""
    fleet = SensorFleet(QUICK)
    for index in range(20):
        reading = fleet.next_reading("WH-001", index * 5)
        aad, payload = split_reading(reading)
        assert len(aad) < 100
        assert len(payload) < 160
