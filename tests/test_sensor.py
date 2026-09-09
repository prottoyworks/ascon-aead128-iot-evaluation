"""Tests for the synthetic smart-warehouse sensor simulator."""

from __future__ import annotations

import csv

import pytest

from src.config import QUICK
from src.sensor import SensorFleet, SensorReading, generate_dataset, read_dataset, write_dataset


def test_generates_requested_number_of_readings():
    readings = generate_dataset(QUICK)
    assert len(readings) == QUICK.sensor_messages


def test_same_seed_produces_identical_dataset():
    """Reproducibility is the whole justification for the seed."""
    first = generate_dataset(QUICK)
    second = generate_dataset(QUICK)
    assert first == second


def test_different_seed_produces_different_dataset():
    """A seed that changed nothing would be a silent bug."""
    other = QUICK.with_overrides(random_seed=QUICK.random_seed + 1)
    assert generate_dataset(QUICK) != generate_dataset(other)


def test_values_stay_inside_configured_physical_ranges():
    t_lo, t_hi = QUICK.temperature_range_c
    h_lo, h_hi = QUICK.humidity_range_pct
    g_lo, g_hi = QUICK.gas_level_range
    for reading in generate_dataset(QUICK):
        assert t_lo <= reading.temperature <= t_hi
        assert h_lo <= reading.humidity <= h_hi
        assert g_lo <= reading.gas_level <= g_hi


def test_sequence_numbers_are_strictly_increasing_per_device():
    """Replay protection depends on this property holding at the source."""
    seen: dict[str, int] = {}
    for reading in generate_dataset(QUICK):
        previous = seen.get(reading.device_id)
        if previous is not None:
            assert reading.sequence > previous, (
                f"{reading.device_id} sequence went {previous} -> {reading.sequence}"
            )
        seen[reading.device_id] = reading.sequence
    assert set(seen) == set(QUICK.device_ids)


def test_all_configured_devices_appear():
    devices = {r.device_id for r in generate_dataset(QUICK)}
    assert devices == set(QUICK.device_ids)


def test_timestamps_are_iso8601_utc():
    for reading in generate_dataset(QUICK)[:50]:
        assert reading.timestamp.endswith("Z")
        assert len(reading.timestamp) == 20  # YYYY-MM-DDTHH:MM:SSZ


def test_csv_round_trip_preserves_every_reading(tmp_path):
    """Writing then reading must not lose or alter data."""
    path = tmp_path / "sensor_messages.csv"
    original = generate_dataset(QUICK)
    written = write_dataset(original, path)
    assert written == len(original)

    restored = read_dataset(path)
    assert restored == original


def test_csv_has_the_expected_header(tmp_path):
    path = tmp_path / "sensor_messages.csv"
    write_dataset(generate_dataset(QUICK), path)
    with path.open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))
    assert header == [
        "device_id", "protocol_version", "sequence",
        "temperature", "humidity", "gas_level", "timestamp",
    ]


def test_read_dataset_gives_actionable_error_when_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="generate-data"):
        read_dataset(tmp_path / "absent.csv")


def test_reading_is_immutable(sample_reading: SensorReading):
    """Frozen dataclass: a reading cannot be mutated after authentication."""
    with pytest.raises(AttributeError):
        sample_reading.temperature = 999.0  # type: ignore[misc]


def test_per_device_walk_is_smooth():
    """Consecutive readings from one device should be autocorrelated."""
    fleet = SensorFleet(QUICK)
    readings = [fleet.next_reading("WH-001", i * 5) for i in range(50)]
    jumps = [
        abs(readings[i + 1].temperature - readings[i].temperature)
        for i in range(len(readings) - 1)
    ]
    # The walk step is 0.35 C, so no single jump may exceed it (plus rounding).
    assert max(jumps) <= 0.36
