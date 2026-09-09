"""Synthetic smart-warehouse IoT sensor simulator.

Why synthetic data is scientifically sufficient here
----------------------------------------------------
The dependent variables in this study are cryptographic latency, throughput,
ciphertext expansion and observed memory.  For any modern block or permutation
cipher these depend on the *length* of the input and not on its content:
AES-GCM and Ascon-AEAD128 both process data in fixed-size blocks with a fixed
number of rounds, and neither contains a data-dependent branch or a
data-dependent memory access.  (That property is exactly what makes them
constant-time and therefore resistant to timing side channels.)

Consequently a real temperature reading and a synthetic one of the same
serialised length produce indistinguishable measurements.  What synthetic
generation buys in exchange is control: an exact, reproducible message count,
a fixed seed, no privacy or ethics review, and no confounding from a real
deployment's network jitter.

The one thing synthetic data cannot support is a claim about *real deployment
conditions* -- duty cycles, radio energy, packet loss.  No such claim is made;
see the limitations chapter.
"""

from __future__ import annotations

import csv
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .config import SENSOR_CSV, ExperimentConfig

#: Field order used in the CSV and in canonical serialisation.
CSV_FIELDS: tuple[str, ...] = (
    "device_id",
    "protocol_version",
    "sequence",
    "temperature",
    "humidity",
    "gas_level",
    "timestamp",
)


@dataclass(frozen=True)
class SensorReading:
    """One reading from one simulated warehouse sensor node.

    The split between metadata and measurement matters cryptographically: the
    first three fields become associated data (authenticated, transmitted in
    clear) and the last four become the encrypted payload.  See
    ``src/serialization.py``.
    """

    device_id: str
    protocol_version: int
    sequence: int
    temperature: float  #: degrees Celsius
    humidity: float     #: relative humidity, percent
    gas_level: int      #: unitless air-quality index from a MQ-series sensor
    timestamp: str      #: ISO-8601, UTC, 'Z'-suffixed

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "SensorReading":
        """Rebuild a reading from a CSV row, restoring numeric types."""
        return cls(
            device_id=row["device_id"],
            protocol_version=int(row["protocol_version"]),
            sequence=int(row["sequence"]),
            temperature=float(row["temperature"]),
            humidity=float(row["humidity"]),
            gas_level=int(row["gas_level"]),
            timestamp=row["timestamp"],
        )


class SensorFleet:
    """A deterministic generator for a fleet of simulated sensor nodes.

    Each device keeps its own monotonically increasing sequence counter, which
    is what the replay-protection logic later relies on.  Values follow a
    bounded random walk rather than independent uniform draws, because real
    environmental sensors are strongly autocorrelated -- consecutive readings
    a few seconds apart do not jump from 18 C to 35 C.  This affects nothing in
    the measurements but makes the dataset defensible if an examiner inspects
    ``data/sensor_messages.csv``.
    """

    def __init__(self, config: ExperimentConfig) -> None:
        self.config = config
        # A dedicated Random instance, so seeding this simulator never touches
        # global random state used elsewhere (and is never used for keys).
        self._rng = random.Random(config.random_seed)
        self._sequence: dict[str, int] = {d: 0 for d in config.device_ids}
        self._state: dict[str, tuple[float, float, int]] = {}
        self._start = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)

        t_lo, t_hi = config.temperature_range_c
        h_lo, h_hi = config.humidity_range_pct
        g_lo, g_hi = config.gas_level_range
        for device in config.device_ids:
            self._state[device] = (
                self._rng.uniform(t_lo, t_hi),
                self._rng.uniform(h_lo, h_hi),
                self._rng.randint(g_lo, g_hi),
            )

    @staticmethod
    def _walk(value: float, step: float, low: float, high: float, rng: random.Random) -> float:
        """Move `value` by a small random step, reflecting at the bounds."""
        return min(high, max(low, value + rng.uniform(-step, step)))

    def next_reading(self, device_id: str, elapsed_seconds: int) -> SensorReading:
        """Produce the next reading for one device."""
        cfg = self.config
        temperature, humidity, gas = self._state[device_id]
        temperature = self._walk(temperature, 0.35, *cfg.temperature_range_c, rng=self._rng)
        humidity = self._walk(humidity, 1.2, *cfg.humidity_range_pct, rng=self._rng)
        g_lo, g_hi = cfg.gas_level_range
        gas = int(self._walk(float(gas), 6.0, float(g_lo), float(g_hi), rng=self._rng))
        self._state[device_id] = (temperature, humidity, gas)

        self._sequence[device_id] += 1
        stamp = (self._start + timedelta(seconds=elapsed_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        return SensorReading(
            device_id=device_id,
            protocol_version=cfg.protocol_version,
            sequence=self._sequence[device_id],
            # Rounding to a fixed number of decimals keeps canonical JSON
            # serialisation byte-stable across platforms and float repr rules.
            temperature=round(temperature, 2),
            humidity=round(humidity, 1),
            gas_level=gas,
            timestamp=stamp,
        )

    def generate(self, count: int | None = None) -> Iterator[SensorReading]:
        """Yield `count` readings, cycling round-robin through the fleet."""
        total = count if count is not None else self.config.sensor_messages
        devices = self.config.device_ids
        for index in range(total):
            device = devices[index % len(devices)]
            # 5-second sampling interval per full sweep of the fleet.
            yield self.next_reading(device, elapsed_seconds=(index // len(devices)) * 5)


def generate_dataset(config: ExperimentConfig) -> list[SensorReading]:
    """Generate the full synthetic dataset in memory."""
    return list(SensorFleet(config).generate())


def write_dataset(readings: Iterable[SensorReading], path: Path = SENSOR_CSV) -> int:
    """Write readings to CSV and return how many rows were written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    # newline="" is required on Windows, otherwise csv writes blank lines.
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for reading in readings:
            writer.writerow(reading.to_dict())
            written += 1
    return written


def read_dataset(path: Path = SENSOR_CSV) -> list[SensorReading]:
    """Load a previously generated dataset from CSV.

    Raises:
        FileNotFoundError: with an actionable message if the dataset is absent.
    """
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} not found. Generate it first with:\n    python main.py generate-data"
        )
    with path.open("r", newline="", encoding="utf-8") as handle:
        return [SensorReading.from_row(row) for row in csv.DictReader(handle)]
