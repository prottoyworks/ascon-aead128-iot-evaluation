"""Extended benchmark: Ascon-AEAD128 against five other lightweight AEAD schemes.

Relationship to ``src/benchmark.py``
------------------------------------
This module does **not** replace the core benchmark and does not modify it.  It
runs a second, self-contained experiment whose purpose is different:

* ``src/benchmark.py``     -- Ascon-AEAD128 vs the established AES-128-GCM
                              baseline.  Answers "how does the new standard
                              compare with the incumbent?"
* ``src/extended_benchmark.py`` -- Ascon-AEAD128 vs five other lightweight AEAD
                              schemes.  Answers "how does Ascon compare with the
                              algorithms it was standardised ahead of, and with
                              what IoT networks deploy today?"

The timing primitives (``_calibrate_batch_size``, ``_measure_samples``,
``BENCHMARK_AAD_SIZE``) are imported from ``src/benchmark.py`` rather than
re-implemented.  That is deliberate: if the extension had its own timing code,
a reviewer could reasonably ask whether the two experiments are comparable.
Sharing the primitives means both experiments use identical warm-up, identical
batching rules, identical garbage-collection handling and identical sample
accounting.

The implementation-tier rule, restated
--------------------------------------
Ascon-AEAD128 and all five comparison algorithms execute as interpreted Python.
AES-128-GCM executes inside OpenSSL as optimised C with AES-NI.  Every output
of this module carries a ``tier`` column for exactly that reason:

* ``pure-python`` vs ``pure-python``  -> a comparison of **algorithms**.
* ``pure-python`` vs ``native-c``     -> a comparison of **implementations**.

AES-128-GCM is still measured, because the report needs the deployment-reality
data point, but every figure marks it as a different tier and no ranking mixes
the two silently.
"""

from __future__ import annotations

import csv
import gc
import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from .aead_interface import AeadCipher
from .aes_gcm import AesGcmCipher
from .ascon_aead import AsconAead128Cipher, is_available as ascon_available
from .benchmark import BENCHMARK_AAD_SIZE, _calibrate_batch_size, _measure_samples
from .config import (OP_DECRYPT, OP_ENCRYPT, RESULTS_DIR, ExperimentConfig,
                     get_config)
from .lightweight import LIGHTWEIGHT_CIPHERS

# --------------------------------------------------------------------------
# Output locations.  Everything the extension writes lives under
# results/extended/ so that no existing result file is ever overwritten.
# --------------------------------------------------------------------------
EXTENDED_DIR: Path = RESULTS_DIR / "extended"
RAW_CSV: Path = EXTENDED_DIR / "raw_extended.csv"
SUMMARY_CSV: Path = EXTENDED_DIR / "summary_extended.csv"
OVERHEAD_CSV: Path = EXTENDED_DIR / "overhead_extended.csv"
MEMORY_CSV: Path = EXTENDED_DIR / "memory_extended.csv"
WORKLOAD_CSV: Path = EXTENDED_DIR / "workload_extended.csv"
ENVIRONMENT_JSON: Path = EXTENDED_DIR / "environment_extended.json"

#: The algorithm under study; every comparison in the extension is relative to it.
REFERENCE_ALGORITHM = "Ascon-AEAD128"

#: Which implementation tier each algorithm belongs to.
TIERS: dict[str, str] = {
    "Ascon-AEAD128": "pure-python",
    "TinyJAMBU-128": "pure-python",
    "Xoodyak": "pure-python",
    "Schwaemm256-128": "pure-python",
    "GIFT-COFB": "pure-python",
    "AES-128-CCM": "pure-python",
    "AES-128-GCM": "native-c",
}

#: One-line justification for each algorithm's presence, echoed into the CSV so
#: that a reader of the data alone can see why the set was chosen.
ROLES: dict[str, str] = {
    "Ascon-AEAD128": "NIST SP 800-232 standard (the algorithm under study)",
    "TinyJAMBU-128": "NIST-LWC finalist (smallest hardware footprint, 64-bit tag)",
    "Xoodyak": "NIST-LWC finalist (Keccak team; closest structural rival)",
    "Schwaemm256-128": "NIST-LWC finalist (SPARKLE; software-oriented ARX)",
    "GIFT-COFB": "NIST-LWC finalist (block-cipher based, not a sponge)",
    "AES-128-CCM": "Deployed IoT AEAD (IEEE 802.15.4 / Zigbee / BLE)",
    "AES-128-GCM": "Established baseline (NIST SP 800-38D, OpenSSL + AES-NI)",
}


@dataclass(frozen=True)
class ExtendedTimingRow:
    """One measured cell of the extended experiment."""

    algorithm: str
    tier: str
    role: str
    message_size: int
    operation: str
    experiment_run: int
    iteration: int
    time_ns: float
    batch_size: int
    plaintext_size: int
    ciphertext_size: int
    aad_size: int


@dataclass(frozen=True)
class ExtendedOverheadRow:
    """Deterministic per-message overhead -- no timing involved."""

    algorithm: str
    tier: str
    plaintext_size: int
    ciphertext_size: int
    tag_bytes: int
    nonce_bytes: int
    expansion_bytes: int
    wire_overhead_bytes: int
    overhead_percent: float


@dataclass(frozen=True)
class ExtendedMemoryRow:
    """Peak Python-heap allocation for one operation, via tracemalloc."""

    algorithm: str
    tier: str
    message_size: int
    operation: str
    sample: int
    peak_python_heap_bytes: int
    current_python_heap_bytes: int


@dataclass(frozen=True)
class ExtendedWorkloadRow:
    """End-to-end cost of protecting one real synthetic sensor message."""

    algorithm: str
    tier: str
    messages: int
    repetition: int
    encrypt_us_mean: float
    decrypt_us_mean: float
    round_trip_us_mean: float
    messages_per_second: float
    mean_payload_bytes: float
    mean_aad_bytes: float
    mean_wire_bytes: float
    overhead_percent: float


# --------------------------------------------------------------------------
# Algorithm set
# --------------------------------------------------------------------------
def extended_cipher_classes(include_aes_gcm: bool = True) -> list[type[AeadCipher]]:
    """Every cipher in the extended comparison, in a stable declaration order.

    Ascon is first because it is the reference the others are measured against.
    Declaration order does not determine execution order -- that is shuffled.
    """
    classes: list[type[AeadCipher]] = []
    if ascon_available():
        classes.append(AsconAead128Cipher)
    classes.extend(LIGHTWEIGHT_CIPHERS)
    if include_aes_gcm:
        classes.append(AesGcmCipher)
    return classes


def _tier(name: str) -> str:
    return TIERS.get(name, "unknown")


def _role(name: str) -> str:
    return ROLES.get(name, "")


# --------------------------------------------------------------------------
# Timing pass
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class _Cell:
    cipher_cls: type[AeadCipher]
    message_size: int
    operation: str
    experiment_run: int


def _build_cells(config: ExperimentConfig, classes) -> list[_Cell]:
    cells = [
        _Cell(cls, size, operation, run)
        for cls in classes
        for size in config.message_sizes
        for operation in (OP_ENCRYPT, OP_DECRYPT)
        for run in range(1, config.experiment_repetitions + 1)
    ]
    if config.randomize_execution_order:
        # Seeded shuffle: reproducible, but uncorrelated with algorithm identity,
        # so thermal drift during a long run cannot favour whichever algorithm
        # would otherwise have run first.
        random.Random(config.random_seed).shuffle(cells)
    return cells


def _run_cell(cell: _Cell, config: ExperimentConfig) -> list[ExtendedTimingRow]:
    """Execute one (algorithm, size, operation, repetition) cell."""
    cipher = cell.cipher_cls(cell.cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    plaintext = os.urandom(cell.message_size)
    aad = os.urandom(BENCHMARK_AAD_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)

    if cell.operation == OP_ENCRYPT:
        operation: Callable[[], object] = lambda: cipher.encrypt(nonce, plaintext, aad)
    else:
        operation = lambda: cipher.decrypt(nonce, ciphertext, aad)

    for _ in range(config.warmup_iterations):       # warm-up, results discarded
        operation()

    batch_size = _calibrate_batch_size(operation)
    samples = _measure_samples(operation, config, batch_size)

    name = cell.cipher_cls.name
    return [
        ExtendedTimingRow(
            algorithm=name,
            tier=_tier(name),
            role=_role(name),
            message_size=cell.message_size,
            operation=cell.operation,
            experiment_run=cell.experiment_run,
            iteration=index,
            time_ns=value,
            batch_size=batch_size,
            plaintext_size=cell.message_size,
            ciphertext_size=len(ciphertext),
            aad_size=BENCHMARK_AAD_SIZE,
        )
        for index, value in enumerate(samples, start=1)
    ]


# --------------------------------------------------------------------------
# Overhead, memory and end-to-end passes
# --------------------------------------------------------------------------
def measure_overhead(config: ExperimentConfig, classes) -> list[ExtendedOverheadRow]:
    """Communication overhead: implementation independent, so exactly reproducible.

    This is the one metric in the whole study that transfers unchanged to real
    hardware -- it depends only on the nonce and tag sizes the specification
    mandates, not on how fast anybody's laptop is.
    """
    rows: list[ExtendedOverheadRow] = []
    for cls in classes:
        cipher = cls(cls.generate_key())
        for size in config.message_sizes:
            result = cipher.seal(os.urandom(size), os.urandom(BENCHMARK_AAD_SIZE))
            rows.append(ExtendedOverheadRow(
                algorithm=cls.name,
                tier=_tier(cls.name),
                plaintext_size=size,
                ciphertext_size=result.ciphertext_size,
                tag_bytes=cls.tag_size,
                nonce_bytes=cls.nonce_size,
                expansion_bytes=result.expansion_bytes,
                wire_overhead_bytes=result.wire_overhead_bytes,
                overhead_percent=100.0 * result.wire_overhead_bytes / (size + result.wire_overhead_bytes),
            ))
    return rows


def measure_memory(config: ExperimentConfig, classes) -> list[ExtendedMemoryRow]:
    """Peak Python-heap allocation per operation.

    ``tracemalloc`` observes CPython allocations only.  It therefore says
    nothing about OpenSSL's C-side buffers, which is why AES-128-GCM's row is
    not comparable with the rest and the ``tier`` column must be respected when
    reading this file.  Within the pure-Python tier the numbers are a fair
    relative indicator of how much transient garbage each algorithm creates.
    """
    rows: list[ExtendedMemoryRow] = []
    for cls in classes:
        cipher = cls(cls.generate_key())
        for size in config.message_sizes:
            nonce = cipher.generate_nonce()
            plaintext = os.urandom(size)
            aad = os.urandom(BENCHMARK_AAD_SIZE)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            for operation, call in (
                (OP_ENCRYPT, lambda: cipher.encrypt(nonce, plaintext, aad)),
                (OP_DECRYPT, lambda: cipher.decrypt(nonce, ciphertext, aad)),
            ):
                for sample in range(1, config.memory_samples + 1):
                    gc.collect()
                    tracemalloc.start()
                    call()
                    current, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    rows.append(ExtendedMemoryRow(
                        algorithm=cls.name,
                        tier=_tier(cls.name),
                        message_size=size,
                        operation=operation,
                        sample=sample,
                        peak_python_heap_bytes=peak,
                        current_python_heap_bytes=current,
                    ))
    return rows


def measure_end_to_end(config: ExperimentConfig, classes,
                       messages: int = 400) -> list[ExtendedWorkloadRow]:
    """Cost of protecting the project's *actual* synthetic warehouse traffic.

    The size sweep uses uniform random payloads; this pass uses the real
    generated sensor readings, with the real AAD/payload split from
    ``src/serialization.py``.  It is the number that answers "how many sensor
    messages per second can this gateway authenticate?", which is the form a
    reader of the report will actually want.
    """
    from .sensor import SensorFleet
    from .serialization import split_reading

    rows: list[ExtendedWorkloadRow] = []
    repetitions = min(config.experiment_repetitions, 3)
    for repetition in range(1, repetitions + 1):
        fleet = SensorFleet(config.with_overrides(random_seed=config.random_seed + repetition))
        readings = list(fleet.generate(messages))
        split = [split_reading(reading) for reading in readings]
        for cls in classes:
            cipher = cls(cls.generate_key())
            encrypt_times: list[float] = []
            decrypt_times: list[float] = []
            wire_bytes: list[int] = []
            payload_bytes: list[int] = []
            aad_bytes: list[int] = []
            gc_was_enabled = gc.isenabled()
            gc.disable()
            try:
                for aad, payload in split:
                    nonce = cipher.generate_nonce()
                    start = time.perf_counter_ns()
                    ciphertext = cipher.encrypt(nonce, payload, aad)
                    middle = time.perf_counter_ns()
                    cipher.decrypt(nonce, ciphertext, aad)
                    end = time.perf_counter_ns()
                    encrypt_times.append(middle - start)
                    decrypt_times.append(end - middle)
                    wire_bytes.append(len(ciphertext) + cls.nonce_size + len(aad))
                    payload_bytes.append(len(payload))
                    aad_bytes.append(len(aad))
            finally:
                if gc_was_enabled:
                    gc.enable()
            encrypt_mean = statistics.fmean(encrypt_times) / 1000.0
            decrypt_mean = statistics.fmean(decrypt_times) / 1000.0
            round_trip = encrypt_mean + decrypt_mean
            mean_wire = statistics.fmean(wire_bytes)
            mean_payload = statistics.fmean(payload_bytes)
            rows.append(ExtendedWorkloadRow(
                algorithm=cls.name,
                tier=_tier(cls.name),
                messages=len(split),
                repetition=repetition,
                encrypt_us_mean=encrypt_mean,
                decrypt_us_mean=decrypt_mean,
                round_trip_us_mean=round_trip,
                messages_per_second=(1e6 / round_trip) if round_trip else float("nan"),
                mean_payload_bytes=mean_payload,
                mean_aad_bytes=statistics.fmean(aad_bytes),
                mean_wire_bytes=mean_wire,
                overhead_percent=100.0 * (mean_wire - mean_payload) / mean_wire,
            ))
    return rows


# --------------------------------------------------------------------------
# Summarising and writing
# --------------------------------------------------------------------------
def _t_critical_95(degrees_of_freedom: int) -> float:
    """Two-sided 95% Student-t critical value, from a small lookup table."""
    table = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
             7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 12: 2.179, 15: 2.131,
             20: 2.086, 25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980}
    if degrees_of_freedom <= 0:
        return float("nan")
    for key in sorted(table):
        if degrees_of_freedom <= key:
            return table[key]
    return 1.960


def summarise(rows: Sequence[ExtendedTimingRow]) -> list[dict]:
    """Collapse raw samples into one row per (algorithm, size, operation)."""
    grouped: dict[tuple[str, int, str], list[ExtendedTimingRow]] = {}
    for row in rows:
        grouped.setdefault((row.algorithm, row.message_size, row.operation), []).append(row)

    summary: list[dict] = []
    for (algorithm, size, operation), group in sorted(grouped.items()):
        times = [row.time_ns for row in group]
        mean = statistics.fmean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0.0
        half_width = (_t_critical_95(len(times) - 1) * stdev / (len(times) ** 0.5)
                      if len(times) > 1 else 0.0)
        # Between-repetition spread: the honest measure of run-to-run variability.
        per_run: dict[int, list[float]] = {}
        for row in group:
            per_run.setdefault(row.experiment_run, []).append(row.time_ns)
        run_means = [statistics.fmean(v) for v in per_run.values()]
        summary.append({
            "algorithm": algorithm,
            "tier": group[0].tier,
            "role": group[0].role,
            "message_size": size,
            "operation": operation,
            "samples": len(times),
            "repetitions": len(run_means),
            "batch_size": group[0].batch_size,
            "mean_ns": mean,
            "median_ns": statistics.median(times),
            "stdev_ns": stdev,
            "min_ns": min(times),
            "max_ns": max(times),
            "ci95_half_width_ns": half_width,
            "ci95_lower_ns": mean - half_width,
            "ci95_upper_ns": mean + half_width,
            "mean_us": mean / 1000.0,
            "median_us": statistics.median(times) / 1000.0,
            "between_run_stdev_ns": statistics.stdev(run_means) if len(run_means) > 1 else 0.0,
            "throughput_mb_s_mean": (size / (mean / 1e9)) / 1e6 if mean else float("nan"),
            "throughput_mb_s_median": (size / (statistics.median(times) / 1e9)) / 1e6,
            "operations_per_second": 1e9 / mean if mean else float("nan"),
            "ciphertext_size": group[0].ciphertext_size,
        })
    return summary


def _write_rows(rows: Sequence[object], path: Path) -> Path:
    """Write dataclass rows or dicts to CSV, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return path
    records = [row if isinstance(row, dict) else asdict(row) for row in rows]  # type: ignore[arg-type]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    return path


def write_environment(config: ExperimentConfig, classes) -> Path:
    """Record everything needed to interpret -- or contest -- these numbers."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        openssl = backend.openssl_version_text()
    except Exception:                                   # pragma: no cover
        import ssl
        openssl = ssl.OPENSSL_VERSION

    report = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "experiment": "extended lightweight-AEAD comparison",
        "reference_algorithm": REFERENCE_ALGORITHM,
        "algorithms": [
            {"name": cls.name, "tier": _tier(cls.name), "role": _role(cls.name),
             "key_bits": cls.key_size * 8, "nonce_bits": cls.nonce_size * 8,
             "tag_bits": cls.tag_size * 8}
            for cls in classes
        ],
        "python": {"version": sys.version, "implementation": platform.python_implementation()},
        "operating_system": {"system": platform.system(), "release": platform.release(),
                             "platform": platform.platform()},
        "cpu": {"machine": platform.machine(), "processor": platform.processor()},
        "openssl": openssl,
        "config": {
            "profile": config.profile,
            "random_seed": config.random_seed,
            "message_sizes": list(config.message_sizes),
            "warmup_iterations": config.warmup_iterations,
            "benchmark_iterations": config.benchmark_iterations,
            "experiment_repetitions": config.experiment_repetitions,
            "memory_samples": config.memory_samples,
            "aad_size": BENCHMARK_AAD_SIZE,
        },
        "interpretation_warning": (
            "Pure-Python and native-c rows are NOT comparable as algorithm "
            "measurements. Compare within a tier; across tiers you are comparing "
            "implementations. See docs/EXTENDED_ALGORITHMS.md."
        ),
    }
    ENVIRONMENT_JSON.parent.mkdir(parents=True, exist_ok=True)
    ENVIRONMENT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return ENVIRONMENT_JSON


def run_extended_benchmark(config: ExperimentConfig | None = None,
                           include_aes_gcm: bool = True,
                           progress: bool = True) -> dict[str, Path]:
    """Run every pass of the extended experiment and write all CSV outputs."""
    config = config or get_config("full")
    classes = extended_cipher_classes(include_aes_gcm)
    EXTENDED_DIR.mkdir(parents=True, exist_ok=True)

    cells = _build_cells(config, classes)
    raw: list[ExtendedTimingRow] = []
    started = time.time()
    for index, cell in enumerate(cells, start=1):
        raw.extend(_run_cell(cell, config))
        if progress and (index % 10 == 0 or index == len(cells)):
            elapsed = time.time() - started
            rate = index / elapsed if elapsed else 0
            remaining = (len(cells) - index) / rate if rate else 0
            print(f"  cell {index}/{len(cells)}  elapsed {elapsed:6.1f}s  "
                  f"eta {remaining:6.1f}s", flush=True)

    paths = {
        "raw": _write_rows(raw, RAW_CSV),
        "summary": _write_rows(summarise(raw), SUMMARY_CSV),
        "overhead": _write_rows(measure_overhead(config, classes), OVERHEAD_CSV),
        "memory": _write_rows(measure_memory(config, classes), MEMORY_CSV),
        "workload": _write_rows(measure_end_to_end(config, classes), WORKLOAD_CSV),
        "environment": write_environment(config, classes),
    }
    return paths
