"""Tests that the measurement harness produces well-formed, honest data.

These do not check *how fast* anything is -- that would be a hardware-dependent
assertion and would fail on a loaded machine.  They check that the harness
measures the right things, records them completely, and never fabricates.
"""

from __future__ import annotations

import pandas as pd
import pytest

from src.analyze_results import (
    summarise_memory,
    summarise_timings,
    t_critical_95,
)
from src.benchmark import (
    BENCHMARK_AAD_SIZE,
    _build_cells,
    measure_memory,
    measure_overhead,
    run_benchmark,
)
from src.config import OP_DECRYPT, OP_ENCRYPT, QUICK

TINY = QUICK.with_overrides(
    message_sizes=(32, 256),
    warmup_iterations=2,
    benchmark_iterations=5,
    experiment_repetitions=2,
    memory_samples=2,
)


def test_execution_order_is_shuffled_but_reproducible():
    """Both properties matter: shuffled removes bias, seeded keeps it repeatable."""
    first = _build_cells(TINY)
    second = _build_cells(TINY)
    assert [(c.cipher_cls.name, c.message_size, c.operation) for c in first] == [
        (c.cipher_cls.name, c.message_size, c.operation) for c in second
    ]

    ordered = _build_cells(TINY.with_overrides(randomize_execution_order=False))
    assert [c.cipher_cls.name for c in first] != [c.cipher_cls.name for c in ordered]


def test_shuffling_interleaves_the_algorithms():
    """If all of one algorithm ran first, thermal drift would bias the result."""
    cells = _build_cells(TINY)
    names = [cell.cipher_cls.name for cell in cells]
    if len(set(names)) < 2:
        pytest.skip("Only one algorithm installed.")
    # Count how often the algorithm changes between consecutive cells.
    switches = sum(1 for a, b in zip(names, names[1:]) if a != b)
    assert switches > len(names) // 4, "Execution order is not well interleaved."


def test_every_cell_is_enumerated():
    cells = _build_cells(TINY)
    algorithms = {cell.cipher_cls.name for cell in cells}
    expected = len(algorithms) * len(TINY.message_sizes) * 2 * TINY.experiment_repetitions
    assert len(cells) == expected


def test_overhead_is_measured_not_assumed():
    """Values must come from real encryptions, and match the specification."""
    rows = measure_overhead(TINY)
    assert rows
    for row in rows:
        assert row.ciphertext_size == row.plaintext_size + row.tag_bytes
        assert row.tag_bytes == 16
        assert row.expansion_bytes == 16
        assert row.wire_overhead_bytes == row.tag_bytes + row.nonce_bytes
        assert row.overhead_percent == pytest.approx(
            100.0 * row.wire_overhead_bytes / row.plaintext_size
        )


def test_aes_and_ascon_have_different_wire_overhead():
    """A real, reportable difference: 128-bit vs 96-bit nonces."""
    rows = measure_overhead(TINY)
    by_algorithm = {row.algorithm: row for row in rows if row.plaintext_size == 32}
    if len(by_algorithm) < 2:
        pytest.skip("Only one algorithm installed.")
    assert by_algorithm["AES-128-GCM"].nonce_bytes == 12
    assert by_algorithm["Ascon-AEAD128"].nonce_bytes == 16
    assert (
        by_algorithm["Ascon-AEAD128"].wire_overhead_bytes
        > by_algorithm["AES-128-GCM"].wire_overhead_bytes
    )


def test_memory_pass_returns_non_negative_measurements():
    rows = measure_memory(TINY)
    assert rows
    assert all(row.peak_python_heap_bytes >= 0 for row in rows)
    assert {row.operation for row in rows} == {OP_ENCRYPT, OP_DECRYPT}


def test_full_pipeline_writes_every_results_file(tmp_path, monkeypatch):
    """End-to-end: benchmark -> CSV -> statistics, with no fabricated values."""
    from src import benchmark as benchmark_module

    raw = tmp_path / "raw_results.csv"
    memory = tmp_path / "memory_results.csv"
    overhead = tmp_path / "overhead_results.csv"
    monkeypatch.setattr(benchmark_module, "RAW_RESULTS_CSV", raw)
    monkeypatch.setattr(benchmark_module, "MEMORY_RESULTS_CSV", memory)
    monkeypatch.setattr(benchmark_module, "OVERHEAD_RESULTS_CSV", overhead)

    written = run_benchmark(TINY)
    assert set(written) == {"raw", "memory", "overhead"}
    for path in (raw, memory, overhead):
        assert path.is_file() and path.stat().st_size > 0

    timings = pd.read_csv(raw)
    assert (timings["time_ns"] > 0).all(), "A non-positive timing indicates a clock bug."
    assert set(timings["operation"]) >= {
        OP_ENCRYPT, OP_DECRYPT, "keygen", "noncegen", "harness_baseline",
    }
    assert (timings["aad_size"].max()) == BENCHMARK_AAD_SIZE


def test_harness_baseline_is_recorded_and_small(tmp_path, monkeypatch):
    """The noise floor must exist and must be well below the cipher timings."""
    from src import benchmark as benchmark_module

    raw = tmp_path / "raw.csv"
    monkeypatch.setattr(benchmark_module, "RAW_RESULTS_CSV", raw)
    monkeypatch.setattr(benchmark_module, "MEMORY_RESULTS_CSV", tmp_path / "m.csv")
    monkeypatch.setattr(benchmark_module, "OVERHEAD_RESULTS_CSV", tmp_path / "o.csv")
    run_benchmark(TINY)

    timings = pd.read_csv(raw)
    baseline = timings[timings["operation"] == "harness_baseline"]["time_ns"]
    assert not baseline.empty
    assert baseline.median() > 0
    # An empty call should be far cheaper than any real cipher operation.
    cipher_times = timings[timings["operation"] == OP_ENCRYPT]["time_ns"]
    assert baseline.median() < cipher_times.median()


def test_setup_costs_are_recorded_separately_from_latency(tmp_path, monkeypatch):
    """Requirement: key and nonce generation must never be folded into latency."""
    from src import benchmark as benchmark_module

    raw = tmp_path / "raw.csv"
    monkeypatch.setattr(benchmark_module, "RAW_RESULTS_CSV", raw)
    monkeypatch.setattr(benchmark_module, "MEMORY_RESULTS_CSV", tmp_path / "m.csv")
    monkeypatch.setattr(benchmark_module, "OVERHEAD_RESULTS_CSV", tmp_path / "o.csv")
    run_benchmark(TINY)

    timings = pd.read_csv(raw)
    setup = timings[timings["operation"].isin(["keygen", "noncegen"])]
    assert not setup.empty
    # Setup rows carry message_size 0 so they can never be mixed into a
    # latency-vs-size series by accident.
    assert (setup["message_size"] == 0).all()


# -- statistics -------------------------------------------------------------

def _synthetic_timings() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "algorithm": ["AES-128-GCM"] * 10,
            "message_size": [1000] * 10,
            "operation": [OP_ENCRYPT] * 10,
            "experiment_run": [1] * 10,
            "iteration": list(range(1, 11)),
            "time_ns": [1000.0] * 9 + [2000.0],
            "batch_size": [1] * 10,
            "plaintext_size": [1000] * 10,
            "ciphertext_size": [1016] * 10,
            "aad_size": [48] * 10,
        }
    )


def test_summary_reports_both_mean_and_median():
    """With one outlier they must differ, which is exactly the point."""
    summary = summarise_timings(_synthetic_timings(), TINY)
    row = summary.iloc[0]
    assert row["mean_ns"] == pytest.approx(1100.0)
    assert row["median_ns"] == pytest.approx(1000.0)
    assert row["samples"] == 10


def test_summary_includes_dispersion_and_extremes():
    row = summarise_timings(_synthetic_timings(), TINY).iloc[0]
    for column in ("stdev_ns", "min_ns", "max_ns", "p95_ns"):
        assert column in row
    assert row["min_ns"] == 1000.0
    assert row["max_ns"] == 2000.0


def test_confidence_interval_brackets_the_mean():
    row = summarise_timings(_synthetic_timings(), TINY).iloc[0]
    assert row["ci95_lower_ns"] < row["mean_ns"] < row["ci95_upper_ns"]
    assert row["ci95_half_width_ns"] > 0


def test_throughput_is_derived_from_the_measurements():
    """1000 bytes in 1000 ns = 1 byte/ns = 1000 MB/s."""
    row = summarise_timings(_synthetic_timings(), TINY).iloc[0]
    assert row["throughput_mb_s_median"] == pytest.approx(1000.0)
    assert row["messages_per_second_median"] == pytest.approx(1_000_000.0)


def test_harness_baseline_is_excluded_from_the_summary():
    frame = _synthetic_timings()
    baseline = frame.copy()
    baseline["algorithm"] = "HARNESS-BASELINE"
    baseline["operation"] = "harness_baseline"
    summary = summarise_timings(pd.concat([frame, baseline]), TINY)
    assert "HARNESS-BASELINE" not in set(summary["algorithm"])


def test_t_critical_values_are_sane():
    assert t_critical_95(1) > t_critical_95(10) > t_critical_95(1000)
    assert t_critical_95(1000) == pytest.approx(1.96, abs=0.01)


def test_memory_summary_aggregates_correctly():
    frame = pd.DataFrame(
        {
            "algorithm": ["AES-128-GCM"] * 4,
            "message_size": [32] * 4,
            "operation": [OP_ENCRYPT] * 4,
            "sample": [1, 2, 3, 4],
            "peak_python_heap_bytes": [100, 200, 300, 400],
            "current_python_heap_bytes": [0, 0, 0, 0],
        }
    )
    row = summarise_memory(frame).iloc[0]
    assert row["samples"] == 4
    assert row["mean_peak_bytes"] == pytest.approx(250.0)
    assert row["median_peak_bytes"] == pytest.approx(250.0)
