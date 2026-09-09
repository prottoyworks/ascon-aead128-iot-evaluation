"""The measurement harness.

Design rules, and the reasoning behind each
-------------------------------------------
1. **Only the cryptographic call is inside the timed region.**  Input
   generation, serialisation, list appends, CSV writing and console output all
   happen outside it.  Timing anything else would measure Python's I/O layer,
   not the cipher.

2. **``time.perf_counter_ns()`` is the clock.**  It is monotonic, has the
   highest resolution the platform offers, and returns integer nanoseconds, so
   no floating-point rounding is introduced before aggregation.  On Windows its
   resolution is typically ~100 ns, which is why the very fastest operations
   are timed in batches (see rule 3).

3. **Sub-microsecond operations are timed in batches, at constant total work.**
   An OpenSSL AES-GCM call on a 32-byte message can take less than a
   microsecond -- close enough to the clock's resolution that per-call timing
   would be dominated by quantisation and by the ~50-100 ns cost of calling the
   clock itself.  Such operations are executed in a batch of ``batch_size`` and
   the elapsed time divided.

   Critically, ``benchmark_iterations`` counts **cryptographic operations**,
   not recorded samples: when batching applies, the sample count is divided by
   the batch size so that both algorithms execute the same number of
   operations.  Getting this wrong is easy and consequential -- treating
   ``benchmark_iterations`` as a sample count would silently make the batched
   algorithm do ``batch_size`` times more work than the unbatched one.  See
   ``_measure_samples``.

   The trade-off that remains is real: batching buys an unbiased mean at the
   cost of per-call variance information.  ``batch_size`` is recorded in every
   raw row so no reader mistakes a batched mean for a single-call sample.
   Ascon at the same message size takes hundreds of microseconds and is never
   batched -- and that asymmetry is itself a reportable finding.

4. **Warm-up before every measured block.**  CPython's first executions of a
   code path pay for bytecode specialisation and branch-predictor cold start;
   OpenSSL may resolve CPU-feature dispatch lazily.  Discarding the first
   ``warmup_iterations`` results removes that transient.

5. **Execution order is randomised.**  If every AES cell ran before every Ascon
   cell, a laptop that thermally throttles partway through would systematically
   penalise whichever algorithm ran second.  The (algorithm, size, operation,
   repetition) cells are shuffled with a seeded RNG -- reproducible, but not
   correlated with the algorithm.

6. **Key setup and nonce generation are measured separately.**  Never folded
   into per-message latency.  This is what makes the AES/Ascon comparison
   honest: AES-GCM amortises key expansion across a session, the Ascon
   reference implementation absorbs the key on every call, and the reader can
   see both numbers.

7. **Memory is measured in a separate pass.**  ``tracemalloc`` adds a large,
   uneven overhead to every allocation, so running it during the timing pass
   would corrupt the latency figures.

   A caveat that must appear in the report: ``tracemalloc`` observes *Python
   heap allocations only*.  AES-GCM's real working memory is allocated inside
   OpenSSL's C code and is invisible to it, whereas the pure-Python Ascon
   implementation allocates Python integers for its entire state.  The two
   numbers are therefore **not comparable as algorithm memory footprints** and
   must be described as "peak Python-heap allocation observed in this
   implementation".  Anything stronger would be false.
"""

from __future__ import annotations

import csv
import gc
import os
import random
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

from .aead_interface import AeadCipher
from .aes_gcm import AesGcmCipher
from .ascon_aead import AsconAead128Cipher, is_available as ascon_available
from .config import (
    MEMORY_RESULTS_CSV,
    OP_DECRYPT,
    OP_ENCRYPT,
    OP_KEYGEN,
    OP_NONCEGEN,
    OVERHEAD_RESULTS_CSV,
    RAW_RESULTS_CSV,
    ExperimentConfig,
)

#: Fixed associated-data size used for every benchmark message, so the AAD
#: length is a controlled constant and the message-size axis is the only
#: variable. 48 bytes is close to the real serialised AAD produced by
#: src/serialization.py for a warehouse reading.
BENCHMARK_AAD_SIZE: int = 48

#: If a single operation is expected to be faster than this, time a batch of
#: calls instead of one. 20 microseconds is comfortably above the resolution
#: and call cost of perf_counter_ns on every platform this targets.
BATCH_THRESHOLD_NS: int = 20_000

#: How many calls to batch when batching is triggered.
#:
#: 20 is chosen as the smallest batch that still lifts a sub-microsecond
#: operation well clear of the clock: 20 x ~1 us = ~20 us elapsed, roughly two
#: hundred times the ~100 ns resolution of perf_counter_ns on Windows. A larger
#: batch would measure no more accurately but would cost proportionally more
#: recorded-sample resolution -- see `_measure_samples` for why.
DEFAULT_BATCH_SIZE: int = 20

#: Never record fewer than this many samples per cell, whatever the batching,
#: so that a mean and a confidence interval remain meaningful.
MIN_SAMPLES_PER_CELL: int = 25


@dataclass(frozen=True)
class TimingRow:
    """One row of ``results/raw_results.csv``.

    ``time_ns`` is the per-operation time.  When ``batch_size`` > 1 it is the
    batch's elapsed time divided by ``batch_size``; the column is retained so
    that no reader mistakes a batched mean for a single-call sample.
    """

    algorithm: str
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
class MemoryRow:
    """One row of ``results/memory_results.csv``."""

    algorithm: str
    message_size: int
    operation: str
    sample: int
    peak_python_heap_bytes: int
    current_python_heap_bytes: int


@dataclass(frozen=True)
class OverheadRow:
    """One row of ``results/overhead_results.csv``."""

    algorithm: str
    plaintext_size: int
    ciphertext_size: int
    tag_bytes: int
    nonce_bytes: int
    expansion_bytes: int
    wire_overhead_bytes: int
    overhead_percent: float


def _cipher_classes() -> list[type[AeadCipher]]:
    """Return the cipher classes to benchmark, in a fixed declaration order.

    Declaration order does not determine execution order -- that is shuffled --
    but keeping it stable makes the CSV diffable between runs.
    """
    classes: list[type[AeadCipher]] = [AesGcmCipher]
    if ascon_available():
        classes.append(AsconAead128Cipher)
    return classes


# --------------------------------------------------------------------------
# Timing primitives
# --------------------------------------------------------------------------

def _time_single(operation: Callable[[], object]) -> int:
    """Time one call, in nanoseconds."""
    start = time.perf_counter_ns()
    operation()
    return time.perf_counter_ns() - start


def _time_batch(operation: Callable[[], object], batch_size: int) -> float:
    """Time `batch_size` calls and return the mean nanoseconds per call."""
    start = time.perf_counter_ns()
    for _ in range(batch_size):
        operation()
    return (time.perf_counter_ns() - start) / batch_size


def _calibrate_batch_size(operation: Callable[[], object]) -> int:
    """Decide whether an operation is fast enough to need batching.

    Runs a handful of trial calls and compares the median against
    ``BATCH_THRESHOLD_NS``.  Trial calls also serve as extra warm-up.
    """
    samples = sorted(_time_single(operation) for _ in range(7))
    median = samples[len(samples) // 2]
    return DEFAULT_BATCH_SIZE if median < BATCH_THRESHOLD_NS else 1


def _measure_samples(
    operation: Callable[[], object], config: ExperimentConfig, batch_size: int
) -> list[float]:
    """Run one cell's measurements and return per-operation times in ns.

    ``benchmark_iterations`` is the number of **cryptographic operations** per
    cell, not the number of recorded samples.  When batching is in effect the
    sample count is divided by the batch size, so that::

        operations executed = samples x batch_size ~= benchmark_iterations

    holds for *both* algorithms.

    Why this definition matters
    ---------------------------
    The obvious alternative -- treat ``benchmark_iterations`` as the number of
    recorded samples and let each sample be a full batch -- would make the
    batched algorithm execute ``batch_size`` times as many cryptographic
    operations as the unbatched one.  With AES-GCM batched and Ascon not, AES
    would perform twenty times more work for the same nominal configuration.
    Besides inflating the run time enormously, it would mean the two algorithms
    were never actually given the same experimental treatment, which is exactly
    the kind of silent asymmetry this harness exists to avoid.

    A floor of ``MIN_SAMPLES_PER_CELL`` keeps the sample count high enough for
    a mean and a confidence interval to mean something.
    """
    if batch_size <= 1:
        samples = config.benchmark_iterations
    else:
        samples = max(MIN_SAMPLES_PER_CELL, config.benchmark_iterations // batch_size)

    # Garbage collection is disabled across the measured region so that a
    # collection cycle triggered by unrelated allocation cannot land inside one
    # sample and show up as a spurious outlier.
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        if batch_size <= 1:
            return [float(_time_single(operation)) for _ in range(samples)]
        return [_time_batch(operation, batch_size) for _ in range(samples)]
    finally:
        if gc_was_enabled:
            gc.enable()


# --------------------------------------------------------------------------
# Benchmark cells
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Cell:
    """One unit of work: an algorithm, a size, an operation, a repetition."""

    cipher_cls: type[AeadCipher]
    message_size: int
    operation: str
    experiment_run: int


def _build_cells(config: ExperimentConfig) -> list[Cell]:
    """Enumerate every (algorithm, size, operation, repetition) cell."""
    cells: list[Cell] = []
    for cipher_cls in _cipher_classes():
        for size in config.message_sizes:
            for operation in (OP_ENCRYPT, OP_DECRYPT):
                for run in range(1, config.experiment_repetitions + 1):
                    cells.append(Cell(cipher_cls, size, operation, run))
    if config.randomize_execution_order:
        # Seeded: reproducible, but uncorrelated with algorithm identity.
        random.Random(config.random_seed).shuffle(cells)
    return cells


def _run_cell(cell: Cell, config: ExperimentConfig) -> list[TimingRow]:
    """Execute one cell and return its measured rows.

    All setup -- key, nonce, plaintext, AAD, and for decryption the ciphertext
    -- happens here, *before* the timed region.
    """
    cipher = cell.cipher_cls(cell.cipher_cls.generate_key())
    nonce = cipher.generate_nonce()
    plaintext = os.urandom(cell.message_size)
    aad = os.urandom(BENCHMARK_AAD_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)

    if cell.operation == OP_ENCRYPT:
        operation: Callable[[], object] = lambda: cipher.encrypt(nonce, plaintext, aad)
    else:
        operation = lambda: cipher.decrypt(nonce, ciphertext, aad)

    # Warm-up: results discarded.
    for _ in range(config.warmup_iterations):
        operation()

    batch_size = _calibrate_batch_size(operation)
    times = _measure_samples(operation, config, batch_size)

    return [
        TimingRow(
            algorithm=cipher.name,
            message_size=cell.message_size,
            operation=cell.operation,
            experiment_run=cell.experiment_run,
            iteration=index + 1,
            time_ns=value,
            batch_size=batch_size,
            plaintext_size=cell.message_size,
            ciphertext_size=len(ciphertext),
            aad_size=BENCHMARK_AAD_SIZE,
        )
        for index, value in enumerate(times)
    ]


def _run_setup_costs(config: ExperimentConfig) -> list[TimingRow]:
    """Measure key setup and nonce generation as first-class, separate metrics.

    Reported alongside -- never inside -- encryption latency.  ``message_size``
    is recorded as 0 because neither cost depends on the message.
    """
    rows: list[TimingRow] = []
    for cipher_cls in _cipher_classes():
        key = cipher_cls.generate_key()

        # Key setup: for AES-GCM this is the AESGCM() constructor (key
        # expansion); for Ascon it is the wrapper's __init__, which does almost
        # nothing because the reference implementation absorbs the key inside
        # each encrypt call. That difference is the finding, not a flaw.
        keygen_op: Callable[[], object] = lambda cls=cipher_cls, k=key: cls(k)
        noncegen_op: Callable[[], object] = lambda cls=cipher_cls: cls.generate_nonce()

        for operation, callable_ in ((OP_KEYGEN, keygen_op), (OP_NONCEGEN, noncegen_op)):
            for _ in range(config.warmup_iterations):
                callable_()
            batch_size = _calibrate_batch_size(callable_)
            for run in range(1, config.experiment_repetitions + 1):
                for index, value in enumerate(
                    _measure_samples(callable_, config, batch_size)
                ):
                    rows.append(
                        TimingRow(
                            algorithm=cipher_cls.name,
                            message_size=0,
                            operation=operation,
                            experiment_run=run,
                            iteration=index + 1,
                            time_ns=value,
                            batch_size=batch_size,
                            plaintext_size=0,
                            ciphertext_size=0,
                            aad_size=0,
                        )
                    )
    return rows


def _run_harness_baseline(config: ExperimentConfig) -> list[TimingRow]:
    """Measure the harness's own cost: the noise floor of every other number.

    Why this exists
    ---------------
    Each timed sample includes not only the cipher call but also a Python
    function-call frame, the loop step, and the ``perf_counter_ns`` calls
    themselves.  For Ascon, running in hundreds of microseconds, that overhead
    is irrelevant.  For OpenSSL-backed AES-GCM on a 32-byte message, running in
    around a microsecond, it is *not* irrelevant -- it can be a meaningful
    fraction of the reported figure.

    Ignoring this would systematically inflate the faster algorithm's latency
    and understate its throughput.  Rather than silently subtracting a
    correction, this function measures an empty callable through the identical
    code path and records it as its own row.  ``analyze_results.py`` then
    reports the floor next to the measurements, so a reader can judge which
    numbers are comfortably above it and which are close to it.

    This is the single most important honesty control in the benchmark, and the
    results chapter should quote it.
    """
    rows: list[TimingRow] = []
    noop: Callable[[], object] = lambda: None

    for _ in range(config.warmup_iterations):
        noop()
    batch_size = _calibrate_batch_size(noop)

    for run in range(1, config.experiment_repetitions + 1):
        for index, value in enumerate(_measure_samples(noop, config, batch_size)):
            rows.append(
                TimingRow(
                    algorithm="HARNESS-BASELINE",
                    message_size=0,
                    operation="harness_baseline",
                    experiment_run=run,
                    iteration=index + 1,
                    time_ns=value,
                    batch_size=batch_size,
                    plaintext_size=0,
                    ciphertext_size=0,
                    aad_size=0,
                )
            )
    return rows


# --------------------------------------------------------------------------
# Memory pass (separate from timing)
# --------------------------------------------------------------------------

def measure_memory(config: ExperimentConfig) -> list[MemoryRow]:
    """Record peak Python-heap allocation per operation.

    See the module docstring for why these numbers must not be presented as
    algorithm memory footprints.
    """
    rows: list[MemoryRow] = []
    for cipher_cls in _cipher_classes():
        for size in config.message_sizes:
            cipher = cipher_cls(cipher_cls.generate_key())
            nonce = cipher.generate_nonce()
            plaintext = os.urandom(size)
            aad = os.urandom(BENCHMARK_AAD_SIZE)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)

            for operation, call in (
                (OP_ENCRYPT, lambda: cipher.encrypt(nonce, plaintext, aad)),
                (OP_DECRYPT, lambda: cipher.decrypt(nonce, ciphertext, aad)),
            ):
                call()  # warm up, so first-call caching is not attributed here
                for sample in range(1, config.memory_samples + 1):
                    gc.collect()
                    tracemalloc.start()
                    call()
                    current, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    rows.append(
                        MemoryRow(
                            algorithm=cipher.name,
                            message_size=size,
                            operation=operation,
                            sample=sample,
                            peak_python_heap_bytes=peak,
                            current_python_heap_bytes=current,
                        )
                    )
    return rows


# --------------------------------------------------------------------------
# Ciphertext / communication overhead (deterministic, not timed)
# --------------------------------------------------------------------------

def measure_overhead(config: ExperimentConfig) -> list[OverheadRow]:
    """Compute cryptographic expansion for every algorithm and message size.

    These values are structural rather than statistical -- AEAD expansion is a
    fixed function of the algorithm -- so a single observation per cell is
    sufficient.  They are still *measured* (by encrypting and looking at the
    result) rather than assumed from the specification, so that a mismatch
    between documentation and implementation would show up.
    """
    rows: list[OverheadRow] = []
    for cipher_cls in _cipher_classes():
        cipher = cipher_cls(cipher_cls.generate_key())
        aad = os.urandom(BENCHMARK_AAD_SIZE)
        for size in config.message_sizes:
            result = cipher.seal(os.urandom(size), aad)
            rows.append(
                OverheadRow(
                    algorithm=cipher.name,
                    plaintext_size=size,
                    ciphertext_size=result.ciphertext_size,
                    tag_bytes=cipher.tag_size,
                    nonce_bytes=cipher.nonce_size,
                    expansion_bytes=result.expansion_bytes,
                    wire_overhead_bytes=result.wire_overhead_bytes,
                    overhead_percent=100.0 * result.wire_overhead_bytes / size,
                )
            )
    return rows


# --------------------------------------------------------------------------
# Orchestration and CSV output
# --------------------------------------------------------------------------

def _write_rows(rows: Sequence[object], path: Path) -> Path:
    """Write a sequence of dataclass rows to CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"Refusing to write an empty results file: {path}")
    fieldnames = list(asdict(rows[0]).keys())  # type: ignore[arg-type]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))  # type: ignore[arg-type]
    return path


def run_benchmark(
    config: ExperimentConfig,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Path]:
    """Run the full measurement campaign and write every results file.

    Args:
        config: Experiment parameters.
        progress: Optional callback for status messages.  Never called from
            inside a timed region.

    Returns:
        Mapping of result name to the file that was written.
    """
    report = progress if progress is not None else (lambda _msg: None)

    cells = _build_cells(config)
    report(
        f"Timing pass: {len(cells)} cells "
        f"x {config.benchmark_iterations} iterations."
    )

    timing_rows: list[TimingRow] = []
    for index, cell in enumerate(cells, start=1):
        timing_rows.extend(_run_cell(cell, config))
        if index % 10 == 0 or index == len(cells):
            report(f"  cell {index}/{len(cells)} complete")

    report("Setup-cost pass (key setup, nonce generation)...")
    timing_rows.extend(_run_setup_costs(config))

    report("Harness-baseline pass (measuring the noise floor)...")
    timing_rows.extend(_run_harness_baseline(config))

    report("Memory pass (tracemalloc, separate from timing)...")
    memory_rows = measure_memory(config)

    report("Overhead pass (ciphertext expansion)...")
    overhead_rows = measure_overhead(config)

    written = {
        "raw": _write_rows(timing_rows, RAW_RESULTS_CSV),
        "memory": _write_rows(memory_rows, MEMORY_RESULTS_CSV),
        "overhead": _write_rows(overhead_rows, OVERHEAD_RESULTS_CSV),
    }
    report(f"Wrote {len(timing_rows)} timing rows to {RAW_RESULTS_CSV.name}")
    return written


def estimate_runtime_note(config: ExperimentConfig) -> str:
    """A short, honest statement of how much work the configuration implies.

    Deliberately reports the operation *count* rather than a predicted duration:
    the duration depends entirely on the host machine, and quoting a number
    here would be a fabricated measurement.
    """
    return (
        f"Profile '{config.profile}': {len(_cipher_classes())} algorithm(s) x "
        f"{len(config.message_sizes)} sizes x 2 operations x "
        f"{config.experiment_repetitions} repetitions x "
        f"{config.benchmark_iterations} iterations "
        f"= {config.total_timed_operations:,} timed cryptographic operations "
        "(plus warm-up, setup-cost, memory and overhead passes). "
        "Wall-clock duration depends on your hardware."
    )
