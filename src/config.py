"""Central experiment configuration.

Every tunable value used by the experiment lives here.  Nothing that affects a
measurement is hard-coded anywhere else in the code base, so a reader of the
report can inspect this single file and know exactly how the experiment was
parameterised.

Two named profiles are provided:

* ``QUICK``  -- tiny iteration counts, used to verify that the pipeline works
                end-to-end before committing to a long run.
* ``FULL``   -- the parameters used for results that are reported.

Paths are derived from the location of this file, so the project can be cloned
to any directory on any operating system without editing anything.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
# --------------------------------------------------------------------------
# Project layout
# --------------------------------------------------------------------------
# config.py lives in <root>/src/, so the project root is one level up.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

DATA_DIR: Path = PROJECT_ROOT / "data"
RESULTS_DIR: Path = PROJECT_ROOT / "results"
GRAPHS_DIR: Path = RESULTS_DIR / "graphs"
THIRD_PARTY_DIR: Path = PROJECT_ROOT / "third_party"
DOCS_DIR: Path = PROJECT_ROOT / "docs"

SENSOR_CSV: Path = DATA_DIR / "sensor_messages.csv"
RAW_RESULTS_CSV: Path = RESULTS_DIR / "raw_results.csv"
SUMMARY_RESULTS_CSV: Path = RESULTS_DIR / "summary_results.csv"
MEMORY_RESULTS_CSV: Path = RESULTS_DIR / "memory_results.csv"
OVERHEAD_RESULTS_CSV: Path = RESULTS_DIR / "overhead_results.csv"
SECURITY_RESULTS_CSV: Path = RESULTS_DIR / "security_results.csv"
KAT_RESULTS_CSV: Path = RESULTS_DIR / "kat_results.csv"
ENVIRONMENT_JSON: Path = RESULTS_DIR / "environment.json"

# Vendored third-party reference material (populated by scripts/setup_ascon.py)
PYASCON_DIR: Path = THIRD_PARTY_DIR / "pyascon"
ASCON_KAT_FILE: Path = THIRD_PARTY_DIR / "ascon_kat" / "LWC_AEAD_KAT_128_128.txt"
PROVENANCE_JSON: Path = THIRD_PARTY_DIR / "PROVENANCE.json"


# --------------------------------------------------------------------------
# Algorithm identifiers
# --------------------------------------------------------------------------
ALG_AES_GCM: str = "AES-128-GCM"
ALG_ASCON: str = "Ascon-AEAD128"
ALGORITHMS: tuple[str, ...] = (ALG_AES_GCM, ALG_ASCON)

# Operations that are timed independently.  Keeping key generation and nonce
# generation as separate operations (rather than folding them into `encrypt`)
# is a deliberate methodological choice -- see docs/METHODOLOGY.md.
OP_ENCRYPT: str = "encrypt"
OP_DECRYPT: str = "decrypt"
OP_KEYGEN: str = "keygen"
OP_NONCEGEN: str = "noncegen"


@dataclass(frozen=True)
class ExperimentConfig:
    """Immutable description of one experimental configuration."""

    #: Name of the profile, recorded in results/environment.json.
    profile: str = "full"

    # ---- reproducibility -------------------------------------------------
    #: Seed for every *non-cryptographic* random choice (synthetic sensor
    #: values, benchmark execution order).  Cryptographic key and nonce
    #: material is NEVER derived from this seed -- it always comes from the
    #: operating system CSPRNG.  See docs/METHODOLOGY.md.
    random_seed: int = 42

    # ---- synthetic dataset ----------------------------------------------
    sensor_messages: int = 10_000
    device_ids: tuple[str, ...] = ("WH-001", "WH-002", "WH-003", "WH-004", "WH-005")
    protocol_version: int = 1

    # Physically plausible ranges for a smart-warehouse deployment.
    temperature_range_c: tuple[float, float] = (18.0, 35.0)
    humidity_range_pct: tuple[float, float] = (30.0, 85.0)
    gas_level_range: tuple[int, int] = (50, 300)

    # ---- benchmark parameters -------------------------------------------
    message_sizes: tuple[int, ...] = (32, 64, 128, 256, 512, 1024, 2048, 4096)
    warmup_iterations: int = 100
    #: Number of *cryptographic operations* measured per cell -- not the number
    #: of recorded samples. Operations faster than the clock can resolve are
    #: timed in batches, and the sample count is divided accordingly, so both
    #: algorithms perform the same amount of work. See src/benchmark.py.
    benchmark_iterations: int = 1_000
    experiment_repetitions: int = 10

    #: Randomise the order in which (algorithm, size, operation) cells are
    #: executed so that machine warm-up / thermal drift does not bias one
    #: algorithm systematically.  Uses `random_seed`, so it is reproducible.
    randomize_execution_order: bool = True

    #: Number of samples used for the tracemalloc memory pass.  Kept small and
    #: run separately from the timing pass because tracemalloc instrumentation
    #: perturbs timing.
    memory_samples: int = 20

    # ---- security-test parameters ---------------------------------------
    #: How many independent random trials each tampering test performs.  A
    #: single trial could pass by luck; repeating makes the result meaningful.
    security_trials: int = 100
    #: Number of random round-trip messages used in correctness tests.
    roundtrip_trials: int = 100

    # ---- statistics ------------------------------------------------------
    confidence_level: float = 0.95

    # ---- output ----------------------------------------------------------
    graph_dpi: int = 160
    graph_format: str = "png"

    def with_overrides(self, **kwargs) -> "ExperimentConfig":
        """Return a copy of this config with selected fields replaced."""
        return replace(self, **kwargs)

    @property
    def total_timed_operations(self) -> int:
        """Number of individually timed crypto calls in the timing pass."""
        cells = len(ALGORITHMS) * len(self.message_sizes) * 2  # encrypt+decrypt
        return cells * self.benchmark_iterations * self.experiment_repetitions


#: Parameters used for reported results.
FULL = ExperimentConfig(profile="full")

#: Fast smoke-test parameters.  Numbers are deliberately far too small for a
#: defensible measurement -- their only purpose is to prove the pipeline runs.
QUICK = ExperimentConfig(
    profile="quick",
    sensor_messages=500,
    warmup_iterations=5,
    benchmark_iterations=20,
    experiment_repetitions=2,
    memory_samples=5,
    security_trials=10,
    roundtrip_trials=10,
)

PROFILES: dict[str, ExperimentConfig] = {"quick": QUICK, "full": FULL}


def get_config(profile: str = "full") -> ExperimentConfig:
    """Look up a named profile.

    Raises:
        KeyError: if `profile` is not a known profile name.
    """
    key = profile.lower()
    if key not in PROFILES:
        raise KeyError(f"Unknown profile {profile!r}. Choose one of {sorted(PROFILES)}.")
    return PROFILES[key]


def ensure_output_dirs() -> None:
    """Create the output directories if they do not already exist."""
    for directory in (DATA_DIR, RESULTS_DIR, GRAPHS_DIR, THIRD_PARTY_DIR):
        directory.mkdir(parents=True, exist_ok=True)
