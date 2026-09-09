"""Shared pytest fixtures and import-path setup.

Why this file matters
---------------------
The single most common way a student project's test suite fails to run is
``ModuleNotFoundError: No module named 'src'``.  It happens because pytest adds
the *test file's* directory to ``sys.path``, not the project root.  Inserting
the project root here fixes it permanently, from any working directory, on any
operating system, whether or not the package is installed.

Deterministic keys in tests
---------------------------
Some tests need a key that does not change between runs, so that a failure is
reproducible.  ``deterministic_key`` provides one.  It is a **test-only**
fixture: production and benchmark code paths always take keys from
``os.urandom``.  The value is a visibly artificial constant so that it can never
be mistaken for a real secret if it appears in a log.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_gcm import AesGcmCipher  # noqa: E402
from src.ascon_aead import AsconAead128Cipher, is_available  # noqa: E402
from src.config import QUICK, ExperimentConfig  # noqa: E402
from src.sensor import SensorFleet, SensorReading  # noqa: E402

#: Skip marker applied to every test that needs the Ascon reference code.
requires_ascon = pytest.mark.skipif(
    not is_available(),
    reason=(
        "NIST SP 800-232 Ascon implementation not installed. "
        "Run: python scripts/setup_ascon.py"
    ),
)


@pytest.fixture(scope="session")
def config() -> ExperimentConfig:
    """A small configuration, so the suite stays fast."""
    return QUICK


@pytest.fixture
def deterministic_key() -> bytes:
    """A fixed 16-byte key. TEST USE ONLY -- never for real data."""
    return bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.fixture
def aes_cipher(deterministic_key: bytes) -> AesGcmCipher:
    return AesGcmCipher(deterministic_key)


@pytest.fixture
def ascon_cipher(deterministic_key: bytes) -> AsconAead128Cipher:
    return AsconAead128Cipher(deterministic_key)


@pytest.fixture
def sample_reading(config: ExperimentConfig) -> SensorReading:
    """One deterministic synthetic reading."""
    return SensorFleet(config).next_reading("WH-001", 0)


# Custom markers ("conformance", "slow") are declared in pyproject.toml under
# [tool.pytest.ini_options].markers rather than via a pytest_configure hook.
# pytest requires that hook's parameter to be named exactly `config`, which
# would collide with the `config` fixture above.
