"""Capture everything needed to reproduce, or fail to reproduce, a result.

A performance number without its environment is not a result, it is an anecdote.
"AES-GCM encrypted a 256-byte message in 1.1 microseconds" is meaningless
unless the reader knows the CPU, whether AES-NI was available, which OpenSSL
build the ``cryptography`` wheel linked against, which Ascon commit was used,
and what the iteration counts were.  This module records all of that
automatically into ``results/environment.json`` on every benchmark run.

Privacy note
------------
Only machine and software characteristics are recorded.  Username, hostname,
home directory, IP address, MAC address and absolute filesystem paths outside
the project are all deliberately excluded, because ``environment.json`` is
intended to be committed to a public repository and submitted with the report.
``platform.node()`` in particular is *not* called: on many systems it returns a
name that identifies the owner.
"""

from __future__ import annotations

import json
import multiprocessing
import platform
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from .ascon_loader import ascon_provenance
from .config import ENVIRONMENT_JSON, ExperimentConfig

#: Packages whose version can affect a measurement or a cryptographic result.
TRACKED_PACKAGES: tuple[str, ...] = (
    "cryptography",
    "pandas",
    "matplotlib",
    "numpy",
    "psutil",
    "pytest",
)


def _package_versions() -> dict[str, str]:
    """Report installed versions of the packages that matter."""
    versions: dict[str, str] = {}
    for name in TRACKED_PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "not installed"
    return versions


def _openssl_info() -> dict[str, str]:
    """Identify the OpenSSL build behind AES-GCM.

    This is arguably the single most important field in the whole file: AES-GCM
    performance is dominated by whether OpenSSL dispatches to AES-NI and
    PCLMULQDQ hardware instructions, and that depends on the build and the CPU.
    """
    info: dict[str, str] = {}
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        info["openssl_version"] = backend.openssl_version_text()
    except Exception as exc:  # pragma: no cover - depends on library internals
        info["openssl_version"] = f"unavailable ({type(exc).__name__})"
    try:
        import ssl

        info["python_ssl_module_openssl"] = ssl.OPENSSL_VERSION
    except Exception:  # pragma: no cover
        info["python_ssl_module_openssl"] = "unavailable"
    return info


def _cpu_info() -> dict[str, object]:
    """Best-effort CPU description, without identifying the machine's owner."""
    info: dict[str, object] = {
        "machine": platform.machine(),
        "processor": platform.processor(),
        "architecture": platform.architecture()[0],
        "logical_cores": multiprocessing.cpu_count(),
    }
    try:
        import psutil

        info["physical_cores"] = psutil.cpu_count(logical=False)
        frequency = psutil.cpu_freq()
        if frequency is not None:
            info["cpu_freq_max_mhz"] = frequency.max
            info["cpu_freq_current_mhz"] = frequency.current
        info["total_ram_bytes"] = psutil.virtual_memory().total
        info["total_ram_gib"] = round(psutil.virtual_memory().total / (1024**3), 2)
    except ImportError:
        info["psutil"] = "not installed; CPU frequency and RAM unavailable"
    except Exception as exc:  # pragma: no cover - psutil can fail in containers
        info["psutil_error"] = f"{type(exc).__name__}: {exc}"

    # A note on why a fixed clock matters for benchmarking.
    info["note"] = (
        "Modern CPUs vary clock speed with load and temperature. Latency "
        "measured on a throttling machine is not comparable with latency "
        "measured on a cool one; state this in the report."
    )
    return info


def collect(config: ExperimentConfig) -> dict[str, object]:
    """Gather the full environment record."""
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": {
            "title": (
                "Performance Evaluation of Ascon-AEAD128 and AES-128-GCM "
                "for Secure IoT Communication: A Proof-of-Concept Study"
            ),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
            "build": " ".join(platform.python_build()),
            "executable_is_venv": sys.prefix != sys.base_prefix,
        },
        "operating_system": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "platform": platform.platform(),
            # platform.node() is intentionally omitted: it can identify the user.
        },
        "cpu": _cpu_info(),
        "crypto_backends": {
            "aes_gcm": {
                "library": "cryptography (pyca)",
                "api": "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
                "algorithm": "AES-128-GCM",
                "standard": "NIST SP 800-38D",
                **_openssl_info(),
            },
            "ascon": ascon_provenance(),
        },
        "package_versions": _package_versions(),
        "experiment_parameters": asdict(config),
        "reproducibility_note": (
            "random_seed governs synthetic sensor values and benchmark execution "
            "order only. Cryptographic keys and nonces always come from "
            "os.urandom and are never seeded; a reproducible nonce would be a "
            "reused nonce."
        ),
    }


def write(config: ExperimentConfig, path: Path = ENVIRONMENT_JSON) -> Path:
    """Write the environment record as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = collect(config)
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return path


def format_console(record: dict[str, object]) -> str:
    """Render the key fields for the terminal."""
    cpu = record.get("cpu", {})
    os_info = record.get("operating_system", {})
    python = record.get("python", {})
    backends = record.get("crypto_backends", {})
    ascon = backends.get("ascon", {}) if isinstance(backends, dict) else {}
    aes = backends.get("aes_gcm", {}) if isinstance(backends, dict) else {}

    lines = [
        "Environment",
        "-" * 60,
        f"OS              : {os_info.get('platform')}",
        f"CPU             : {cpu.get('processor') or cpu.get('machine')}",
        f"Logical cores   : {cpu.get('logical_cores')}",
        f"RAM             : {cpu.get('total_ram_gib', 'unknown')} GiB",
        f"Python          : {python.get('version')} ({python.get('implementation')})",
        f"Virtualenv      : {'yes' if python.get('executable_is_venv') else 'NO - see README'}",
        f"OpenSSL         : {aes.get('openssl_version')}",
        f"Ascon available : {ascon.get('available')}",
        f"Ascon module    : {ascon.get('module_file', 'n/a')}",
    ]
    return "\n".join(lines)
