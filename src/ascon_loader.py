"""Locate and load the Ascon reference implementation, with provenance.

This module isolates one fragile concern -- "where did the Ascon code come
from?" -- from the clean cryptographic wrapper in ``ascon_aead.py``.

Resolution order
----------------
1. ``third_party/pyascon/ascon.py``  (vendored by ``scripts/setup_ascon.py``)
2. A module named ``ascon`` already importable on ``sys.path``

Rule 2 exists so an advanced user can point the project at their own copy.
It is checked *second* and validated: any implementation that does not expose
the ``Ascon-AEAD128`` variant is rejected with an explicit error rather than
being silently used.  This matters because the ``ascon`` package published on
PyPI (version 0.0.9 at the time of writing) implements only the superseded
Ascon v1.2 competition candidates -- ``Ascon-128``, ``Ascon-128a`` and
``Ascon-80pq`` -- which are *not* the standardised algorithm and produce
different ciphertexts.  Loading it by accident would silently invalidate the
entire experiment.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

from .config import PROVENANCE_JSON, PYASCON_DIR

ASCON_VARIANT: str = "Ascon-AEAD128"

_SETUP_HINT = (
    "The NIST SP 800-232 Ascon reference implementation was not found.\n"
    "Run the setup helper from the project root:\n\n"
    "    python scripts/setup_ascon.py\n\n"
    "See README.md, section 'Ascon setup', for the manual alternative."
)


class AsconUnavailableError(ImportError):
    """Raised when no SP 800-232-capable Ascon implementation can be loaded."""


def _load_from_path(module_path: Path) -> ModuleType | None:
    """Import ``ascon.py`` directly from a file path, if it exists."""
    if not module_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("vendored_ascon", module_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return None
    module = importlib.util.module_from_spec(spec)
    # Registering before exec lets the module reference itself if it needs to.
    sys.modules["vendored_ascon"] = module
    spec.loader.exec_module(module)
    return module


def _supports_sp800_232(module: ModuleType) -> bool:
    """Return True only if the module implements Ascon-AEAD128 correctly.

    A structural check (does the function exist?) is not enough, because the
    obsolete PyPI package also exposes ``ascon_encrypt``.  Instead we perform a
    behavioural check: encrypt an empty message under an all-zero key and nonce
    and require the call to succeed with the ``Ascon-AEAD128`` variant name and
    to produce exactly a 16-byte tag.  Full cryptographic conformance is
    established separately by the known-answer tests in ``src/kat.py``.
    """
    encrypt = getattr(module, "ascon_encrypt", None)
    decrypt = getattr(module, "ascon_decrypt", None)
    if not callable(encrypt) or not callable(decrypt):
        return False
    try:
        out = encrypt(bytes(16), bytes(16), b"", b"", ASCON_VARIANT)
    except Exception:
        # An AssertionError here is exactly what the v1.2-only PyPI package
        # raises, because "Ascon-AEAD128" is not in its variant list.
        return False
    return isinstance(out, (bytes, bytearray)) and len(out) == 16


def load_ascon_module() -> ModuleType:
    """Return a module implementing NIST SP 800-232 Ascon-AEAD128.

    Raises:
        AsconUnavailableError: if nothing suitable is found.
    """
    candidates: list[tuple[str, ModuleType]] = []

    vendored = _load_from_path(PYASCON_DIR / "ascon.py")
    if vendored is not None:
        candidates.append(("vendored", vendored))

    try:
        installed = importlib.import_module("ascon")
    except ImportError:
        installed = None
    if installed is not None:
        candidates.append(("installed", installed))

    rejected: list[str] = []
    for origin, module in candidates:
        if _supports_sp800_232(module):
            return module
        rejected.append(f"{origin} ({getattr(module, '__file__', 'unknown path')})")

    detail = ""
    if rejected:
        detail = (
            "\n\nAn Ascon module was found but rejected because it does not "
            "implement the standardised Ascon-AEAD128 variant:\n  - "
            + "\n  - ".join(rejected)
            + "\nThis is the expected result for the obsolete PyPI 'ascon' "
              "package, which only implements the Ascon v1.2 candidates."
        )
    raise AsconUnavailableError(_SETUP_HINT + detail)


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ascon_provenance() -> dict[str, object]:
    """Describe exactly which Ascon code is in use, for the environment log.

    Every field is derived from the files actually present on disk; nothing is
    assumed.  ``PROVENANCE.json`` is written by ``scripts/setup_ascon.py`` and
    records the upstream URL and the exact commit that was fetched.
    """
    info: dict[str, object] = {
        "variant": ASCON_VARIANT,
        "standard": "NIST SP 800-232",
    }
    try:
        module = load_ascon_module()
        info["module_file"] = str(getattr(module, "__file__", "unknown"))
        info["available"] = True
        info["source_sha256"] = _sha256(Path(str(getattr(module, "__file__", ""))))
    except AsconUnavailableError as exc:
        info["available"] = False
        info["error"] = str(exc).splitlines()[0]

    if PROVENANCE_JSON.is_file():
        try:
            info["provenance"] = json.loads(PROVENANCE_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - corrupt file
            info["provenance"] = "PROVENANCE.json present but unreadable"
    else:
        info["provenance"] = "not recorded (scripts/setup_ascon.py not run)"
    return info
