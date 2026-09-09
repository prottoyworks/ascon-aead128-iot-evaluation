"""Known-Answer Test (KAT) conformance checking for Ascon-AEAD128.

What a Known-Answer Test is
---------------------------
A KAT is a fixed table of (input, expected output) triples published alongside
a cryptographic standard.  You feed your implementation the input and require
it to produce the published output *byte for byte*.

Why this matters more than a round-trip test
--------------------------------------------
A round-trip test -- encrypt then decrypt and check you got the original back
-- proves only that the implementation is self-consistent.  An implementation
with the wrong initialisation vector, the wrong number of permutation rounds,
or a byte-order error will still round-trip perfectly with itself, while being
unable to interoperate with any other implementation and, in the worst case,
offering far less security than the standard specifies.  Only a KAT detects
that.  Conformance, not correctness, is the property being tested.

For this project the stakes are specific.  NIST SP 800-232 standardises
Ascon-AEAD128, which differs from the Ascon v1.2 competition candidates
(Ascon-128, Ascon-128a, Ascon-80pq) in its initialisation vector, its rate and
its padding conventions.  An implementation of the *candidate* would look
entirely healthy under round-trip testing while producing ciphertexts that no
SP 800-232 implementation could decrypt.  The KAT is what makes the claim "this
project evaluates the standardised algorithm" verifiable rather than assumed.

Where the vectors come from
---------------------------
``crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt`` in the Ascon team's
official C reference repository, https://github.com/ascon/ascon-c, whose
README states that it implements NIST SP 800-232.  ``scripts/setup_ascon.py``
fetches that file and records the exact commit in
``third_party/PROVENANCE.json``.  No vector values are embedded in this source
file, invented, or transcribed by hand.

File format (NIST Lightweight Cryptography KAT format)::

    Count = 1
    Key = 000102030405060708090A0B0C0D0E0F
    Nonce = 101112131415161718191A1B1C1D1E1F
    PT =
    AD =
    CT = <ciphertext || tag, hex>

What a successful run means
---------------------------
Every vector's ``CT`` was reproduced exactly by the vendored Python
implementation, and each ``CT`` decrypted back to its ``PT``.  Since the
vectors were produced by an independent implementation in a different language
by the algorithm's designers, agreement on all of them is strong evidence that
the Python code implements the standardised algorithm.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .aead_interface import AuthenticationError
from .ascon_aead import AsconAead128Cipher
from .config import ASCON_KAT_FILE, KAT_RESULTS_CSV


class KatFileMissing(FileNotFoundError):
    """Raised when the official KAT file has not been fetched."""


@dataclass(frozen=True)
class KatVector:
    """One known-answer test case."""

    count: int
    key: bytes
    nonce: bytes
    plaintext: bytes
    associated_data: bytes
    ciphertext: bytes  #: expected ciphertext || tag


@dataclass(frozen=True)
class KatReport:
    """Aggregate outcome of a KAT run."""

    total: int
    encrypt_matches: int
    decrypt_matches: int
    failures: list[int]
    source_file: str

    @property
    def passed(self) -> bool:
        return (
            self.total > 0
            and self.encrypt_matches == self.total
            and self.decrypt_matches == self.total
        )


def parse_kat_file(path: Path = ASCON_KAT_FILE) -> list[KatVector]:
    """Parse a NIST LWC-format AEAD KAT file.

    Raises:
        KatFileMissing: if the file has not been fetched.
        ValueError: if a record is malformed.
    """
    if not path.is_file():
        raise KatFileMissing(
            f"KAT file not found at {path}.\n"
            "Fetch it with:\n    python scripts/setup_ascon.py\n"
            "It comes from https://github.com/ascon/ascon-c "
            "(crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt)."
        )

    vectors: list[KatVector] = []
    record: dict[str, str] = {}

    def flush() -> None:
        if not record:
            return
        try:
            vectors.append(
                KatVector(
                    count=int(record["Count"]),
                    key=bytes.fromhex(record["Key"]),
                    nonce=bytes.fromhex(record["Nonce"]),
                    plaintext=bytes.fromhex(record.get("PT", "")),
                    associated_data=bytes.fromhex(record.get("AD", "")),
                    ciphertext=bytes.fromhex(record["CT"]),
                )
            )
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Malformed KAT record near Count={record.get('Count')}: {exc}")
        record.clear()

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                flush()
                continue
            key, sep, value = stripped.partition("=")
            if not sep:
                continue  # ignore any comment or banner line
            record[key.strip()] = value.strip()
    flush()

    if not vectors:
        raise ValueError(f"No KAT vectors parsed from {path}.")
    return vectors


def run_kat(path: Path = ASCON_KAT_FILE, limit: int | None = None) -> KatReport:
    """Run every vector through the vendored implementation.

    Args:
        path: KAT file location.
        limit: Optionally cap the number of vectors (used by the quick profile).
    """
    vectors = parse_kat_file(path)
    if limit is not None:
        vectors = vectors[:limit]

    encrypt_matches = 0
    decrypt_matches = 0
    failures: list[int] = []

    for vector in vectors:
        cipher = AsconAead128Cipher(vector.key)
        produced = cipher.encrypt(vector.nonce, vector.plaintext, vector.associated_data)
        if produced == vector.ciphertext:
            encrypt_matches += 1
        else:
            failures.append(vector.count)
            continue
        try:
            recovered = cipher.decrypt(
                vector.nonce, vector.ciphertext, vector.associated_data
            )
        except AuthenticationError:
            failures.append(vector.count)
            continue
        if recovered == vector.plaintext:
            decrypt_matches += 1
        else:
            failures.append(vector.count)

    return KatReport(
        total=len(vectors),
        encrypt_matches=encrypt_matches,
        decrypt_matches=decrypt_matches,
        failures=failures,
        source_file=str(path),
    )


def write_kat_report(report: KatReport, path: Path = KAT_RESULTS_CSV) -> Path:
    """Persist the KAT outcome so it can be cited in the results chapter."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerow(["algorithm", "Ascon-AEAD128"])
        writer.writerow(["standard", "NIST SP 800-232"])
        writer.writerow(["source_file", report.source_file])
        writer.writerow(["vectors_total", report.total])
        writer.writerow(["encrypt_matches", report.encrypt_matches])
        writer.writerow(["decrypt_matches", report.decrypt_matches])
        writer.writerow(["failed_counts", ";".join(str(c) for c in report.failures)])
        writer.writerow(["passed", report.passed])
    return path
