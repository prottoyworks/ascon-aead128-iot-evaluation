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


# ==========================================================================
# Conformance across the whole comparison set
# ==========================================================================
# Everything above this line concerns Ascon-AEAD128 alone, because the core
# study compares two algorithms and only one of them is implemented here (the
# AES-128-GCM path is OpenSSL, already validated by its own project).
#
# The extension adds five more algorithms, four of which are pure-Python
# implementations written for this project.  A timing measurement of an
# implementation that computes the wrong function measures nothing, so each of
# those has to clear the same bar Ascon does: reproduce the published vectors
# of its own specification, byte for byte, before any number it produces is
# quoted.  The code below runs that check for every algorithm and writes one
# table, so the repository carries the evidence instead of requiring a reader
# to install pytest and take the result on trust.
# --------------------------------------------------------------------------

from .config import ALG_AES_CCM, LWC_KAT_DIR  # noqa: E402

#: Algorithm name -> official NIST-LWC vector file in third_party/lwc_kat/.
#:
#: AES-128-CCM is absent on purpose: it was never a NIST-LWC candidate, so no
#: vector file of this form exists for it.  It is validated differently, by
#: :func:`run_openssl_cross_check` below.
LWC_KAT_FILES: dict[str, str] = {
    "TinyJAMBU-128": "TinyJAMBU-128.txt",
    "Xoodyak": "Xoodyak.txt",
    "Schwaemm256-128": "Schwaemm256-128.txt",
    "GIFT-COFB": "GIFT-COFB.txt",
}


@dataclass(frozen=True)
class ConformanceResult:
    """One algorithm's conformance outcome, in a form that tabulates."""

    algorithm: str
    standard: str
    method: str  #: how conformance was established
    vector_source: str
    total: int
    encrypt_matches: int
    decrypt_matches: int
    failures: list[int]

    @property
    def passed(self) -> bool:
        return (
            self.total > 0
            and self.encrypt_matches == self.total
            and self.decrypt_matches == self.total
        )


def run_vector_file(
    cipher_cls, path: Path, algorithm: str, standard: str, limit: int | None = None
) -> ConformanceResult:
    """Drive one cipher through a NIST-LWC format vector file.

    The parser is :func:`parse_kat_file`, unchanged -- all NIST-LWC AEAD vector
    files share one format, which is the reason a single reader serves both the
    Ascon file and the four finalist files.
    """
    vectors = parse_kat_file(path)
    if limit is not None:
        vectors = vectors[:limit]

    encrypt_matches = 0
    decrypt_matches = 0
    failures: list[int] = []

    for vector in vectors:
        cipher = cipher_cls(vector.key)
        produced = cipher.encrypt(vector.nonce, vector.plaintext, vector.associated_data)
        if produced != vector.ciphertext:
            failures.append(vector.count)
            continue
        encrypt_matches += 1
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

    return ConformanceResult(
        algorithm=algorithm,
        standard=standard,
        method="official published test vectors",
        vector_source=str(path),
        total=len(vectors),
        encrypt_matches=encrypt_matches,
        decrypt_matches=decrypt_matches,
        failures=failures,
    )


def run_openssl_cross_check(limit: int | None = None) -> ConformanceResult:
    """Validate the pure-Python AES-128-CCM against OpenSSL.

    AES-128-CCM has no NIST-LWC vector file, so conformance is established the
    other way a cryptographic implementation can be checked: exact agreement
    with an independent, widely deployed implementation of the same standard
    (NIST SP 800-38C, via OpenSSL through ``cryptography``).

    To keep the evidence comparable with the other algorithms, the inputs cover
    the same grid the NIST-LWC files use -- every plaintext length 0-32 against
    every associated-data length 0-32, which is 33 x 33 = 1089 cases -- with
    keys and nonces derived deterministically from the case index so the run is
    reproducible.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    from .lightweight.aes_ccm import AesCcmPythonCipher

    cases = [(pt_len, ad_len) for pt_len in range(33) for ad_len in range(33)]
    if limit is not None:
        cases = cases[:limit]

    encrypt_matches = 0
    decrypt_matches = 0
    failures: list[int] = []

    for index, (pt_len, ad_len) in enumerate(cases, start=1):
        # Deterministic, documented derivation -- no randomness, so the table
        # is byte-identical on every machine and in every run.
        key = bytes((index * 7 + i * 31) % 256 for i in range(AesCcmPythonCipher.key_size))
        nonce = bytes((index * 11 + i * 17) % 256 for i in range(AesCcmPythonCipher.nonce_size))
        plaintext = bytes((i * 3 + 1) % 256 for i in range(pt_len))
        aad = bytes((i * 5 + 2) % 256 for i in range(ad_len))

        expected = AESCCM(key, tag_length=AesCcmPythonCipher.tag_size).encrypt(
            nonce, plaintext, aad or None
        )
        produced = AesCcmPythonCipher(key).encrypt(nonce, plaintext, aad)
        if produced != expected:
            failures.append(index)
            continue
        encrypt_matches += 1
        try:
            recovered = AesCcmPythonCipher(key).decrypt(nonce, expected, aad)
        except AuthenticationError:
            failures.append(index)
            continue
        if recovered == plaintext:
            decrypt_matches += 1
        else:
            failures.append(index)

    return ConformanceResult(
        algorithm=ALG_AES_CCM,
        standard="NIST SP 800-38C",
        method="cross-validation against OpenSSL",
        vector_source="cryptography/OpenSSL AESCCM, 33x33 length grid",
        total=len(cases),
        encrypt_matches=encrypt_matches,
        decrypt_matches=decrypt_matches,
        failures=failures,
    )


def run_all_conformance(limit: int | None = None) -> list[ConformanceResult]:
    """Establish conformance for every algorithm this project implements.

    AES-128-GCM is absent from the table for a reason worth stating: it is not
    implemented here.  It is OpenSSL, reached through ``cryptography``, and its
    conformance is the responsibility -- and the validated claim -- of that
    project rather than of this one.
    """
    from .lightweight import BY_NAME

    results: list[ConformanceResult] = [
        run_vector_file(
            AsconAead128Cipher,
            ASCON_KAT_FILE,
            algorithm="Ascon-AEAD128",
            standard="NIST SP 800-232",
            limit=limit,
        )
    ]
    for algorithm, filename in LWC_KAT_FILES.items():
        results.append(
            run_vector_file(
                BY_NAME[algorithm],
                LWC_KAT_DIR / filename,
                algorithm=algorithm,
                standard="NIST LWC submission",
                limit=limit,
            )
        )
    results.append(run_openssl_cross_check(limit=limit))
    return results


def write_conformance_table(
    results: list[ConformanceResult], path: Path = KAT_RESULTS_CSV
) -> Path:
    """Write one row per algorithm, so the evidence can be cited as a table."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "algorithm", "standard", "method", "vector_source",
            "vectors_total", "encrypt_matches", "decrypt_matches",
            "failed_counts", "passed",
        ])
        for result in results:
            writer.writerow([
                result.algorithm,
                result.standard,
                result.method,
                result.vector_source,
                result.total,
                result.encrypt_matches,
                result.decrypt_matches,
                ";".join(str(c) for c in result.failures),
                result.passed,
            ])
    return path
