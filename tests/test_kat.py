"""Conformance tests against the official NIST SP 800-232 Ascon-AEAD128 vectors.

This is the most important test file in the project.  Every other Ascon test
proves the implementation is self-consistent; only this one proves it is the
*standardised algorithm*.

If these tests fail, no performance result in the project is meaningful,
because the thing being measured would not be Ascon-AEAD128.
"""

from __future__ import annotations

import pytest

from src.config import ASCON_KAT_FILE
from src.kat import (
    KatFileMissing,
    parse_kat_file,
    run_all_conformance,
    run_kat,
    write_conformance_table,
    write_kat_report,
)
from tests.conftest import requires_ascon

pytestmark = [
    requires_ascon,
    pytest.mark.skipif(
        not ASCON_KAT_FILE.is_file(),
        reason=(
            "Official KAT vectors not fetched. "
            "Run: python scripts/setup_ascon.py"
        ),
    ),
    pytest.mark.conformance,
]


@pytest.fixture(scope="module")
def vectors():
    return parse_kat_file()


def test_kat_file_parses_and_is_not_empty(vectors):
    assert len(vectors) > 0


def test_every_vector_has_standard_parameter_sizes(vectors):
    """Ascon-AEAD128 fixes the key and nonce at 128 bits each."""
    for vector in vectors:
        assert len(vector.key) == 16, f"Count={vector.count}"
        assert len(vector.nonce) == 16, f"Count={vector.count}"
        # Ciphertext is plaintext plus a 128-bit tag.
        assert len(vector.ciphertext) == len(vector.plaintext) + 16, f"Count={vector.count}"


def test_vectors_cover_empty_and_multi_block_inputs(vectors):
    """A KAT set that only tested one length would prove very little."""
    plaintext_lengths = {len(v.plaintext) for v in vectors}
    aad_lengths = {len(v.associated_data) for v in vectors}
    assert 0 in plaintext_lengths, "No empty-plaintext vector"
    assert 0 in aad_lengths, "No empty-AAD vector"
    assert max(plaintext_lengths) >= 16, "No multi-block plaintext vector"
    assert max(aad_lengths) >= 16, "No multi-block AAD vector"


def test_all_vectors_encrypt_to_the_published_ciphertext():
    """The conformance assertion itself."""
    report = run_kat()
    assert report.encrypt_matches == report.total, (
        f"{report.total - report.encrypt_matches} of {report.total} vectors "
        f"produced the wrong ciphertext. First failures: {report.failures[:10]}. "
        "The vendored implementation does NOT conform to NIST SP 800-232."
    )


def test_all_vectors_decrypt_back_to_the_published_plaintext():
    report = run_kat()
    assert report.decrypt_matches == report.total, (
        f"Decryption failed for vectors {report.failures[:10]}."
    )


def test_report_is_marked_as_passing():
    assert run_kat().passed


def test_report_can_be_written_for_the_results_chapter(tmp_path):
    path = write_kat_report(run_kat(limit=50), tmp_path / "kat_results.csv")
    text = path.read_text(encoding="utf-8")
    assert "Ascon-AEAD128" in text
    assert "NIST SP 800-232" in text
    assert "passed,True" in text


def test_missing_kat_file_raises_an_actionable_error(tmp_path):
    with pytest.raises(KatFileMissing, match="setup_ascon"):
        parse_kat_file(tmp_path / "does_not_exist.txt")


# --------------------------------------------------------------------------
# Conformance across the whole comparison set
#
# The tests above cover Ascon alone, which was correct while the study compared
# two algorithms.  Now that it compares seven, the evidence has to be as wide
# as the claim: four of the five comparators are implementations written for
# this project, and an unvalidated implementation makes every timing number
# measured from it meaningless.
# --------------------------------------------------------------------------

EXPECTED_CONFORMANCE_ALGORITHMS = {
    "Ascon-AEAD128",
    "TinyJAMBU-128",
    "Xoodyak",
    "Schwaemm256-128",
    "GIFT-COFB",
    "AES-128-CCM",
}


@pytest.mark.conformance
def test_conformance_covers_every_implemented_algorithm():
    """AES-128-GCM is excluded on purpose: it is OpenSSL, validated upstream."""
    covered = {result.algorithm for result in run_all_conformance(limit=20)}
    assert covered == EXPECTED_CONFORMANCE_ALGORITHMS


@pytest.mark.conformance
@pytest.mark.slow
def test_every_algorithm_reproduces_its_full_vector_set():
    """The headline claim: 1089 vectors each, encrypt and decrypt, no failures."""
    for result in run_all_conformance():
        assert result.total == 1089, (
            f"{result.algorithm}: expected the full 33x33 grid, got {result.total}"
        )
        assert result.encrypt_matches == result.total, (
            f"{result.algorithm}: encryption mismatches at {result.failures[:10]}"
        )
        assert result.decrypt_matches == result.total, (
            f"{result.algorithm}: decryption mismatches at {result.failures[:10]}"
        )
        assert result.passed


@pytest.mark.conformance
def test_conformance_table_is_one_row_per_algorithm(tmp_path):
    """The table is the artefact a reader cites instead of re-running pytest."""
    results = run_all_conformance(limit=10)
    path = write_conformance_table(results, tmp_path / "kat_results.csv")
    lines = path.read_text(encoding="utf-8").strip().splitlines()

    assert lines[0].startswith("algorithm,standard,method,vector_source")
    assert len(lines) == len(results) + 1
    for algorithm in EXPECTED_CONFORMANCE_ALGORITHMS:
        assert any(line.startswith(f"{algorithm},") for line in lines[1:]), (
            f"{algorithm} is missing from the conformance table"
        )
