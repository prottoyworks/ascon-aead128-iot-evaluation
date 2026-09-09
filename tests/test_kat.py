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
from src.kat import KatFileMissing, parse_kat_file, run_kat, write_kat_report
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
