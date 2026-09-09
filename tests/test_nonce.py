"""Tests for nonce management: budgets, reuse detection and birthday bounds."""

from __future__ import annotations

import pytest

from src.nonce import (
    DEFAULT_MESSAGE_BUDGET,
    NonceBudget,
    NonceBudgetExhausted,
    NonceReuseDetector,
    NonceReuseError,
    NonceSource,
    collision_probability,
)


def test_source_issues_nonces_of_the_requested_length():
    source = NonceSource(nonce_size=12)
    assert all(len(source.issue()) == 12 for _ in range(100))


def test_issued_nonces_are_unique_in_practice():
    source = NonceSource(nonce_size=12, detector=NonceReuseDetector())
    nonces = {source.issue() for _ in range(10_000)}
    assert len(nonces) == 10_000


def test_budget_blocks_further_nonces_when_exhausted():
    source = NonceSource(nonce_size=12, budget=NonceBudget(limit=3))
    for _ in range(3):
        source.issue()
    with pytest.raises(NonceBudgetExhausted, match="Rekey"):
        source.issue()


def test_budget_reports_remaining_capacity():
    budget = NonceBudget(limit=10)
    budget.consume(4)
    assert budget.remaining == 6


def test_default_budget_matches_the_documented_rekey_point():
    assert DEFAULT_MESSAGE_BUDGET == 2**32


def test_detector_raises_on_a_repeated_nonce():
    detector = NonceReuseDetector()
    detector.check(b"\x00" * 12)
    with pytest.raises(NonceReuseError):
        detector.check(b"\x00" * 12)


def test_detector_error_does_not_leak_the_nonce_value():
    detector = NonceReuseDetector()
    detector.check(b"\xde\xad\xbe\xef" * 3)
    with pytest.raises(NonceReuseError) as info:
        detector.check(b"\xde\xad\xbe\xef" * 3)
    assert "deadbeef" not in str(info.value).lower()


def test_detector_saturates_instead_of_growing_without_bound():
    """Memory safety: a long run must not exhaust RAM tracking nonces."""
    detector = NonceReuseDetector(max_tracked=100)
    for index in range(500):
        detector.check(index.to_bytes(12, "big"))
    assert detector.saturated
    assert detector.tracked <= 100


def test_saturated_detector_stops_claiming_to_check():
    """It must go quiet, not report false safety by raising nothing forever."""
    detector = NonceReuseDetector(max_tracked=2)
    detector.check(b"a" * 12)
    detector.check(b"b" * 12)
    assert detector.saturated
    # Below saturation this repeat would raise; the caller is told via
    # `saturated` that checking has stopped.
    detector.check(b"a" * 12)


def test_detector_reset_clears_state():
    detector = NonceReuseDetector()
    detector.check(b"x" * 12)
    detector.reset()
    detector.check(b"x" * 12)  # must not raise


def test_collision_probability_is_lower_for_the_longer_nonce():
    """Quantifies a real difference between the two schemes."""
    messages = 2**32
    aes = collision_probability(96, messages)
    ascon = collision_probability(128, messages)
    assert ascon < aes


def test_collision_probability_matches_the_birthday_approximation():
    # q = 2^32, n = 96  ->  q^2 / 2^(n+1) = 2^64 / 2^97 = 2^-33
    assert collision_probability(96, 2**32) == pytest.approx(2.0**-33)
    # q = 2^32, n = 128 ->  2^64 / 2^129 = 2^-65
    assert collision_probability(128, 2**32) == pytest.approx(2.0**-65)


def test_collision_probability_is_zero_for_trivial_message_counts():
    assert collision_probability(96, 0) == 0.0
    assert collision_probability(96, 1) == 0.0


def test_collision_probability_grows_with_message_count():
    values = [collision_probability(96, 2**k) for k in range(10, 40)]
    assert values == sorted(values)


def test_source_rejects_a_nonsensical_nonce_size():
    with pytest.raises(ValueError):
        NonceSource(nonce_size=0)
