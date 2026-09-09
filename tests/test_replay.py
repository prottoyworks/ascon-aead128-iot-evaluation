"""Tests for freshness policies -- the defence AEAD does not provide."""

from __future__ import annotations

import pytest

from src.replay_protection import (
    ReplayVerdict,
    SlidingWindowValidator,
    StrictSequenceValidator,
)

VALIDATORS = [
    pytest.param(StrictSequenceValidator, id="strict"),
    pytest.param(SlidingWindowValidator, id="sliding-window"),
]


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_first_message_from_a_device_is_accepted(validator_cls):
    validator = validator_cls()
    assert validator.validate_and_commit("WH-001", 1).accepted


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_increasing_sequence_numbers_are_accepted(validator_cls):
    validator = validator_cls()
    for sequence in range(1, 200):
        decision = validator.validate_and_commit("WH-001", sequence)
        assert decision.accepted, f"Rejected sequence {sequence}: {decision.reason}"


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_exact_duplicate_is_rejected_as_replay(validator_cls):
    """The scenario from the project brief: 101, 102, then 102 again."""
    validator = validator_cls()
    assert validator.validate_and_commit("WH-001", 101).accepted
    assert validator.validate_and_commit("WH-001", 102).accepted

    decision = validator.validate_and_commit("WH-001", 102)
    assert not decision.accepted
    assert decision.verdict is ReplayVerdict.REPLAY


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_repeated_replays_stay_rejected(validator_cls):
    validator = validator_cls()
    validator.validate_and_commit("WH-001", 10)
    for _ in range(20):
        assert not validator.validate_and_commit("WH-001", 10).accepted


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_devices_have_independent_counters(validator_cls):
    """One device's traffic must not affect another's."""
    validator = validator_cls()
    assert validator.validate_and_commit("WH-001", 500).accepted
    assert validator.validate_and_commit("WH-002", 1).accepted
    assert validator.validate_and_commit("WH-002", 2).accepted
    assert validator.last_accepted("WH-001") == 500
    assert validator.last_accepted("WH-002") == 2


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_malformed_sequence_numbers_are_rejected(validator_cls):
    validator = validator_cls()
    for bad in (-1, "5", None, 3.5, True):
        decision = validator.check("WH-001", bad)  # type: ignore[arg-type]
        assert not decision.accepted, f"Accepted malformed sequence {bad!r}"


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_check_does_not_mutate_state(validator_cls):
    """`check` must be side-effect free so it is safe on unverified data."""
    validator = validator_cls()
    validator.validate_and_commit("WH-001", 5)
    for _ in range(10):
        validator.check("WH-001", 9999)
    assert validator.last_accepted("WH-001") == 5


@pytest.mark.parametrize("validator_cls", VALIDATORS)
def test_forged_high_sequence_cannot_lock_out_a_device(validator_cls):
    """The denial-of-service the two-phase design exists to prevent.

    An attacker sends a forged packet claiming sequence 2**31.  Because the
    receiver never commits on unverified data, the genuine device's next
    message is still accepted.
    """
    validator = validator_cls()
    validator.validate_and_commit("WH-001", 100)
    validator.check("WH-001", 2**31)  # forged: checked, never committed
    assert validator.validate_and_commit("WH-001", 101).accepted


# -- strict-policy specifics ------------------------------------------------

def test_strict_rejects_any_older_sequence():
    validator = StrictSequenceValidator()
    validator.validate_and_commit("WH-001", 101)
    validator.validate_and_commit("WH-001", 102)
    decision = validator.check("WH-001", 100)
    assert decision.verdict is ReplayVerdict.STALE


def test_strict_rejects_out_of_order_delivery():
    """Documents the strict policy's cost: legitimate reordering is dropped."""
    validator = StrictSequenceValidator()
    validator.validate_and_commit("WH-001", 10)
    validator.validate_and_commit("WH-001", 12)
    assert not validator.check("WH-001", 11).accepted


def test_strict_tolerates_gaps_from_lost_packets():
    validator = StrictSequenceValidator()
    validator.validate_and_commit("WH-001", 1)
    assert validator.validate_and_commit("WH-001", 1000).accepted


# -- sliding-window specifics ----------------------------------------------

def test_window_accepts_reordered_arrivals():
    """The reason a real deployment needs a window rather than strict order."""
    validator = SlidingWindowValidator(window_size=64)
    validator.validate_and_commit("WH-001", 10)
    validator.validate_and_commit("WH-001", 12)
    assert validator.validate_and_commit("WH-001", 11).accepted


def test_window_still_rejects_a_duplicate_inside_the_window():
    validator = SlidingWindowValidator(window_size=64)
    validator.validate_and_commit("WH-001", 10)
    validator.validate_and_commit("WH-001", 12)
    validator.validate_and_commit("WH-001", 11)
    assert not validator.validate_and_commit("WH-001", 11).accepted


def test_window_rejects_anything_older_than_the_window():
    validator = SlidingWindowValidator(window_size=8)
    validator.validate_and_commit("WH-001", 100)
    decision = validator.check("WH-001", 50)
    assert decision.verdict is ReplayVerdict.STALE


def test_window_slides_forward_correctly():
    validator = SlidingWindowValidator(window_size=8)
    for sequence in (1, 2, 3, 20):
        assert validator.validate_and_commit("WH-001", sequence).accepted
    # 3 is now far outside the window; it must be stale, not accepted.
    assert not validator.check("WH-001", 3).accepted
    assert validator.validate_and_commit("WH-001", 19).accepted


def test_window_size_must_be_positive():
    with pytest.raises(ValueError):
        SlidingWindowValidator(window_size=0)


def test_window_bitmap_does_not_grow_without_bound():
    """A naive implementation leaks memory as sequence numbers climb."""
    validator = SlidingWindowValidator(window_size=32)
    for sequence in range(1, 5000):
        validator.validate_and_commit("WH-001", sequence)
    assert validator._bitmap["WH-001"].bit_length() <= 32
