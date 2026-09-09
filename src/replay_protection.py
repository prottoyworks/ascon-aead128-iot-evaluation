"""Application-layer replay protection.

The point this module exists to make
------------------------------------
AEAD does **not** prevent replay attacks, and a student who claims otherwise
will be corrected in a viva.  AEAD guarantees that a message was produced by a
holder of the key and has not been altered.  A replayed message satisfies both
conditions perfectly -- it *was* produced by the legitimate sender, and it has
*not* been altered.  Its authentication tag verifies flawlessly.

Freshness is therefore not a property of the cipher; it is a property of the
protocol wrapped around the cipher.  Concretely, in a warehouse: an attacker
who captures a valid "temperature = 21 C" packet can rebroadcast it during a
fire.  Every cryptographic check passes and the monitoring system sees a
normal reading.  Nothing in AES-GCM or Ascon prevents this.

The defence used here is a monotonic sequence number carried in the
*authenticated* associated data.  Because it is covered by the tag an attacker
cannot renumber a captured packet; because the receiver remembers the highest
value it has accepted per device, an exact rebroadcast is recognised as stale.

Two policies are provided
-------------------------
:class:`StrictSequenceValidator` accepts only strictly increasing sequence
numbers.  Simple, exact, and correct when the transport preserves order.

:class:`SlidingWindowValidator` implements the IPsec / DTLS style window
(RFC 4303 §3.4.3, RFC 6347): it accepts out-of-order arrivals within a window
of recent values while still rejecting duplicates.  Real IoT transports such
as UDP-based CoAP reorder packets, and a strict validator would discard
legitimate data.  The strict policy is the project default because the
simulated channel is ordered; the window is provided, tested, and discussed so
the report can state what a real deployment needs.

What neither policy handles is discussed in the limitations chapter: neither
survives a receiver reboot without persistent state, and neither bounds how
*old* an accepted message may be -- that needs a timestamp or a challenge.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum


class ReplayVerdict(str, Enum):
    """Outcome of a freshness check."""

    ACCEPT = "ACCEPT"
    REPLAY = "REPLAY"          #: exact duplicate of something already accepted
    STALE = "STALE"            #: older than the receiver is willing to accept
    MALFORMED = "MALFORMED"    #: sequence number absent or not a valid integer

    @property
    def accepted(self) -> bool:
        return self is ReplayVerdict.ACCEPT


@dataclass(frozen=True)
class ReplayDecision:
    """A verdict plus a human-readable reason, for logging and CSV output."""

    verdict: ReplayVerdict
    reason: str

    @property
    def accepted(self) -> bool:
        return self.verdict.accepted


class ReplayValidator(abc.ABC):
    """Base class for per-device freshness policies.

    The two-phase API is the important part.  ``check`` is side-effect free and
    may be called on *unauthenticated* data as a cheap pre-filter.  ``commit``
    mutates the stored state and must be called only after the AEAD tag has
    verified.  Splitting them prevents a forged packet with sequence number
    2^31 from poisoning the counter and locking out the genuine device -- a
    trivial denial-of-service that a single-phase design would allow.
    """

    @abc.abstractmethod
    def check(self, device_id: str, sequence: int) -> ReplayDecision:
        """Evaluate freshness without changing any state."""

    @abc.abstractmethod
    def commit(self, device_id: str, sequence: int) -> None:
        """Record an accepted sequence number.  Call only after verification."""

    @abc.abstractmethod
    def last_accepted(self, device_id: str) -> int | None:
        """Highest sequence number committed for a device, if any."""

    def validate_and_commit(self, device_id: str, sequence: int) -> ReplayDecision:
        """Convenience for tests: check, and commit if accepted.

        Production code must not use this on unauthenticated input.
        """
        decision = self.check(device_id, sequence)
        if decision.accepted:
            self.commit(device_id, sequence)
        return decision


@dataclass
class StrictSequenceValidator(ReplayValidator):
    """Accept a sequence number only if it exceeds the last accepted one."""

    _highest: dict[str, int] = field(default_factory=dict)

    def check(self, device_id: str, sequence: int) -> ReplayDecision:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            return ReplayDecision(
                ReplayVerdict.MALFORMED, "Sequence number is not a non-negative integer."
            )
        previous = self._highest.get(device_id)
        if previous is None:
            return ReplayDecision(
                ReplayVerdict.ACCEPT, f"First message seen from {device_id}."
            )
        if sequence == previous:
            return ReplayDecision(
                ReplayVerdict.REPLAY,
                f"Sequence {sequence} already accepted from {device_id}.",
            )
        if sequence < previous:
            return ReplayDecision(
                ReplayVerdict.STALE,
                f"Sequence {sequence} is below the last accepted value {previous}.",
            )
        return ReplayDecision(
            ReplayVerdict.ACCEPT, f"Sequence {sequence} advances past {previous}."
        )

    def commit(self, device_id: str, sequence: int) -> None:
        current = self._highest.get(device_id)
        if current is None or sequence > current:
            self._highest[device_id] = sequence

    def last_accepted(self, device_id: str) -> int | None:
        return self._highest.get(device_id)


@dataclass
class SlidingWindowValidator(ReplayValidator):
    """Anti-replay window in the style of RFC 4303 / RFC 6347.

    Accepts any sequence number above the current high-water mark, and any
    value within ``window_size`` below it that has not already been seen.

    Attributes:
        window_size: How far below the high-water mark reordering is tolerated.
    """

    window_size: int = 64
    _highest: dict[str, int] = field(default_factory=dict)
    #: Per device, a bitmap of which recent sequence numbers have been seen.
    #: Bit i corresponds to (highest - i).
    _bitmap: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.window_size < 1:
            raise ValueError("window_size must be at least 1.")

    def check(self, device_id: str, sequence: int) -> ReplayDecision:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            return ReplayDecision(
                ReplayVerdict.MALFORMED, "Sequence number is not a non-negative integer."
            )
        highest = self._highest.get(device_id)
        if highest is None:
            return ReplayDecision(
                ReplayVerdict.ACCEPT, f"First message seen from {device_id}."
            )
        if sequence > highest:
            return ReplayDecision(
                ReplayVerdict.ACCEPT, f"Sequence {sequence} advances past {highest}."
            )
        offset = highest - sequence
        if offset >= self.window_size:
            return ReplayDecision(
                ReplayVerdict.STALE,
                f"Sequence {sequence} falls outside the {self.window_size}-wide window.",
            )
        if self._bitmap.get(device_id, 0) & (1 << offset):
            return ReplayDecision(
                ReplayVerdict.REPLAY,
                f"Sequence {sequence} already accepted from {device_id}.",
            )
        return ReplayDecision(
            ReplayVerdict.ACCEPT,
            f"Sequence {sequence} is a fresh out-of-order arrival within the window.",
        )

    def commit(self, device_id: str, sequence: int) -> None:
        highest = self._highest.get(device_id)
        bitmap = self._bitmap.get(device_id, 0)
        if highest is None:
            self._highest[device_id] = sequence
            self._bitmap[device_id] = 1
            return
        if sequence > highest:
            shift = sequence - highest
            # Shift the window forward, then mark the new high-water mark.
            bitmap = ((bitmap << shift) | 1) if shift < self.window_size else 1
            # Keep only window_size bits so the integer cannot grow unboundedly.
            bitmap &= (1 << self.window_size) - 1
            self._highest[device_id] = sequence
            self._bitmap[device_id] = bitmap
        else:
            offset = highest - sequence
            if offset < self.window_size:
                self._bitmap[device_id] = bitmap | (1 << offset)

    def last_accepted(self, device_id: str) -> int | None:
        return self._highest.get(device_id)
