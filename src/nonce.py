"""Nonce management, and why it is the sharpest edge in AEAD deployment.

Both AES-GCM and Ascon-AEAD128 are *nonce-respecting* schemes: their security
proofs hold only while no (key, nonce) pair is ever used to encrypt twice.
Violating that is not a graceful degradation.

For AES-GCM the consequence is catastrophic and well documented.  GCM is
counter mode plus a GHASH authenticator; reusing a nonce under one key emits
the same keystream twice, so XORing the two ciphertexts cancels the keystream
and leaks the XOR of the two plaintexts.  Worse, the collision also allows an
adversary to solve for the GHASH subkey H, which breaks *authentication* for
every message under that key from then on -- a "forbidden attack" (Joux; and
see Böck, Zauner, Devlin, Somorovsky & Jovanovic, "Nonce-Disrespecting
Adversaries", USENIX WOOT 2016).  [VERIFY CITATION for exact page/DOI.]

Ascon's mode also requires unique nonces; reuse likewise leaks plaintext
relationships. Neither algorithm is misuse-resistant in the SIV sense.

Two safe strategies, and the one this project uses
--------------------------------------------------
*Counter nonces* are optimal when a single sender owns the whole nonce space:
zero collision risk until the counter wraps.  They need durable state that
survives a reboot -- an IoT device that resets its counter after a power cycle
reuses nonces immediately, which is a real and common field failure.

*Random nonces* need no state and no coordination between devices, which suits
a fleet of independent nodes.  The cost is a birthday bound: with an n-bit
nonce, after q messages the probability that some pair collides is about
q^2 / 2^(n+1).

    AES-GCM, n = 96:   q = 2^32 messages  ->  ~2^-33 collision probability
    Ascon,   n = 128:  q = 2^32 messages  ->  ~2^-65 collision probability

This project uses random nonces from ``os.urandom`` and makes the budget
*explicit* rather than implicit: :class:`NonceBudget` refuses to issue nonces
past a configured message count, forcing a rekey.  Making the limit a runtime
object rather than a comment is the difference between a documented assumption
and an enforced one.

:class:`NonceReuseDetector` is a defensive test aid.  It records issued nonces
and raises if one repeats.  It is not a production mechanism -- it is memory
bounded and single-process -- but it turns "we believe nonces are unique" into
a testable assertion, which is what an examiner will ask for.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class NonceReuseError(RuntimeError):
    """Raised when the same nonce is issued twice under one key."""


class NonceBudgetExhausted(RuntimeError):
    """Raised when the safe message count for a key has been reached."""


#: Conservative default: rekey after 2^32 messages under one key.  At this
#: point AES-GCM's random-nonce collision probability is about 2^-33.
DEFAULT_MESSAGE_BUDGET: int = 2**32


@dataclass
class NonceBudget:
    """Track how many messages have been sent under one key.

    Attributes:
        limit: Maximum messages permitted before a rekey is required.
        used: Messages issued so far.
    """

    limit: int = DEFAULT_MESSAGE_BUDGET
    used: int = 0

    def consume(self, count: int = 1) -> None:
        """Account for `count` messages.

        Raises:
            NonceBudgetExhausted: if the budget would be exceeded.
        """
        if self.used + count > self.limit:
            raise NonceBudgetExhausted(
                f"Key has encrypted {self.used} messages; limit is {self.limit}. "
                "Rekey before sending more."
            )
        self.used += count

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


@dataclass
class NonceReuseDetector:
    """In-process guard that detects a repeated nonce under one key.

    Attributes:
        max_tracked: Upper bound on remembered nonces, so a long benchmark run
            cannot exhaust memory.  Once exceeded the detector stops recording
            and sets ``saturated``; it never silently claims safety it has not
            checked.
    """

    max_tracked: int = 1_000_000
    _seen: set[bytes] = field(default_factory=set, repr=False)
    saturated: bool = False

    def check(self, nonce: bytes) -> None:
        """Record a nonce, raising if it has been seen before.

        Raises:
            NonceReuseError: on a repeat.
        """
        if self.saturated:
            return
        if nonce in self._seen:
            raise NonceReuseError(
                f"Nonce reuse detected after {len(self._seen)} messages "
                "(nonce value withheld from the log)."
            )
        self._seen.add(nonce)
        if len(self._seen) >= self.max_tracked:
            self.saturated = True

    @property
    def tracked(self) -> int:
        return len(self._seen)

    def reset(self) -> None:
        self._seen.clear()
        self.saturated = False


class NonceSource:
    """Issues random nonces for one key, under a budget, with reuse checking.

    This is what application code should hold.  It deliberately offers no way
    to supply a caller-chosen nonce.
    """

    def __init__(
        self,
        nonce_size: int,
        budget: NonceBudget | None = None,
        detector: NonceReuseDetector | None = None,
    ) -> None:
        if nonce_size <= 0:
            raise ValueError("nonce_size must be positive.")
        self.nonce_size = nonce_size
        self.budget = budget if budget is not None else NonceBudget()
        # The detector is optional because tracking every nonce costs memory;
        # it is enabled in tests and in the security suite.
        self.detector = detector

    def issue(self) -> bytes:
        """Return a fresh nonce, or raise if the key's budget is spent."""
        self.budget.consume(1)
        # os.urandom draws from the OS CSPRNG. The project's reproducibility
        # seed is never applied here: a reproducible nonce is a reused nonce.
        nonce = os.urandom(self.nonce_size)
        if self.detector is not None:
            self.detector.check(nonce)
        return nonce


def collision_probability(nonce_bits: int, messages: int) -> float:
    """Approximate birthday-collision probability for random nonces.

    Uses the standard approximation q^2 / 2^(n+1), which is accurate while the
    result is well below 1.

    Args:
        nonce_bits: Nonce length in bits (96 for AES-GCM, 128 for Ascon).
        messages: Number of messages sent under one key.

    Returns:
        Approximate probability that at least one nonce repeats.
    """
    if messages < 2:
        return 0.0
    # Computed in log space; 2^128 overflows a float otherwise.
    exponent = 2 * _log2(messages) - (nonce_bits + 1)
    return 2.0**exponent if exponent < 0 else 1.0


def _log2(value: int) -> float:
    import math

    return math.log2(value)
