"""Simulated gateway receiver: the order in which checks happen matters.

Pipeline
--------
1. **Select cipher** from the packet's algorithm label.  An unknown label is
   rejected outright; the receiver never guesses.
2. **Cheap pre-filter** on the *unauthenticated* sequence number.  This can
   only reject.  It exists so a flood of obviously stale packets can be dropped
   without paying for an AEAD verification each -- a real concern on a gateway
   serving thousands of nodes.
3. **AEAD verification and decryption.**  This is the only step that
   establishes authenticity.  Everything before it operated on attacker-
   controlled data.
4. **Authoritative replay check** on the now-authenticated sequence number,
   followed by ``commit``.  The counter advances only here.
5. **Structural validation** and reconstruction of the reading.

Why step 4 repeats step 2
-------------------------
Because step 2's input was not trustworthy.  A design that pre-filters and then
commits without rechecking lets an attacker send a forged packet claiming
sequence 2^31; if the counter advanced on that, every genuine message from
that device would afterwards be rejected as stale -- a one-packet denial of
service.  Committing only post-verification closes that.

Logging discipline
------------------
No key, nonce, tag or plaintext is ever written to a log or an exception
message.  Failure reasons are deliberately coarse ("authentication failed")
rather than specific ("wrong AAD"), because a receiver that explains *which*
check failed is an oracle an attacker can query.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from .aead_interface import AeadCipher, AuthenticationError
from .aes_gcm import AesGcmCipher
from .ascon_aead import AsconAead128Cipher
from .config import ALG_AES_GCM, ALG_ASCON
from .replay_protection import ReplayValidator, ReplayVerdict, StrictSequenceValidator
from .sensor import SensorReading
from .serialization import SecurePacket, reassemble

logger = logging.getLogger(__name__)

#: Algorithm label -> cipher class.  Adding a third AEAD later (for the thesis)
#: means adding one line here; nothing else in the receiver changes.  That is
#: the seed of the crypto-agility work described in docs/THESIS_EXTENSION.md.
CIPHER_REGISTRY: dict[str, type[AeadCipher]] = {
    ALG_AES_GCM: AesGcmCipher,
    ALG_ASCON: AsconAead128Cipher,
}


class RejectionReason(str, Enum):
    """Coarse, non-oracular failure categories."""

    UNKNOWN_ALGORITHM = "UNKNOWN_ALGORITHM"
    PRE_FILTER_STALE = "PRE_FILTER_STALE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    REPLAY = "REPLAY"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class ReceiveResult:
    """Outcome of processing one packet."""

    accepted: bool
    reading: SensorReading | None = None
    reason: RejectionReason | None = None
    detail: str = ""

    @property
    def status(self) -> str:
        """'ACCEPTED' or 'REJECTED', for CSV output and console display."""
        return "ACCEPTED" if self.accepted else "REJECTED"


class SecureReceiver:
    """A gateway that terminates the secure channel for a fleet of devices.

    Keys are held per (device_id, algorithm).  In a real deployment they would
    come from a key-establishment protocol; here they are provisioned directly,
    which is stated as a limitation.
    """

    def __init__(
        self,
        validator: ReplayValidator | None = None,
        enable_prefilter: bool = True,
    ) -> None:
        self.validator = validator if validator is not None else StrictSequenceValidator()
        self.enable_prefilter = enable_prefilter
        self._ciphers: dict[tuple[str, str], AeadCipher] = {}
        #: Counters for the security report, keyed by rejection reason.
        self.stats: dict[str, int] = {"accepted": 0}

    # -- key provisioning --------------------------------------------------

    def provision(self, device_id: str, algorithm: str, key: bytes) -> None:
        """Install a device key for one algorithm.

        Raises:
            ValueError: if the algorithm is not registered.
        """
        cipher_cls = CIPHER_REGISTRY.get(algorithm)
        if cipher_cls is None:
            raise ValueError(f"Unsupported algorithm: {algorithm!r}")
        self._ciphers[(device_id, algorithm)] = cipher_cls(key)

    def _cipher_for(self, device_id: str, algorithm: str) -> AeadCipher | None:
        return self._ciphers.get((device_id, algorithm))

    # -- packet processing -------------------------------------------------

    def _reject(self, reason: RejectionReason, detail: str) -> ReceiveResult:
        self.stats[reason.value] = self.stats.get(reason.value, 0) + 1
        # Logged at INFO with no secret material and no per-check detail.
        logger.info("Packet rejected: %s", reason.value)
        return ReceiveResult(accepted=False, reason=reason, detail=detail)

    def receive(self, packet: SecurePacket) -> ReceiveResult:
        """Process one packet through the full pipeline."""
        # ---- 1. algorithm selection --------------------------------------
        if packet.algorithm not in CIPHER_REGISTRY:
            return self._reject(
                RejectionReason.UNKNOWN_ALGORITHM,
                f"No cipher registered for {packet.algorithm!r}.",
            )

        peeked = packet.peek_sequence()
        if peeked is None:
            return self._reject(
                RejectionReason.MALFORMED, "Associated data is not well-formed."
            )
        device_id, claimed_sequence = peeked

        cipher = self._cipher_for(device_id, packet.algorithm)
        if cipher is None:
            # Treated as an authentication failure on purpose: telling a
            # stranger "I don't know that device" is itself information.
            return self._reject(
                RejectionReason.AUTHENTICATION_FAILED,
                "No key provisioned for this device and algorithm.",
            )

        # ---- 2. cheap pre-filter on UNAUTHENTICATED data ------------------
        # May only reject. Never commits, never accepts on this basis alone.
        if self.enable_prefilter:
            provisional = self.validator.check(device_id, claimed_sequence)
            if provisional.verdict in (ReplayVerdict.REPLAY, ReplayVerdict.STALE):
                return self._reject(
                    RejectionReason.PRE_FILTER_STALE,
                    "Rejected before verification by the freshness pre-filter.",
                )

        # ---- 3. AEAD verification and decryption -------------------------
        try:
            plaintext = cipher.decrypt(packet.nonce, packet.ciphertext, packet.aad)
        except AuthenticationError:
            return self._reject(
                RejectionReason.AUTHENTICATION_FAILED,
                "AEAD tag verification failed.",
            )
        except ValueError as exc:
            # e.g. a nonce of the wrong length: malformed, not forged.
            return self._reject(RejectionReason.MALFORMED, str(exc))

        # ---- 4. authoritative replay check, then commit ------------------
        # From here on, packet.aad is known-authentic.
        decision = self.validator.check(device_id, claimed_sequence)
        if not decision.accepted:
            return self._reject(RejectionReason.REPLAY, decision.reason)

        # ---- 5. structural validation ------------------------------------
        try:
            reading = reassemble(packet.aad, plaintext)
        except ValueError as exc:
            return self._reject(RejectionReason.MALFORMED, str(exc))

        self.validator.commit(device_id, claimed_sequence)
        self.stats["accepted"] += 1
        return ReceiveResult(accepted=True, reading=reading, detail="Verified and fresh.")


def build_packet(
    cipher: AeadCipher, reading: SensorReading, nonce: bytes | None = None
) -> SecurePacket:
    """Encrypt a reading into a transmittable packet (sender side)."""
    from .serialization import split_reading  # local import avoids a cycle

    aad, plaintext = split_reading(reading)
    result = cipher.seal(plaintext, aad, nonce=nonce)
    return SecurePacket(
        algorithm=cipher.name,
        aad=aad,
        nonce=result.nonce,
        ciphertext=result.ciphertext,
    )
