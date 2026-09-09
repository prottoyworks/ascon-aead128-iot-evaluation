"""A single abstract AEAD interface implemented by both ciphers.

Why this file exists
--------------------
The benchmark must not advantage one algorithm through the *harness* rather
than through the algorithm itself.  If AES-GCM were called via one code path
and Ascon via another, any difference in Python-level dispatch overhead would
silently contaminate the measurement.

Both ciphers therefore implement the same abstract base class, and the
benchmark holds only an ``AeadCipher`` reference.  The attribute lookup,
method call and argument marshalling are then identical for both algorithms,
and whatever Python interpreter overhead exists is applied equally.

Nomenclature note
-----------------
Both AES-GCM and Ascon-AEAD128 are *AEAD* schemes: a single primitive that
simultaneously provides confidentiality of the plaintext and integrity /
authenticity of both the plaintext and the associated data.  The interface
below therefore returns ciphertext-with-tag as one opaque byte string, which
is how both underlying libraries present it, and refuses to expose a
"decrypt without verifying" operation -- there is deliberately no way for a
caller of this project to obtain unauthenticated plaintext.
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass


class AuthenticationError(Exception):
    """Raised when AEAD tag verification fails.

    This single exception type is raised by both cipher wrappers so that
    calling code cannot accidentally distinguish *why* verification failed.
    Leaking a distinction between "wrong key", "tampered ciphertext" and
    "tampered associated data" would hand an attacker an oracle; every
    failure mode must be reported identically.
    """


@dataclass(frozen=True)
class EncryptionResult:
    """Everything a receiver needs, plus sizes used for overhead analysis."""

    nonce: bytes
    ciphertext: bytes  #: ciphertext || authentication tag
    plaintext_size: int
    aad_size: int

    @property
    def ciphertext_size(self) -> int:
        return len(self.ciphertext)

    @property
    def expansion_bytes(self) -> int:
        """Ciphertext growth over plaintext (i.e. the authentication tag)."""
        return len(self.ciphertext) - self.plaintext_size

    @property
    def wire_overhead_bytes(self) -> int:
        """Total per-message cryptographic overhead actually transmitted.

        The nonce must travel with the message (the receiver cannot derive it),
        so honest communication-overhead accounting includes it alongside the
        tag.  Reporting only the tag would understate AES-GCM by 12 bytes and
        Ascon by 16.
        """
        return self.expansion_bytes + len(self.nonce)


class AeadCipher(abc.ABC):
    """Abstract AEAD cipher with an identical surface for both algorithms."""

    #: Human-readable algorithm identifier used in every results file.
    name: str = "undefined"
    #: Key length in bytes.
    key_size: int = 0
    #: Nonce length in bytes.
    nonce_size: int = 0
    #: Authentication tag length in bytes.
    tag_size: int = 0

    # -- key and nonce material -------------------------------------------

    @classmethod
    def generate_key(cls) -> bytes:
        """Return a fresh key from the operating-system CSPRNG.

        ``os.urandom`` is used rather than the ``random`` module because
        ``random`` is a Mersenne Twister: it is seeded, predictable and
        completely unsuitable for key material.  The project's reproducibility
        seed is deliberately never applied to this function.
        """
        return os.urandom(cls.key_size)

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Return a fresh random nonce from the operating-system CSPRNG."""
        return os.urandom(cls.nonce_size)

    # -- the AEAD operations ----------------------------------------------

    @abc.abstractmethod
    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt and authenticate.

        Args:
            nonce: Unique-per-key nonce of exactly ``nonce_size`` bytes.
            plaintext: Data to be kept confidential and authenticated.
            aad: Associated data -- authenticated but transmitted in clear.

        Returns:
            ``ciphertext || tag``.
        """

    @abc.abstractmethod
    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Verify and decrypt.

        Returns:
            The recovered plaintext.

        Raises:
            AuthenticationError: if the tag does not verify, for any reason.
        """

    # -- convenience -------------------------------------------------------

    def seal(self, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> EncryptionResult:
        """Encrypt with a freshly generated nonce unless one is supplied.

        Passing ``nonce`` explicitly is required only by known-answer tests and
        by the deliberate nonce-reuse demonstration; ordinary application code
        should let this method generate one.
        """
        if nonce is None:
            nonce = self.generate_nonce()
        ciphertext = self.encrypt(nonce, plaintext, aad)
        return EncryptionResult(
            nonce=nonce,
            ciphertext=ciphertext,
            plaintext_size=len(plaintext),
            aad_size=len(aad),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<{type(self).__name__} {self.name}>"
