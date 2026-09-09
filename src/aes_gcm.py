"""AES-128-GCM baseline, via the `cryptography` library (OpenSSL backend).

AES-GCM is the incumbent authenticated-encryption scheme for internet
protocols (TLS 1.3, IPsec, QUIC) and is specified in NIST SP 800-38D.  It is
used here as the well-established comparison baseline, not as a "competitor"
that must win or lose.

Design decisions worth defending in a viva
------------------------------------------
*Nonce length is 96 bits.*  GCM accepts nonces of any length, but any length
other than 96 bits is passed through GHASH first, which costs time and, more
importantly, destroys the injectivity that makes collision analysis simple.
NIST SP 800-38D explicitly recommends 96-bit nonces.

*Nonces are random, not counters.*  A counter is the safest construction for a
single sender, but this project models many independent devices; a random
96-bit nonce avoids any need for cross-device counter coordination.  The cost
is a birthday bound: after 2^32 messages under one key the collision
probability is roughly 2^-33, which is why ``src/nonce.py`` enforces a
rekeying budget rather than leaving it implicit.

*The cipher object is constructed once and reused.*  ``AESGCM(key)`` performs
key expansion.  A real IoT device establishes a session key and then sends
many messages under it, so reuse is the faithful model.  Key-setup cost is
still measured, but as a *separate* metric (``OP_KEYGEN``) so that it is never
silently folded into per-message latency.

*Every verification failure raises one exception type.*  The library raises
``InvalidTag``; it is translated to this project's ``AuthenticationError`` so
that a caller cannot distinguish a wrong key from a tampered tag.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .aead_interface import AeadCipher, AuthenticationError
from .config import ALG_AES_GCM


class AesGcmCipher(AeadCipher):
    """AES-128-GCM wrapped in the project's common AEAD interface."""

    name = ALG_AES_GCM
    key_size = 16   # 128-bit key
    nonce_size = 12  # 96-bit nonce, per NIST SP 800-38D recommendation
    tag_size = 16   # 128-bit authentication tag (GCM default, full length)

    def __init__(self, key: bytes) -> None:
        """Bind a key and perform key expansion once.

        Args:
            key: Exactly 16 bytes.

        Raises:
            ValueError: if the key is not 128 bits.
        """
        if len(key) != self.key_size:
            raise ValueError(
                f"AES-128-GCM requires a {self.key_size}-byte key, got {len(key)}."
            )
        # Store the AESGCM object, not the raw key, so the secret is not held
        # as an attribute that could end up in a repr or a traceback.
        self._aesgcm = AESGCM(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"AES-128-GCM expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        return self._aesgcm.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"AES-128-GCM expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        # A ciphertext shorter than the tag cannot possibly be valid; the
        # library would raise InvalidTag anyway, but rejecting here keeps the
        # failure inside our own exception type.
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            # Deliberately opaque: no detail about which check failed.
            raise AuthenticationError("AES-128-GCM authentication failed.") from exc

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<AesGcmCipher {self.name}>"


def new_cipher(key: bytes | None = None) -> AesGcmCipher:
    """Convenience factory: build a cipher, generating a key if none is given."""
    return AesGcmCipher(key if key is not None else AesGcmCipher.generate_key())
