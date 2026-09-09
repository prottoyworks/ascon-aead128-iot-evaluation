"""Ascon-AEAD128 (NIST SP 800-232) wrapped in the project's AEAD interface.

Which implementation is this?
-----------------------------
The underlying code is the Python reference implementation ``pyascon`` by
Maria Eichlseder (one of Ascon's designers), vendored into
``third_party/pyascon/`` by ``scripts/setup_ascon.py``.  Its conformance to
the standard is not asserted -- it is *tested*, in ``src/kat.py`` and
``tests/test_kat.py``, against the known-answer-test vectors shipped with the
Ascon team's official C reference implementation.  See README.md.

Parameters fixed by NIST SP 800-232 for Ascon-AEAD128
-----------------------------------------------------
==================  ==========================================
Key                 128 bits (16 bytes)
Nonce               128 bits (16 bytes)
Tag                 128 bits (16 bytes)
Rate                128 bits per block
Permutation rounds  12 (initialisation/finalisation), 8 (data)
==================  ==========================================

Note that the nonce is 128 bits, versus 96 for AES-GCM.  This is a genuine
difference between the two schemes and it has two consequences the report
should state explicitly: Ascon carries 4 more bytes of per-message overhead,
and it enjoys a far more comfortable random-nonce birthday bound.

API differences from AES-GCM, and how they are reconciled
---------------------------------------------------------
1. ``pyascon`` is a set of module-level *functions* with no cipher object, so
   there is no key-expansion step to amortise; the key is absorbed on every
   call.  ``AesGcmCipher`` by contrast expands the key once.  This asymmetry
   is real, it favours AES-GCM slightly, and it is reported as a limitation
   rather than hidden.  It is also faithful to how the two are actually used.
2. ``ascon_decrypt`` signals failure by *returning None* rather than raising.
   Returning a sentinel is a dangerous API shape -- a caller who forgets to
   check it proceeds with ``None`` instead of a security failure.  This
   wrapper converts that sentinel into an ``AuthenticationError`` immediately,
   so both ciphers fail in exactly the same, unmissable way.
3. ``pyascon`` takes arguments in the order (key, nonce, aad, data); this
   wrapper reorders them to match the project interface.
"""

from __future__ import annotations

from types import ModuleType

from .aead_interface import AeadCipher, AuthenticationError
from .ascon_loader import ASCON_VARIANT, load_ascon_module
from .config import ALG_ASCON

#: The reference module is loaded once at import time.  Loading it per call
#: would add import machinery to the measured region.
_ascon: ModuleType | None = None


def _module() -> ModuleType:
    """Return the loaded Ascon module, loading it on first use."""
    global _ascon
    if _ascon is None:
        _ascon = load_ascon_module()
    return _ascon


class AsconAead128Cipher(AeadCipher):
    """Ascon-AEAD128 in the project's common AEAD interface."""

    name = ALG_ASCON
    key_size = 16    # 128-bit key
    nonce_size = 16  # 128-bit nonce
    tag_size = 16    # 128-bit tag

    def __init__(self, key: bytes) -> None:
        """Bind a key.

        Args:
            key: Exactly 16 bytes.

        Raises:
            ValueError: if the key is not 128 bits.
            AsconUnavailableError: if no SP 800-232 implementation is present.
        """
        if len(key) != self.key_size:
            raise ValueError(
                f"Ascon-AEAD128 requires a {self.key_size}-byte key, got {len(key)}."
            )
        self._key = key
        # Resolve the module and bind the two functions as instance attributes.
        # Binding here rather than looking them up inside encrypt()/decrypt()
        # removes a module attribute lookup from the timed region, matching the
        # single bound-method lookup that the AES path performs.
        module = _module()
        self._encrypt_fn = module.ascon_encrypt
        self._decrypt_fn = module.ascon_decrypt

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Ascon-AEAD128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        return self._encrypt_fn(self._key, nonce, aad, plaintext, ASCON_VARIANT)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Ascon-AEAD128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        # The reference implementation asserts len(ciphertext) >= 16; a
        # truncated message must be rejected as an authentication failure, not
        # crash the receiver with an AssertionError.
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        plaintext = self._decrypt_fn(self._key, nonce, aad, ciphertext, ASCON_VARIANT)
        if plaintext is None:
            # Convert the sentinel into a hard failure. Same message shape as
            # the AES path: no information about which check failed.
            raise AuthenticationError("Ascon-AEAD128 authentication failed.")
        return plaintext

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<AsconAead128Cipher {self.name}>"


def new_cipher(key: bytes | None = None) -> AsconAead128Cipher:
    """Convenience factory: build a cipher, generating a key if none is given."""
    return AsconAead128Cipher(
        key if key is not None else AsconAead128Cipher.generate_key()
    )


def is_available() -> bool:
    """Return True if a usable SP 800-232 Ascon implementation is installed."""
    try:
        _module()
    except ImportError:
        return False
    return True
