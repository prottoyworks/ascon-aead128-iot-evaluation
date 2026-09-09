"""AES-128-CCM -- the AEAD that constrained IoT networks actually deploy.

Why this algorithm is in the comparison
---------------------------------------
The other four additions are NIST-LWC finalists: algorithms that competed with
Ascon and lost.  AES-128-CCM is the opposite kind of comparison point -- it is
what IoT devices are running *today*.  CCM is mandated or recommended in
IEEE 802.15.4 (and therefore Zigbee and Thread), in Bluetooth Low Energy, and
in the DTLS/TLS cipher suites written for constrained devices.  If Ascon is to
replace anything in a real warehouse deployment, this is what it replaces.

Parameters: 128-bit key, 96-bit nonce (L = 3), 128-bit tag.

Why CCM costs roughly twice what GCM costs
------------------------------------------
CCM is a *two-pass* mode: it computes a CBC-MAC over the associated data and
plaintext, then encrypts in CTR mode.  Every byte is therefore processed by the
block cipher twice.  GCM authenticates with GHASH, a carry-less multiplication
that is far cheaper than a second AES pass (and on modern x86 has its own
instruction).  Expect CCM to be about 2x GCM in the same tier -- and note that
this is exactly the cost that a sponge like Ascon avoids by producing
ciphertext and tag from a single pass over the data.

Implementation tier
-------------------
Deliberately implemented on the project's pure-Python AES core
(``_aes_core.py``) rather than on OpenSSL, so that its measurement sits on the
same axis as Ascon and the finalists.  See that module for the security
warning that applies.

Standard: NIST SP 800-38C / RFC 3610.
"""

from __future__ import annotations

import hmac

from ..aead_interface import AeadCipher, AuthenticationError
from ._aes_core import _encrypt_block, _key_expansion

_TAG_LEN = 16
_NONCE_LEN = 12          # L = 15 - 12 = 3, so messages up to 2^24 - 1 bytes


def _b0(nonce: bytes, aad_len: int, msg_len: int) -> bytes:
    """Build CCM's first CBC-MAC block: flags || nonce || length."""
    l_param = 15 - len(nonce)                       # bytes used for the length
    flags = (0x40 if aad_len else 0x00) | (((_TAG_LEN - 2) // 2) << 3) | (l_param - 1)
    return bytes([flags]) + nonce + msg_len.to_bytes(l_param, "big")


def _encode_aad_length(aad_len: int) -> bytes:
    """CCM's length prefix for the associated data."""
    if aad_len < 0xFF00:
        return aad_len.to_bytes(2, "big")
    if aad_len <= 0xFFFFFFFF:
        return b"\xff\xfe" + aad_len.to_bytes(4, "big")
    return b"\xff\xff" + aad_len.to_bytes(8, "big")


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return data if remainder == 0 else data + bytes(16 - remainder)


def _cbc_mac(schedule, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """CBC-MAC over B0 || encoded-AAD || plaintext, all zero-padded to 16 bytes."""
    blocks = _b0(nonce, len(aad), len(plaintext))
    if aad:
        blocks += _pad16(_encode_aad_length(len(aad)) + aad)
    blocks += _pad16(plaintext)
    x = bytes(16)
    for offset in range(0, len(blocks), 16):
        chunk = blocks[offset:offset + 16]
        x = _encrypt_block(schedule, bytes(a ^ b for a, b in zip(x, chunk)))
    return x


def _ctr_block(nonce: bytes, counter: int) -> bytes:
    """CCM counter block A_i: flags || nonce || counter."""
    l_param = 15 - len(nonce)
    return bytes([l_param - 1]) + nonce + counter.to_bytes(l_param, "big")


def _ctr_keystream(schedule, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 1
    while len(out) < nbytes:
        out += _encrypt_block(schedule, _ctr_block(nonce, counter))
        counter += 1
    return bytes(out[:nbytes])


class AesCcmPythonCipher(AeadCipher):
    """AES-128-CCM behind the project's common AEAD interface."""

    name = "AES-128-CCM"
    key_size = 16
    nonce_size = _NONCE_LEN
    tag_size = _TAG_LEN

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(
                f"AES-128-CCM requires a {self.key_size}-byte key, got {len(key)}."
            )
        # Key expansion happens once per session, exactly as in the AES-GCM
        # baseline, so the two are treated identically by the harness.
        self._schedule = _key_expansion(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"AES-128-CCM expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        mac = _cbc_mac(self._schedule, nonce, aad, plaintext)
        s0 = _encrypt_block(self._schedule, _ctr_block(nonce, 0))
        tag = bytes(a ^ b for a, b in zip(mac, s0))
        keystream = _ctr_keystream(self._schedule, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"AES-128-CCM expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        body, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        keystream = _ctr_keystream(self._schedule, nonce, len(body))
        plaintext = bytes(a ^ b for a, b in zip(body, keystream))
        mac = _cbc_mac(self._schedule, nonce, aad, plaintext)
        s0 = _encrypt_block(self._schedule, _ctr_block(nonce, 0))
        expected = bytes(a ^ b for a, b in zip(mac, s0))
        if not hmac.compare_digest(expected, tag):
            # The plaintext was recovered before the tag could be checked --
            # CCM's structure requires it -- so it must be discarded here and
            # never returned. This is the classic "release of unverified
            # plaintext" trap and the reason this branch exists.
            raise AuthenticationError("AES-128-CCM authentication failed.")
        return plaintext

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<AesCcmPythonCipher {self.name}>"
