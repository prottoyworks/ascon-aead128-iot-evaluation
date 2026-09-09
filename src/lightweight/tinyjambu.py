"""TinyJAMBU-128 -- NIST Lightweight Cryptography finalist (v2 parameters).

What it is
----------
TinyJAMBU is the *smallest* of the ten NIST-LWC finalists in hardware: its
entire state is a 128-bit non-linear feedback shift register (NLFSR), with no
S-box table, no key schedule and no round constants.  Where Ascon is a
320-bit sponge, TinyJAMBU is a keyed shift register clocked hundreds of times
per message.  Including it therefore tests a genuinely different design
philosophy rather than a second sponge.

Parameters: 128-bit key, 96-bit nonce, **64-bit tag**, P_640 / P_1024.

The 64-bit tag matters for the report
-------------------------------------
Every other algorithm in this study emits a 128-bit tag.  TinyJAMBU's 64-bit
tag halves its per-message wire overhead -- which looks like a win in the
communication-overhead figure -- but it also reduces online forgery resistance
from 2^-128 to 2^-64 per attempt.  Wherever this algorithm appears in a
ranking, that trade must be stated; it is not a free saving.

Provenance
----------
Pure-Python port written for this project from the public TinyJAMBU v2
specification, validated against all 1089 vectors in
``third_party/lwc_kat/TinyJAMBU-128.txt``.  See ``docs/EXTENDED_ALGORITHMS.md``.
"""

from __future__ import annotations

import hmac

from ..aead_interface import AeadCipher, AuthenticationError

_M32 = 0xFFFFFFFF
_NROUND1 = 640    # 128 * 5, used for nonce and associated-data steps
_NROUND2 = 1024   # 128 * 8, used for key setup, encryption and finalisation

# The 3-bit frame constant lives at state bits 36..38, i.e. bits 4..6 of word 1.
_FRAME_NONCE = 0x10
_FRAME_AD = 0x30
_FRAME_PT = 0x50
_FRAME_FINAL = 0x70


def _state_update(s: list[int], k: list[int], steps: int) -> None:
    """Clock the keyed NLFSR ``steps`` times, 32 steps per loop iteration.

    The feedback bit is
    ``s[0] ^ s[47] ^ ~(s[70] & s[85]) ^ s[91] ^ k[i mod 4]``; because the
    state is held as four 32-bit words, 32 consecutive steps can be computed
    with word-wide shifts instead of one bit at a time.
    """
    s0, s1, s2, s3 = s
    for i in range(steps >> 5):
        t1 = ((s1 >> 15) | (s2 << 17)) & _M32   # bit 47
        t2 = ((s2 >> 6) | (s3 << 26)) & _M32    # bit 70
        t3 = ((s2 >> 21) | (s3 << 11)) & _M32   # bit 85
        t4 = ((s2 >> 27) | (s3 << 5)) & _M32    # bit 91
        feedback = (s0 ^ t1 ^ (~(t2 & t3)) ^ t4 ^ k[i & 3]) & _M32
        s0, s1, s2, s3 = s1, s2, s3, feedback
    s[0], s[1], s[2], s[3] = s0, s1, s2, s3


def _w32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _initialise(key: bytes, nonce: bytes) -> tuple[list[int], list[int]]:
    k = [_w32(key, 4 * i) for i in range(4)]
    s = [0, 0, 0, 0]
    _state_update(s, k, _NROUND2)
    for i in range(3):                      # 96-bit nonce == three 32-bit words
        s[1] ^= _FRAME_NONCE
        _state_update(s, k, _NROUND1)
        s[3] = (s[3] ^ _w32(nonce, 4 * i)) & _M32
    return s, k


def _absorb_associated_data(s: list[int], k: list[int], aad: bytes) -> None:
    full_words = len(aad) // 4
    for i in range(full_words):
        s[1] ^= _FRAME_AD
        _state_update(s, k, _NROUND1)
        s[3] = (s[3] ^ _w32(aad, 4 * i)) & _M32
    remainder = len(aad) & 3
    if remainder:
        s[1] ^= _FRAME_AD
        _state_update(s, k, _NROUND1)
        base = full_words * 4
        for j in range(remainder):
            s[3] ^= aad[base + j] << (8 * j)
        s[3] &= _M32
        s[1] ^= remainder               # length domain separation


def _finalise(s: list[int], k: list[int]) -> bytes:
    s[1] ^= _FRAME_FINAL
    _state_update(s, k, _NROUND2)
    tag = (s[2] & _M32).to_bytes(4, "little")
    s[1] ^= _FRAME_FINAL
    _state_update(s, k, _NROUND1)
    return tag + (s[2] & _M32).to_bytes(4, "little")


class TinyJambu128Cipher(AeadCipher):
    """TinyJAMBU-128 behind the project's common AEAD interface."""

    name = "TinyJAMBU-128"
    key_size = 16
    nonce_size = 12
    tag_size = 8            # 64 bits -- deliberately different from the others

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(
                f"TinyJAMBU-128 requires a {self.key_size}-byte key, got {len(key)}."
            )
        self._key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"TinyJAMBU-128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        s, k = _initialise(self._key, nonce)
        _absorb_associated_data(s, k, aad)
        out = bytearray()
        full_words = len(plaintext) // 4
        for i in range(full_words):
            s[1] ^= _FRAME_PT
            _state_update(s, k, _NROUND2)
            m = _w32(plaintext, 4 * i)
            s[3] = (s[3] ^ m) & _M32
            out += ((s[2] ^ m) & _M32).to_bytes(4, "little")
        remainder = len(plaintext) & 3
        if remainder:
            s[1] ^= _FRAME_PT
            _state_update(s, k, _NROUND2)
            base = full_words * 4
            for j in range(remainder):
                s[3] ^= plaintext[base + j] << (8 * j)
            s[3] &= _M32
            s[1] ^= remainder
            for j in range(remainder):
                out.append(((s[2] >> (8 * j)) & 0xFF) ^ plaintext[base + j])
        return bytes(out) + _finalise(s, k)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"TinyJAMBU-128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        body, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        s, k = _initialise(self._key, nonce)
        _absorb_associated_data(s, k, aad)
        out = bytearray()
        full_words = len(body) // 4
        for i in range(full_words):
            s[1] ^= _FRAME_PT
            _state_update(s, k, _NROUND2)
            c = _w32(body, 4 * i)
            m = (s[2] ^ c) & _M32
            s[3] = (s[3] ^ m) & _M32
            out += m.to_bytes(4, "little")
        remainder = len(body) & 3
        if remainder:
            s[1] ^= _FRAME_PT
            _state_update(s, k, _NROUND2)
            base = full_words * 4
            for j in range(remainder):
                m = ((s[2] >> (8 * j)) & 0xFF) ^ body[base + j]
                out.append(m)
                s[3] ^= m << (8 * j)
            s[3] &= _M32
            s[1] ^= remainder
        # hmac.compare_digest: constant-time, so a failed verification cannot
        # be turned into a byte-by-byte tag-guessing oracle by timing.
        if not hmac.compare_digest(_finalise(s, k), tag):
            raise AuthenticationError("TinyJAMBU-128 authentication failed.")
        return bytes(out)

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<TinyJambu128Cipher {self.name}>"
