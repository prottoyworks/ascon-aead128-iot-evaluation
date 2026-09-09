"""Schwaemm256-128 (SPARKLE) -- NIST Lightweight Cryptography finalist.

What it is
----------
SPARKLE is the *software-oriented* finalist: an ARX design (addition, rotation,
XOR only -- no S-box tables, no bit-slicing) built on the Alzette 64-bit
ARX-box.  Where TinyJAMBU optimises for hardware gates and GIFT-COFB reuses a
block cipher, SPARKLE optimises for exactly the kind of 32-bit microcontroller
most IoT nodes actually use, which makes it the toughest speed competitor for
Ascon in this comparison.

Parameters: 128-bit key, **256-bit nonce**, 128-bit tag, SPARKLE-384
permutation, rate 32 bytes, capacity 16 bytes.

The 256-bit nonce matters for the report
----------------------------------------
Schwaemm256-128 transmits a 32-byte nonce where Ascon transmits 16 and AES-GCM
transmits 12.  On a 128-byte telemetry frame that is a materially larger
communication overhead, and it is visible in the overhead figures. Speed is not
the only axis on which a "lightweight" algorithm can be expensive.

Provenance
----------
Pure-Python port written for this project from the public SPARKLE v1.2
specification, validated against all 1089 vectors in
``third_party/lwc_kat/Schwaemm256-128.txt``.
"""

from __future__ import annotations

import hmac

from ..aead_interface import AeadCipher, AuthenticationError

_M = 0xFFFFFFFF
_RC = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
       0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]
_SPARKLE_RC = _RC + _RC[:4]          # 12 step constants
_RATE = 32                            # bytes


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _M


def _alzette(x: int, y: int, c: int) -> tuple[int, int]:
    x = (x + _rotl(y, 1)) & _M           # ROTR(y, 31) == ROTL(y, 1)
    y ^= _rotl(x, 8)                     # ROTR(x, 24) == ROTL(x, 8)
    x ^= c
    x = (x + _rotl(y, 15)) & _M          # ROTR(y, 17) == ROTL(y, 15)
    y ^= _rotl(x, 15)                    # ROTR(x, 17) == ROTL(x, 15)
    x ^= c
    x = (x + y) & _M
    y ^= _rotl(x, 1)                     # ROTR(x, 31) == ROTL(x, 1)
    x ^= c
    x = (x + _rotl(y, 8)) & _M           # ROTR(y, 24) == ROTL(y, 8)
    y ^= _rotl(x, 16)
    x ^= c
    return x, y


def sparkle_384(s: list[int], steps: int) -> None:
    """SPARKLE-384 permutation, in place on 12 32-bit words."""
    x0, y0, x1, y1, x2, y2 = s[0], s[1], s[2], s[3], s[4], s[5]
    x3, y3, x4, y4, x5, y5 = s[6], s[7], s[8], s[9], s[10], s[11]
    for step in range(steps):
        y0 ^= _SPARKLE_RC[step]
        y1 ^= step
        x0, y0 = _alzette(x0, y0, _RC[0])
        x1, y1 = _alzette(x1, y1, _RC[1])
        x2, y2 = _alzette(x2, y2, _RC[2])
        x3, y3 = _alzette(x3, y3, _RC[3])
        x4, y4 = _alzette(x4, y4, _RC[4])
        x5, y5 = _alzette(x5, y5, _RC[5])
        tx = x0 ^ x1 ^ x2
        ty = y0 ^ y1 ^ y2
        tx = _rotl(tx ^ ((tx << 16) & _M), 16)
        ty = _rotl(ty ^ ((ty << 16) & _M), 16)
        y3 ^= tx
        y4 ^= tx
        tx ^= y5
        y5 = y2
        y2 = y3 ^ y0
        y3 = y0
        y0 = y4 ^ y1
        y4 = y1
        y1 = tx ^ y5
        x3 ^= ty
        x4 ^= ty
        ty ^= x5
        x5 = x2
        x2 = x3 ^ x0
        x3 = x0
        x0 = x4 ^ x1
        x4 = x1
        x1 = ty ^ x5
    s[0], s[1], s[2], s[3] = x0, y0, x1, y1
    s[4], s[5], s[6], s[7] = x2, y2, x3, y3
    s[8], s[9], s[10], s[11] = x4, y4, x5, y5


def _rho(s: list[int]) -> None:
    """rho1 combined with rate whitening (Schwaemm256-128 feedback)."""
    for i in range(4):
        t = s[i]
        s[i] = s[i + 4] ^ s[i + 8]
        s[i + 4] ^= t ^ s[i + 8]


def _rate_bytes(s: list[int]) -> bytes:
    return b"".join(s[i].to_bytes(4, "little") for i in range(8))


def _right_bytes(s: list[int]) -> bytes:
    return b"".join(s[i].to_bytes(4, "little") for i in range(8, 12))


def _xor_into_rate(s: list[int], data: bytes) -> None:
    n = len(data)
    full = n // 4
    for i in range(full):
        s[i] ^= int.from_bytes(data[4 * i:4 * i + 4], "little")
    rem = n & 3
    if rem:
        s[full] ^= int.from_bytes(data[full * 4:] + bytes(4 - rem), "little")


def _xor_pad(s: list[int], idx: int) -> None:
    s[idx // 4] ^= 0x80 << (8 * (idx % 4))


def _domain(s: list[int], value: int) -> None:
    s[11] ^= (value << 24) & _M


def _authenticate(s: list[int], ad: bytes) -> None:
    i = 0
    remaining = len(ad)
    while remaining > _RATE:
        _rho(s)
        _xor_into_rate(s, ad[i:i + _RATE])
        sparkle_384(s, 7)
        i += _RATE
        remaining -= _RATE
    if remaining == _RATE:
        _domain(s, 0x05)
        _rho(s)
        _xor_into_rate(s, ad[i:i + _RATE])
    else:
        _domain(s, 0x04)
        _rho(s)
        _xor_into_rate(s, ad[i:])
        _xor_pad(s, remaining)
    sparkle_384(s, 11)


def _init(key: bytes, nonce: bytes) -> list[int]:
    s = [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(8)]
    s += [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(4)]
    sparkle_384(s, 11)
    return s


def _crypt(s: list[int], data: bytes, decrypt: bool) -> bytes:
    out = bytearray()
    i, remaining = 0, len(data)
    while remaining > _RATE:
        block = data[i:i + _RATE]
        produced = bytes(a ^ b for a, b in zip(_rate_bytes(s), block))
        out += produced
        _rho(s)
        _xor_into_rate(s, produced if decrypt else block)
        sparkle_384(s, 7)
        i += _RATE
        remaining -= _RATE
    block = data[i:]
    produced = bytes(a ^ b for a, b in zip(_rate_bytes(s), block))
    out += produced
    if remaining == _RATE:
        _domain(s, 0x07)
        _rho(s)
        _xor_into_rate(s, produced if decrypt else block)
    else:
        _domain(s, 0x06)
        _rho(s)
        _xor_into_rate(s, produced if decrypt else block)
        _xor_pad(s, remaining)
    sparkle_384(s, 11)
    return bytes(out)



class Schwaemm256128Cipher(AeadCipher):
    """Schwaemm256-128 behind the project's common AEAD interface."""

    name = "Schwaemm256-128"
    key_size = 16
    nonce_size = 32
    tag_size = 16

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(
                f"Schwaemm256-128 requires a {self.key_size}-byte key, got {len(key)}."
            )
        self._key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Schwaemm256-128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        state = _init(self._key, nonce)
        if aad:
            _authenticate(state, aad)
        ciphertext = _crypt(state, plaintext, decrypt=False) if plaintext else b""
        tag = bytes(a ^ b for a, b in zip(_right_bytes(state), self._key))
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Schwaemm256-128 expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        body, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        state = _init(self._key, nonce)
        if aad:
            _authenticate(state, aad)
        plaintext = _crypt(state, body, decrypt=True) if body else b""
        expected = bytes(a ^ b for a, b in zip(_right_bytes(state), self._key))
        if not hmac.compare_digest(expected, tag):
            raise AuthenticationError("Schwaemm256-128 authentication failed.")
        return plaintext

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<Schwaemm256128Cipher {self.name}>"
