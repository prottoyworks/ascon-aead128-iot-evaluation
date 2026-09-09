"""GIFT-COFB -- NIST Lightweight Cryptography finalist.

What it is
----------
GIFT-COFB is the one finalist in this comparison that is **not** a sponge. It
is a classical block cipher (GIFT-128, 40 rounds) used in COFB
(COmbined FeedBack) mode, which needs only n/2 bits of state beyond the block
cipher itself.  Including it means the study compares two *families* --
permutation/sponge designs (Ascon, Xoodyak, SPARKLE) against a
block-cipher-plus-mode design -- instead of only comparing sponges with each
other.

Parameters: 128-bit key, 128-bit nonce, 128-bit tag, GIFT-128 with 40 rounds.

Why it is slow in software
--------------------------
GIFT-128's bit permutation is designed to be free in hardware (it is just
wiring) but must be emulated with shift/mask sequences in software, and it runs
40 rounds per 16-byte block.  When the measurement shows GIFT-COFB near the
bottom of the software ranking, that is the expected consequence of a
hardware-oriented design, not an implementation defect -- say so in the report.

Provenance
----------
Pure-Python port written for this project from the public GIFT-COFB
specification, validated against all 1089 vectors in
``third_party/lwc_kat/GIFT-COFB.txt``.
"""

from __future__ import annotations

import hmac

from ..aead_interface import AeadCipher, AuthenticationError

_M = 0xFFFFFFFF

#: GIFT-128 round constants (6-bit LFSR sequence), one per round.
_RC = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
       0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
       0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
       0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M


def _bit_permute_step(y: int, mask: int, shift: int) -> int:
    """Swap the bit pairs selected by ``mask`` across a distance of ``shift``."""
    t = ((y >> shift) ^ y) & mask
    return ((y ^ t) ^ ((t << shift) & _M)) & _M


def _perm_inner(x: int) -> int:
    x = _bit_permute_step(x, 0x0A0A0A0A, 3)
    x = _bit_permute_step(x, 0x00CC00CC, 6)
    x = _bit_permute_step(x, 0x0000F0F0, 12)
    x = _bit_permute_step(x, 0x000000FF, 24)
    return x


def _be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def gift128b_key_schedule(key: bytes) -> list[int]:
    """Load the key in the word order the bit-sliced representation expects."""
    return [_be(key, 12), _be(key, 4), _be(key, 8), _be(key, 0)]


def gift128b_encrypt(k: list[int], block: list[int]) -> list[int]:
    """One GIFT-128 block encryption: 40 rounds of SubCells/PermBits/AddKey."""
    s0, s1, s2, s3 = block
    w0, w1, w2, w3 = k[3], k[1], k[2], k[0]
    for r in range(40):
        # SubCells: the GIFT S-box, expressed bit-sliced across the four words.
        s1 ^= s0 & s2
        s0 ^= s1 & s3
        s2 ^= s0 | s1
        s3 ^= s2
        s1 ^= s3
        s3 ^= _M
        s2 ^= s0 & s1
        s0, s3 = s3, s0
        # PermBits: the 128-bit wire permutation, as four word permutations.
        s0 = _rotl(_perm_inner(s0), 8)
        s1 = _rotl(_perm_inner(s1), 16)
        s2 = _rotl(_perm_inner(s2), 24)
        s3 = _perm_inner(s3)
        # AddRoundKey plus the round constant.
        s2 ^= w1
        s1 ^= w3
        s3 ^= 0x80000000 ^ _RC[r]
        # Key-state rotation (the GIFT key schedule).
        temp = w3
        w3, w2, w1 = w2, w1, w0
        w0 = (((temp & 0xFFFC0000) >> 2) | ((temp & 0x00030000) << 14)
              | ((temp & 0x00000FFF) << 4) | ((temp & 0x0000F000) >> 12)) & _M
        s0 &= _M
        s1 &= _M
        s2 &= _M
        s3 &= _M
    return [s0, s1, s2, s3]


# -- COFB mode helpers ------------------------------------------------------
def _double_l(L: list[int]) -> list[int]:
    """Multiply the mask L by x in GF(2^64)."""
    x, y = L
    mask = _M if (x >> 31) else 0
    return [((x << 1) | (y >> 31)) & _M, ((y << 1) ^ (mask & 0x1B)) & _M]


def _triple_l(L: list[int]) -> list[int]:
    """Multiply the mask L by (x + 1)."""
    doubled = _double_l(L)
    return [L[0] ^ doubled[0], L[1] ^ doubled[1]]


def _feedback(Y: list[int]) -> list[int]:
    """The COFB feedback function: swap halves and rotate the old top half."""
    lx, ly = Y[0], Y[1]
    return [Y[2], Y[3], ((lx << 1) | (ly >> 31)) & _M, ((ly << 1) | (lx >> 31)) & _M]


def _words_to_bytes(words: list[int]) -> bytes:
    return b"".join((w & _M).to_bytes(4, "big") for w in words)


def _absorb_associated_data(k: list[int], Y: list[int], L: list[int],
                            aad: bytes, message_length: int):
    i, remaining = 0, len(aad)
    while remaining > 16:
        L = _double_l(L)
        Y = _feedback(Y)
        Y[0] ^= L[0] ^ _be(aad, i)
        Y[1] ^= L[1] ^ _be(aad, i + 4)
        Y[2] ^= _be(aad, i + 8)
        Y[3] ^= _be(aad, i + 12)
        Y = gift128b_encrypt(k, Y)
        i += 16
        remaining -= 16
    Y = _feedback(Y)
    if remaining == 16:
        for j in range(4):
            Y[j] ^= _be(aad, i + 4 * j)
        L = _triple_l(L)
    else:
        padded = (aad[i:] + b"\x80").ljust(16, b"\x00")
        for j in range(4):
            Y[j] ^= _be(padded, 4 * j)
        L = _triple_l(_triple_l(L))
    if message_length == 0:
        L = _triple_l(_triple_l(L))
    Y[0] ^= L[0]
    Y[1] ^= L[1]
    return gift128b_encrypt(k, Y), L


def _core(key: bytes, nonce: bytes, aad: bytes, data: bytes, decrypt: bool):
    """Shared COFB body: returns (output, tag).

    Encryption and decryption differ only in which side of the XOR is the
    plaintext; the state is always advanced with the *plaintext* block, which
    is what makes the tag cover the message rather than the ciphertext.
    """
    k = gift128b_key_schedule(key)
    Y = gift128b_encrypt(k, [_be(nonce, 4 * j) for j in range(4)])
    L = [Y[0], Y[1]]
    Y, L = _absorb_associated_data(k, Y, L, aad, len(data))

    out = bytearray()
    i, remaining = 0, len(data)
    if remaining:
        while remaining > 16:
            block = [_be(data, i + 4 * j) for j in range(4)]
            produced = [(Y[j] ^ block[j]) & _M for j in range(4)]
            out += _words_to_bytes(produced)
            plain = produced if decrypt else block
            L = _double_l(L)
            Y = _feedback(Y)
            Y[0] ^= L[0] ^ plain[0]
            Y[1] ^= L[1] ^ plain[1]
            Y[2] ^= plain[2]
            Y[3] ^= plain[3]
            Y = gift128b_encrypt(k, Y)
            i += 16
            remaining -= 16
        if remaining == 16:
            block = [_be(data, i + 4 * j) for j in range(4)]
            produced = [(Y[j] ^ block[j]) & _M for j in range(4)]
            out += _words_to_bytes(produced)
            plain = produced if decrypt else block
            Y = _feedback(Y)
            for j in range(4):
                Y[j] ^= plain[j]
            L = _triple_l(L)
        else:
            y_bytes = _words_to_bytes(Y)
            produced_bytes = bytes(a ^ b for a, b in zip(data[i:], y_bytes))
            out += produced_bytes
            plain_bytes = produced_bytes if decrypt else data[i:]
            padded = (plain_bytes + b"\x80").ljust(16, b"\x00")
            plain = [_be(padded, 4 * j) for j in range(4)]
            Y = _feedback(Y)
            for j in range(4):
                Y[j] ^= plain[j]
            L = _triple_l(_triple_l(L))
        Y[0] ^= L[0]
        Y[1] ^= L[1]
        Y = gift128b_encrypt(k, Y)
    return bytes(out), _words_to_bytes(Y)


class GiftCofbCipher(AeadCipher):
    """GIFT-COFB behind the project's common AEAD interface."""

    name = "GIFT-COFB"
    key_size = 16
    nonce_size = 16
    tag_size = 16

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(
                f"GIFT-COFB requires a {self.key_size}-byte key, got {len(key)}."
            )
        self._key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"GIFT-COFB expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        ciphertext, tag = _core(self._key, nonce, aad, plaintext, decrypt=False)
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"GIFT-COFB expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        body, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        plaintext, expected = _core(self._key, nonce, aad, body, decrypt=True)
        if not hmac.compare_digest(expected, tag):
            raise AuthenticationError("GIFT-COFB authentication failed.")
        return plaintext

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<GiftCofbCipher {self.name}>"
