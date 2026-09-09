"""Xoodyak -- NIST Lightweight Cryptography finalist, in Cyclist keyed mode.

What it is
----------
Xoodyak comes from the Keccak team (the designers of SHA-3) and is the closest
structural rival to Ascon among the finalists: both are permutation-based
duplex constructions.  Xoodyak uses the 384-bit Xoodoo permutation with 12
rounds; Ascon uses a 320-bit permutation with 12/8 rounds.  A head-to-head
measurement between the two is therefore the single most informative
comparison in this extension -- it isolates *permutation and rate choices*
rather than comparing unrelated designs.

Parameters: 128-bit key, 128-bit nonce, 128-bit tag, 384-bit state,
absorb rate 44 bytes, squeeze rate 24 bytes.

Provenance
----------
Pure-Python port written for this project from the public specification. The
Xoodoo[12] permutation was verified word-for-word against the C reference that
generated the vectors, and the full AEAD is validated against all 1089 vectors
in ``third_party/lwc_kat/Xoodyak.txt``.
"""

from __future__ import annotations

import hmac

from ..aead_interface import AeadCipher, AuthenticationError

_M = 0xFFFFFFFF

#: Xoodoo round constants, one per round, 12 rounds.
_RC = [0x058, 0x038, 0x3C0, 0x0D0, 0x120, 0x014,
       0x060, 0x02C, 0x380, 0x0F0, 0x1A0, 0x012]


def _rotl(value: int, n: int) -> int:
    return ((value << n) | (value >> (32 - n))) & _M


def xoodoo(state: bytearray) -> bytearray:
    """Xoodoo[12] on a 48-byte little-endian state.

    The state is three planes of four 32-bit lanes; lane (x, y) occupies bytes
    ``4*(x + 4*y)``.  Each round is theta (column parity mixing), rho-west
    (plane shift), iota (round constant), chi (the non-linear layer) and
    rho-east (a second plane shift).
    """
    A = [[int.from_bytes(state[4 * (x + 4 * y):4 * (x + 4 * y) + 4], "little")
          for y in range(3)] for x in range(4)]
    for rc in _RC:
        # theta
        parity = [A[x][0] ^ A[x][1] ^ A[x][2] for x in range(4)]
        effect = [_rotl(parity[(x - 1) % 4], 5) ^ _rotl(parity[(x - 1) % 4], 14)
                  for x in range(4)]
        for x in range(4):
            for y in range(3):
                A[x][y] ^= effect[x]
        # rho-west
        shifted = [A[(x - 1) % 4][1] for x in range(4)]
        for x in range(4):
            A[x][1] = shifted[x]
            A[x][2] = _rotl(A[x][2], 11)
        # iota
        A[0][0] ^= rc
        # chi
        for x in range(4):
            a0, a1, a2 = A[x][0], A[x][1], A[x][2]
            A[x][0] = a0 ^ ((~a1) & a2 & _M)
            A[x][1] = a1 ^ ((~a2) & a0 & _M)
            A[x][2] = a2 ^ ((~a0) & a1 & _M)
        # rho-east
        for x in range(4):
            A[x][1] = _rotl(A[x][1], 1)
        east = [_rotl(A[(x - 2) % 4][2], 8) for x in range(4)]
        for x in range(4):
            A[x][2] = east[x]
    out = bytearray(48)
    for y in range(3):
        for x in range(4):
            out[4 * (x + 4 * y):4 * (x + 4 * y) + 4] = A[x][y].to_bytes(4, "little")
    return out


class _Cyclist:
    """The Cyclist mode of operation, keyed variant.

    Cyclist alternates ``Down`` (absorb data into the state, with padding and a
    domain byte) and ``Up`` (apply the permutation and optionally read output).
    The ``phase`` flag records which happened last, so that the mode never
    permutes twice in a row or absorbs twice without a permutation between.
    """

    R_ABSORB = 44
    R_SQUEEZE = 24

    def __init__(self, key: bytes, identifier: bytes = b"") -> None:
        self.s = bytearray(48)
        # The all-zero starting state counts as "just after an Up", so the very
        # first key block is absorbed without a leading permutation.
        self.phase_up = True
        self._absorb_any(key + identifier + bytes([len(identifier)]),
                         self.R_ABSORB, 0x02)

    def _up(self, n: int, cu: int) -> bytes:
        self.s[47] ^= cu
        self.s = xoodoo(self.s)
        self.phase_up = True
        return bytes(self.s[:n])

    def _down(self, block: bytes, cd: int) -> None:
        for i, b in enumerate(block):
            self.s[i] ^= b
        self.s[len(block)] ^= 0x01          # 10* padding
        self.s[47] ^= cd                    # domain separation
        self.phase_up = False

    def _absorb_any(self, data: bytes, rate: int, cd: int) -> None:
        first, i = True, 0
        while True:
            block = data[i:i + rate]
            i += rate
            if not self.phase_up:
                self._up(0, 0x00)
            self._down(block, cd if first else 0x00)
            first = False
            if i >= len(data):
                break

    def absorb(self, data: bytes) -> None:
        self._absorb_any(data, self.R_ABSORB, 0x03)

    def crypt(self, data: bytes, decrypt: bool) -> bytes:
        """Encrypt or decrypt; either way the *plaintext* is absorbed."""
        out = bytearray()
        cu, i = 0x80, 0
        while True:
            block = data[i:i + self.R_SQUEEZE]
            i += self.R_SQUEEZE
            keystream = self._up(len(block), cu)
            cu = 0x00
            produced = bytes(a ^ b for a, b in zip(block, keystream))
            out += produced
            self._down(produced if decrypt else block, 0x00)
            if i >= len(data):
                break
        return bytes(out)

    def squeeze(self, length: int) -> bytes:
        y = self._up(min(length, self.R_SQUEEZE), 0x40)
        while len(y) < length:
            self._down(b"", 0x00)
            y += self._up(min(length - len(y), self.R_SQUEEZE), 0x00)
        return y


class XoodyakCipher(AeadCipher):
    """Xoodyak AEAD behind the project's common AEAD interface."""

    name = "Xoodyak"
    key_size = 16
    nonce_size = 16
    tag_size = 16

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(
                f"Xoodyak requires a {self.key_size}-byte key, got {len(key)}."
            )
        self._key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Xoodyak expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        # In Xoodyak's AEAD profile the nonce is the Cyclist "id", absorbed in
        # the same block as the key -- not as ordinary associated data.
        cyclist = _Cyclist(self._key, nonce)
        cyclist.absorb(aad)
        return cyclist.crypt(plaintext, decrypt=False) + cyclist.squeeze(self.tag_size)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"Xoodyak expects a {self.nonce_size}-byte nonce, got {len(nonce)}."
            )
        if len(ciphertext) < self.tag_size:
            raise AuthenticationError("Ciphertext shorter than the authentication tag.")
        body, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        cyclist = _Cyclist(self._key, nonce)
        cyclist.absorb(aad)
        plaintext = cyclist.crypt(body, decrypt=True)
        if not hmac.compare_digest(cyclist.squeeze(self.tag_size), tag):
            raise AuthenticationError("Xoodyak authentication failed.")
        return plaintext

    def __repr__(self) -> str:  # pragma: no cover - never print key material
        return f"<XoodyakCipher {self.name}>"
