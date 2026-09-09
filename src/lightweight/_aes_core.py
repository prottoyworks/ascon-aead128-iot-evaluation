"""A minimal pure-Python AES-128 block cipher, used only by AES-128-CCM.

This exists so that AES-128-CCM can be measured in the *same implementation
tier* as Ascon-AEAD128 and the four NIST-LWC finalists.  The project's
AES-128-GCM baseline runs inside OpenSSL as optimised C with AES-NI hardware
instructions; putting CCM through the same C library would make the CCM data
point a measurement of OpenSSL rather than of the algorithm, and it could not
be placed on the same axis as the interpreted ciphers.

Security warning
----------------
This implementation is table-driven and therefore **not constant-time**: it is
vulnerable to cache-timing attacks.  It is a measurement instrument, not a
security component, and nothing in this project uses it to protect real data.
Its correctness is established by differential testing against OpenSSL (see
``tests/test_lightweight_kat.py``).
"""

from __future__ import annotations

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


# T-tables: one round of SubBytes+ShiftRows+MixColumns folded into 4 lookups.
def _build_tables() -> tuple[list[int], ...]:
    t0, t1, t2, t3 = [], [], [], []
    for x in range(256):
        s = _SBOX[x]
        s2 = _xtime(s)
        s3 = s2 ^ s
        w = (s2 << 24) | (s << 16) | (s << 8) | s3
        t0.append(w)
        t1.append(((w >> 8) | (w << 24)) & 0xFFFFFFFF)
        t2.append(((w >> 16) | (w << 16)) & 0xFFFFFFFF)
        t3.append(((w >> 24) | (w << 8)) & 0xFFFFFFFF)
    return t0, t1, t2, t3


_T0, _T1, _T2, _T3 = _build_tables()
_M32 = 0xFFFFFFFF


def _key_expansion(key: bytes) -> list[int]:
    """11 round keys x 4 words for AES-128."""
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((t << 8) | (t >> 24)) & _M32                       # RotWord
            t = ((_SBOX[(t >> 24) & 0xFF] << 24) | (_SBOX[(t >> 16) & 0xFF] << 16)
                 | (_SBOX[(t >> 8) & 0xFF] << 8) | _SBOX[t & 0xFF])  # SubWord
            t ^= _RCON[i // 4 - 1] << 24
        w.append(w[i - 4] ^ t)
    return w


def _encrypt_block(w: list[int], block: bytes) -> bytes:
    s0 = int.from_bytes(block[0:4], "big") ^ w[0]
    s1 = int.from_bytes(block[4:8], "big") ^ w[1]
    s2 = int.from_bytes(block[8:12], "big") ^ w[2]
    s3 = int.from_bytes(block[12:16], "big") ^ w[3]
    for r in range(1, 10):
        k = 4 * r
        t0 = (_T0[(s0 >> 24) & 0xFF] ^ _T1[(s1 >> 16) & 0xFF]
              ^ _T2[(s2 >> 8) & 0xFF] ^ _T3[s3 & 0xFF] ^ w[k])
        t1 = (_T0[(s1 >> 24) & 0xFF] ^ _T1[(s2 >> 16) & 0xFF]
              ^ _T2[(s3 >> 8) & 0xFF] ^ _T3[s0 & 0xFF] ^ w[k + 1])
        t2 = (_T0[(s2 >> 24) & 0xFF] ^ _T1[(s3 >> 16) & 0xFF]
              ^ _T2[(s0 >> 8) & 0xFF] ^ _T3[s1 & 0xFF] ^ w[k + 2])
        t3 = (_T0[(s3 >> 24) & 0xFF] ^ _T1[(s0 >> 16) & 0xFF]
              ^ _T2[(s1 >> 8) & 0xFF] ^ _T3[s2 & 0xFF] ^ w[k + 3])
        s0, s1, s2, s3 = t0, t1, t2, t3
    out = bytearray(16)
    for i, (a, b, c, d) in enumerate(((s0, s1, s2, s3), (s1, s2, s3, s0),
                                      (s2, s3, s0, s1), (s3, s0, s1, s2))):
        v = ((_SBOX[(a >> 24) & 0xFF] << 24) | (_SBOX[(b >> 16) & 0xFF] << 16)
             | (_SBOX[(c >> 8) & 0xFF] << 8) | _SBOX[d & 0xFF]) ^ w[40 + i]
        out[4 * i:4 * i + 4] = v.to_bytes(4, "big")
    return bytes(out)


