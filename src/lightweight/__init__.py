"""Additional lightweight AEAD schemes used to widen the comparison.

Why this package exists
-----------------------
The core study compares Ascon-AEAD128 against a single established baseline,
AES-128-GCM.  That answers "how does the new standard compare with the
incumbent", but it cannot answer the question a reader of the title will also
ask: **how does Ascon-AEAD128 compare with the other lightweight algorithms it
was standardised ahead of?**

This package adds five comparison algorithms so that question can be answered
from measurement rather than from citation:

======================  ===================================================
Algorithm               Why it is in the comparison
======================  ===================================================
TinyJAMBU-128           NIST-LWC finalist; the smallest hardware footprint
Xoodyak                 NIST-LWC finalist; Keccak team; Ascon's closest rival
Schwaemm256-128         NIST-LWC finalist (SPARKLE); software-oriented ARX
GIFT-COFB               NIST-LWC finalist; block-cipher based, not a sponge
AES-128-CCM             The AEAD actually deployed in IEEE 802.15.4 / Zigbee
======================  ===================================================

Four of the five are the NIST Lightweight Cryptography **finalists that Ascon
was selected ahead of** in 2023; the fifth is the AEAD that constrained IoT
networks use today.  Together they make "is Ascon a good choice for small IoT
messages?" an empirical question rather than an appeal to authority.

Implementation status -- read this before quoting any number
------------------------------------------------------------
Every algorithm here is a **pure-Python implementation written for this
project** and validated against published test vectors (see
``tests/test_lightweight_kat.py`` and ``docs/EXTENDED_ALGORITHMS.md``).  They
are therefore in the *same implementation tier* as the project's Ascon-AEAD128,
which is also interpreted Python.  That is deliberate and it is the single most
important methodological property of this extension:

    Comparing Ascon (Python) with these five (Python) compares **algorithms**.
    Comparing Ascon (Python) with AES-128-GCM (OpenSSL C, AES-NI) compares
    **implementations**.

None of these implementations is constant-time and none should protect real
data.  They exist to be measured, not deployed.
"""

from __future__ import annotations

from ..aead_interface import AeadCipher
from .aes_ccm import AesCcmPythonCipher
from .gift_cofb import GiftCofbCipher
from .schwaemm import Schwaemm256128Cipher
from .tinyjambu import TinyJambu128Cipher
from .xoodyak import XoodyakCipher

#: The five comparison algorithms, in a stable declaration order.
LIGHTWEIGHT_CIPHERS: tuple[type[AeadCipher], ...] = (
    TinyJambu128Cipher,
    XoodyakCipher,
    Schwaemm256128Cipher,
    GiftCofbCipher,
    AesCcmPythonCipher,
)

#: Map of algorithm name -> class, for lookups from CSV rows.
BY_NAME: dict[str, type[AeadCipher]] = {c.name: c for c in LIGHTWEIGHT_CIPHERS}

__all__ = [
    "LIGHTWEIGHT_CIPHERS",
    "BY_NAME",
    "TinyJambu128Cipher",
    "XoodyakCipher",
    "Schwaemm256128Cipher",
    "GiftCofbCipher",
    "AesCcmPythonCipher",
]
