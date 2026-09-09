"""Performance Evaluation of Ascon-AEAD128 and AES-128-GCM for Secure IoT Communication.

A proof-of-concept study comparing two authenticated-encryption-with-associated-
data (AEAD) schemes on simulated smart-warehouse sensor traffic:

* **Ascon-AEAD128** -- the lightweight AEAD standardised in NIST SP 800-232.
* **AES-128-GCM**   -- the established baseline from NIST SP 800-38D.

The package is organised so that each research concern lives in one module:

===========================  ==================================================
``config``                   Every experimental parameter, in one place
``aead_interface``           The common abstraction both ciphers implement
``aes_gcm`` / ``ascon_aead`` The two cipher wrappers
``ascon_loader``             Locating the reference implementation, with provenance
``kat``                      Conformance testing against official test vectors
``sensor``                   Synthetic smart-warehouse data generation
``serialization``            Deterministic encoding and the AAD / payload split
``nonce``                    Nonce budgets, reuse detection, birthday bounds
``replay_protection``        Freshness policies (strict and sliding-window)
``receiver``                 The gateway pipeline, in security-correct order
``security_tests``           Defensive tampering experiments
``benchmark``                The measurement harness
``analyze_results``          Statistics and figures, from measured data only
``environment_info``         Reproducibility metadata capture
===========================  ==================================================
"""

__version__ = "1.0.0"
__all__ = [
    "aead_interface",
    "aes_gcm",
    "analyze_results",
    "ascon_aead",
    "ascon_loader",
    "benchmark",
    "config",
    "environment_info",
    "kat",
    "nonce",
    "receiver",
    "replay_protection",
    "security_tests",
    "sensor",
    "serialization",
]
