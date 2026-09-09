"""Automated test suite for the IoT AEAD comparison study.

Layout
------
==========================  =================================================
``test_sensor.py``          Synthetic data generation and reproducibility
``test_serialization.py``   Canonical encoding and the AAD / payload split
``test_aes.py``             AES-128-GCM correctness and round trips
``test_ascon.py``           Ascon-AEAD128 correctness and round trips
``test_kat.py``             Conformance to official NIST SP 800-232 vectors
``test_security.py``        Tampering, wrong-key and truncation rejection
``test_replay.py``          Freshness policies, strict and sliding-window
``test_receiver.py``        The end-to-end gateway pipeline
``test_nonce.py``           Nonce budgets, reuse detection, birthday bounds
``test_benchmark.py``       That the harness produces well-formed measurements
==========================  =================================================
"""
