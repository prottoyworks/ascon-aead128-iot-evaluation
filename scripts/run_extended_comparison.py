#!/usr/bin/env python3
"""Run the extended lightweight-AEAD comparison and draw its figures.

    python scripts/run_extended_comparison.py                 # default profile
    python scripts/run_extended_comparison.py --profile full   # long, reportable run
    python scripts/run_extended_comparison.py --profile quick  # ~1 minute smoke test
    python scripts/run_extended_comparison.py --graphs-only    # redraw from existing CSVs

What it does, in order
----------------------
1. Verifies every added implementation against its official test vectors.  If
   any vector fails the run stops: a timing measurement of a wrong
   implementation is worthless, so it must never be produced.
2. Measures latency, throughput, memory, communication overhead and end-to-end
   message rate for Ascon-AEAD128 and the five comparison algorithms (plus the
   AES-128-GCM baseline, marked as a different implementation tier).
3. Writes every result under ``results/extended/``.
4. Draws figures ``graph09`` .. ``graph18`` into ``results/graphs/``.

Nothing this script writes overwrites an existing result of the core study.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import get_config  # noqa: E402
from src.extended_benchmark import run_extended_benchmark  # noqa: E402
from src.extended_graphs import generate_extended_graphs  # noqa: E402


#: Profiles for the extension.
#:
#: ``extended`` is the default: all eight payload sizes and all ten repetitions,
#: but 100 measured operations per cell instead of 1000.  Repetitions -- not
#: iterations -- are what the confidence intervals are computed across, so this
#: keeps the statistics honest while bringing a run that would take hours in
#: interpreted Python down to roughly fifteen minutes.  Use ``full`` for the
#: final numbers if you can leave the machine running.
PROFILE_OVERRIDES = {
    "quick": dict(message_sizes=(32, 128, 1024), warmup_iterations=5,
                  benchmark_iterations=20, experiment_repetitions=3, memory_samples=3),
    "extended": dict(warmup_iterations=20, benchmark_iterations=100,
                     experiment_repetitions=10, memory_samples=10),
    "full": dict(),          # exactly the parameters in src/config.FULL
}


def verify_implementations() -> bool:
    """Check every added cipher against its published vectors before measuring."""
    from tests.test_lightweight_kat import KAT_DIR, KAT_FILES, _parse_kat
    from src.lightweight import BY_NAME
    from src.lightweight.aes_ccm import AesCcmPythonCipher

    everything_passed = True
    for algorithm, filename in KAT_FILES.items():
        cipher_cls = BY_NAME[algorithm]
        passed = failed = 0
        for vector in _parse_kat(KAT_DIR / filename):
            key = bytes.fromhex(vector["Key"])
            nonce = bytes.fromhex(vector["Nonce"])
            plaintext = bytes.fromhex(vector["PT"])
            aad = bytes.fromhex(vector["AD"])
            expected = bytes.fromhex(vector["CT"])
            cipher = cipher_cls(key)
            if cipher.encrypt(nonce, plaintext, aad) == expected \
                    and cipher.decrypt(nonce, expected, aad) == plaintext:
                passed += 1
            else:
                failed += 1
        everything_passed &= failed == 0
        status = "PASS" if failed == 0 else "FAIL"
        print(f"  [{status}] {algorithm:<18} {passed:>5} vectors verified, {failed} failed")

    # AES-128-CCM has no LWC vector file; check it against OpenSSL instead.
    import os
    import random

    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    rng = random.Random(20260908)
    mismatches = 0
    for _ in range(40):
        key, nonce = os.urandom(16), os.urandom(12)
        plaintext = os.urandom(rng.randint(0, 512))
        aad = os.urandom(rng.randint(0, 96))
        if AesCcmPythonCipher(key).encrypt(nonce, plaintext, aad) != \
                AESCCM(key, tag_length=16).encrypt(nonce, plaintext, aad):
            mismatches += 1
    everything_passed &= mismatches == 0
    print(f"  [{'PASS' if mismatches == 0 else 'FAIL'}] {'AES-128-CCM':<18} "
          f"   40 differential trials against OpenSSL, {mismatches} mismatches")
    return everything_passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", default="extended",
                        choices=sorted(PROFILE_OVERRIDES),
                        help="measurement profile (default: extended)")
    parser.add_argument("--graphs-only", action="store_true",
                        help="skip measurement and redraw figures from existing CSVs")
    parser.add_argument("--skip-verification", action="store_true",
                        help="not recommended: skip the known-answer test gate")
    parser.add_argument("--no-aes-gcm", action="store_true",
                        help="omit the OpenSSL AES-128-GCM baseline from the extension")
    args = parser.parse_args()

    base = get_config("full")
    config = base.with_overrides(**PROFILE_OVERRIDES[args.profile])

    print("=" * 74)
    print("Extended comparison: Ascon-AEAD128 vs five other lightweight AEAD schemes")
    print("=" * 74)

    if not args.graphs_only and not args.skip_verification:
        print("\n[1/3] Verifying implementations against official test vectors")
        if not verify_implementations():
            print("\nAborting: an implementation does not match its published vectors.",
                  file=sys.stderr)
            return 1

    if not args.graphs_only:
        print(f"\n[2/3] Measuring (profile '{args.profile}': "
              f"{config.benchmark_iterations} operations/cell x "
              f"{config.experiment_repetitions} repetitions x "
              f"{len(config.message_sizes)} sizes)")
        started = time.time()
        paths = run_extended_benchmark(config, include_aes_gcm=not args.no_aes_gcm)
        print(f"  measurement wall-clock: {time.time() - started:,.1f} s")
        for label, path in paths.items():
            print(f"  {label:<12} -> {path.relative_to(PROJECT_ROOT)}")

    print("\n[3/3] Drawing figures")
    for path in generate_extended_graphs(config):
        print(f"  figure -> {path.relative_to(PROJECT_ROOT)}")

    print("\nDone. New results are in results/extended/, new figures in results/graphs/.")
    print("Nothing belonging to the original experiment was modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
