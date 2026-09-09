#!/usr/bin/env python3
"""Command-line entry point for the whole experiment.

Every stage of the study is reachable from here, so the sequence recorded in
the report is exactly the sequence a reader can re-run.

Commands
--------
``check``            Verify the environment and the Ascon installation.
``generate-data``    Write the synthetic sensor dataset to data/.
``kat``              Run the NIST SP 800-232 conformance vectors.
``security-tests``   Run the defensive tampering and replay experiments.
``benchmark``        Measure latency, throughput, memory and overhead.
``analyze``          Aggregate statistics and render every figure.
``demo``             Walk one message through the secure channel, verbosely.
``all``              check -> generate-data -> kat -> security-tests ->
                     benchmark -> analyze, in that order.

Every command accepts ``--quick`` or ``--full`` to select a configuration
profile.  ``--quick`` exists so you can prove the pipeline runs end to end in
well under a minute before committing to the full campaign; its iteration
counts are far too small to report.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Make `src` importable when this file is run directly from any directory.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import analyze_results, benchmark, environment_info, security_tests, sensor
from src.ascon_aead import is_available as ascon_available
from src.config import (
    ENVIRONMENT_JSON,
    SECURITY_RESULTS_CSV,
    SENSOR_CSV,
    ExperimentConfig,
    ensure_output_dirs,
    get_config,
)

BANNER = """
==============================================================================
 Performance Evaluation of Ascon-AEAD128 and AES-128-GCM
 for Secure IoT Communication -- A Proof-of-Concept Study
==============================================================================
"""


def _log(message: str) -> None:
    """Print a progress message immediately (never inside a timed region)."""
    print(message, flush=True)


def _resolve_config(args: argparse.Namespace) -> ExperimentConfig:
    """Pick the profile from --quick / --full, defaulting to full."""
    profile = "quick" if getattr(args, "quick", False) else "full"
    config = get_config(profile)
    if getattr(args, "seed", None) is not None:
        config = config.with_overrides(random_seed=args.seed)
    return config


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_check(config: ExperimentConfig) -> int:
    """Report the environment and whether Ascon is correctly installed."""
    ensure_output_dirs()
    record = environment_info.collect(config)
    print(environment_info.format_console(record))
    print()

    if not ascon_available():
        print(
            "Ascon-AEAD128 is NOT available.\n"
            "Fix this before running anything else:\n"
            "    python scripts/setup_ascon.py\n"
        )
        return 1

    print("Ascon-AEAD128 (NIST SP 800-232) is available.")
    path = environment_info.write(config)
    print(f"Environment record written to {path.relative_to(PROJECT_ROOT)}")
    return 0


def cmd_generate_data(config: ExperimentConfig) -> int:
    """Generate and save the synthetic sensor dataset."""
    ensure_output_dirs()
    _log(f"Generating {config.sensor_messages:,} synthetic readings "
         f"(seed={config.random_seed}) ...")
    readings = sensor.generate_dataset(config)
    count = sensor.write_dataset(readings)
    _log(f"Wrote {count:,} rows to {SENSOR_CSV.relative_to(PROJECT_ROOT)}")

    first = readings[0]
    _log("\nFirst reading:")
    for key, value in first.to_dict().items():
        _log(f"  {key:<17}= {value!r}")

    from src.serialization import split_reading

    aad, payload = split_reading(first)
    _log(f"\n  AAD  ({len(aad):>3} bytes, authenticated, sent in clear): {aad.decode()}")
    _log(f"  Payload ({len(payload):>3} bytes, encrypted + authenticated): {payload.decode()}")
    return 0


def cmd_kat(config: ExperimentConfig) -> int:
    """Run known-answer tests against the official Ascon vectors."""
    from src import kat

    ensure_output_dirs()
    if not ascon_available():
        _log("Ascon is not installed. Run: python scripts/setup_ascon.py")
        return 1

    limit = 100 if config.profile == "quick" else None
    _log(
        "Running NIST SP 800-232 known-answer tests"
        + (f" (first {limit} vectors, quick profile)" if limit else " (all vectors)")
        + " ..."
    )
    try:
        report = kat.run_kat(limit=limit)
    except (kat.KatFileMissing, ValueError) as exc:
        _log(f"KAT run failed: {exc}")
        return 1

    path = kat.write_kat_report(report)
    _log(f"\nVectors tested   : {report.total}")
    _log(f"Encrypt matches  : {report.encrypt_matches}/{report.total}")
    _log(f"Decrypt matches  : {report.decrypt_matches}/{report.total}")
    _log(f"Result           : {'PASS' if report.passed else 'FAIL'}")
    if report.failures:
        _log(f"Failing Count values (first 10): {report.failures[:10]}")
    _log(f"Written to       : {path.relative_to(PROJECT_ROOT)}")
    _log(f"Vector source    : {report.source_file}")
    return 0 if report.passed else 1


def cmd_security_tests(config: ExperimentConfig) -> int:
    """Run the defensive security experiments."""
    ensure_output_dirs()
    _log(f"Running defensive security tests ({config.security_trials} trials each) ...")
    results = security_tests.run_all(config)
    security_tests.write_results(results)

    header = f"{'alg':<16}{'id':<4}{'test':<30}{'expected':<10}{'actual':<10}{'pass':<6}"
    _log("\n" + header)
    _log("-" * len(header))
    for row in results:
        _log(
            f"{row.algorithm:<16}{row.test_id:<4}{row.test_name:<30}"
            f"{row.expected_result:<10}{row.actual_result:<10}"
            f"{'YES' if row.passed else 'NO':<6}"
        )

    failed = [r for r in results if not r.passed]
    _log(f"\n{len(results) - len(failed)}/{len(results)} tests passed.")
    _log(f"Written to {SECURITY_RESULTS_CSV.relative_to(PROJECT_ROOT)}")
    if failed:
        _log("\nFAILURES -- investigate before reporting any result:")
        for row in failed:
            _log(f"  {row.algorithm} {row.test_id} {row.test_name}: "
                 f"{row.unexpected_outcomes}/{row.trials} unexpected")
        return 1
    return 0


def cmd_benchmark(config: ExperimentConfig) -> int:
    """Run the measurement campaign."""
    ensure_output_dirs()
    if not ascon_available():
        _log("WARNING: Ascon is not installed; only AES-128-GCM will be measured.")
        _log("         Run `python scripts/setup_ascon.py` for a complete comparison.\n")

    _log(benchmark.estimate_runtime_note(config))
    if config.profile == "quick":
        _log("\nQUICK PROFILE: these iteration counts are a smoke test only.")
        _log("Do NOT report numbers from a quick run.\n")
    else:
        _log("\nFull profile. Close other applications; a busy machine adds outliers.\n")

    environment_info.write(config)
    written = benchmark.run_benchmark(config, progress=_log)
    for name, path in written.items():
        _log(f"  {name:<9} -> {path.relative_to(PROJECT_ROOT)}")
    _log(f"  environment -> {ENVIRONMENT_JSON.relative_to(PROJECT_ROOT)}")
    _log("\nNext: python main.py analyze")
    return 0


def cmd_analyze(config: ExperimentConfig) -> int:
    """Aggregate statistics and render figures."""
    ensure_output_dirs()
    try:
        artefacts = analyze_results.analyze(config)
    except FileNotFoundError as exc:
        _log(str(exc))
        return 1

    print(artefacts["console"])
    _log(f"\nSummary CSV : {Path(str(artefacts['summary_csv'])).relative_to(PROJECT_ROOT)}")
    _log(f"Memory CSV  : {Path(str(artefacts['memory_summary_csv'])).relative_to(PROJECT_ROOT)}")
    _log("Figures     :")
    for path in artefacts["graphs"]:  # type: ignore[union-attr]
        _log(f"  {Path(str(path)).relative_to(PROJECT_ROOT)}")
    return 0


def cmd_demo(config: ExperimentConfig) -> int:
    """Walk a single message through the secure channel, showing every step.

    This is the command to run in a viva or a demonstration: it makes the
    AAD/payload split, the tag, the tamper rejection and the replay rejection
    visible on one screen.
    """
    from src.aead_interface import AuthenticationError
    from src.aes_gcm import AesGcmCipher
    from src.ascon_aead import AsconAead128Cipher
    from src.receiver import SecureReceiver, build_packet
    from src.replay_protection import StrictSequenceValidator
    from src.sensor import SensorFleet
    from src.serialization import split_reading

    print(BANNER)
    fleet = SensorFleet(config)
    reading = fleet.next_reading("WH-001", 0)
    reading_2 = fleet.next_reading("WH-001", 5)

    cipher_classes = [AesGcmCipher] + ([AsconAead128Cipher] if ascon_available() else [])

    for cipher_cls in cipher_classes:
        key = cipher_cls.generate_key()
        cipher = cipher_cls(key)
        receiver = SecureReceiver(validator=StrictSequenceValidator())
        receiver.provision("WH-001", cipher_cls.name, key)

        aad, payload = split_reading(reading)
        packet = build_packet(cipher, reading)

        print(f"\n{'=' * 78}\n {cipher_cls.name}\n{'=' * 78}")
        print(f"Key size        : {cipher_cls.key_size} bytes ({cipher_cls.key_size * 8} bits)")
        print(f"Nonce size      : {cipher_cls.nonce_size} bytes ({cipher_cls.nonce_size * 8} bits)")
        print(f"Tag size        : {cipher_cls.tag_size} bytes ({cipher_cls.tag_size * 8} bits)")
        print(f"\nAAD (clear, authenticated, {len(aad)} B): {aad.decode()}")
        print(f"Payload (before encryption, {len(payload)} B): {payload.decode()}")
        print(f"Ciphertext+tag  : {len(packet.ciphertext)} B  "
              f"(expansion {len(packet.ciphertext) - len(payload)} B)")
        print(f"Ciphertext head : {packet.ciphertext[:24].hex()}...")
        print(f"Total on wire   : {packet.wire_size} B")

        print("\n 1. Genuine packet          -> ", end="")
        result = receiver.receive(packet)
        print(f"{result.status}  ({result.detail})")

        print(" 2. One ciphertext bit flipped -> ", end="")
        corrupted = bytearray(packet.ciphertext)
        corrupted[0] ^= 0x01
        from src.serialization import SecurePacket

        tampered = SecurePacket(packet.algorithm, packet.aad, packet.nonce, bytes(corrupted))
        print(f"{receiver.receive(tampered).status}")

        print(' 3. AAD "WH-001" -> "WH-999"   -> ', end="")
        forged_aad = packet.aad.replace(b'"WH-001"', b'"WH-999"')
        forged = SecurePacket(packet.algorithm, forged_aad, packet.nonce, packet.ciphertext)
        try:
            cipher.decrypt(forged.nonce, forged.ciphertext, forged.aad)
            print("ACCEPTED  <-- THIS WOULD BE A SERIOUS BUG")
        except AuthenticationError:
            print("REJECTED (tag verification failed)")

        print(" 4. Wrong key                  -> ", end="")
        try:
            cipher_cls(cipher_cls.generate_key()).decrypt(
                packet.nonce, packet.ciphertext, packet.aad
            )
            print("ACCEPTED  <-- THIS WOULD BE A SERIOUS BUG")
        except AuthenticationError:
            print("REJECTED (tag verification failed)")

        print(" 5. Next genuine packet        -> ", end="")
        print(receiver.receive(build_packet(cipher, reading_2)).status)

        print(" 6. Replay of packet 1         -> ", end="")
        replayed = receiver.receive(packet)
        print(f"{replayed.status}  ({replayed.reason.value if replayed.reason else ''})")
        print("    Note: the replayed packet's AEAD tag is still perfectly valid.")
        print("    It is the sequence-number check, not the cipher, that stops it.")

    return 0


def cmd_all(config: ExperimentConfig) -> int:
    """Run the entire study in order, stopping at the first failure."""
    print(BANNER)
    stages: list[tuple[str, object]] = [
        ("Environment check", cmd_check),
        ("Sensor data generation", cmd_generate_data),
        ("Ascon conformance (KAT)", cmd_kat),
        ("Defensive security tests", cmd_security_tests),
        ("Benchmark", cmd_benchmark),
        ("Analysis and figures", cmd_analyze),
    ]
    for index, (label, function) in enumerate(stages, start=1):
        print(f"\n{'#' * 78}\n# Stage {index}/{len(stages)}: {label}\n{'#' * 78}")
        code = function(config)  # type: ignore[operator]
        if code != 0:
            print(f"\nStage '{label}' failed with exit code {code}. Stopping.")
            return code
    print("\nAll stages completed.")
    return 0


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

COMMANDS = {
    "check": (cmd_check, "verify the environment and Ascon installation"),
    "generate-data": (cmd_generate_data, "write the synthetic sensor dataset"),
    "kat": (cmd_kat, "run NIST SP 800-232 known-answer conformance tests"),
    "security-tests": (cmd_security_tests, "run defensive tampering and replay tests"),
    "benchmark": (cmd_benchmark, "measure latency, throughput, memory and overhead"),
    "analyze": (cmd_analyze, "aggregate statistics and render figures"),
    "demo": (cmd_demo, "walk one message through the channel, verbosely"),
    "all": (cmd_all, "run every stage in order"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (_function, help_text) in COMMANDS.items():
        sub = subparsers.add_parser(name, help=help_text)
        profile = sub.add_mutually_exclusive_group()
        profile.add_argument(
            "--quick", action="store_true",
            help="tiny iteration counts; smoke test only, not reportable",
        )
        profile.add_argument(
            "--full", action="store_true",
            help="full iteration counts (default)",
        )
        sub.add_argument(
            "--seed", type=int, default=None,
            help="override the reproducibility seed (default 42)",
        )
        sub.add_argument(
            "--verbose", action="store_true", help="enable INFO-level logging",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    config = _resolve_config(args)
    function, _help = COMMANDS[args.command]
    try:
        return function(config)  # type: ignore[operator]
    except KeyboardInterrupt:
        print("\nInterrupted. Partial results may be incomplete.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
