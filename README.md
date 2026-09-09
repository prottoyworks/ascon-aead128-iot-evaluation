# Performance Evaluation of Ascon-AEAD128 and AES-128-GCM for Secure IoT Communication

**A Proof-of-Concept Study**

An experimental comparison of two authenticated-encryption-with-associated-data (AEAD)
schemes on simulated smart-warehouse IoT sensor traffic:

- **Ascon-AEAD128** — the lightweight AEAD standardised in **NIST SP 800-232**
- **AES-128-GCM** — the established baseline from **NIST SP 800-38D**

---

## 1. Research question

> How suitable are Ascon-AEAD128 and AES-128-GCM for securing small IoT messages when
> evaluated in terms of authenticated security functionality, encryption/decryption
> latency, throughput, memory overhead, and communication overhead?

The study is **not** designed to show that either algorithm wins. It is designed to
produce measurements, in a documented environment, from which a bounded conclusion can
be drawn — and to be explicit about the boundary. See [§14 Limitations](#14-limitations).

## 2. Cybersecurity motivation

IoT deployments concentrate three problems that make cryptography hard:

1. **The devices are constrained.** Microcontrollers with tens of kilobytes of RAM, no
   AES hardware acceleration, and a battery that has to last years. Cryptography that is
   nearly free on a laptop can be the dominant energy cost on a sensor node.
2. **The data is sensitive even when it looks trivial.** A stream of warehouse
   temperature readings reveals occupancy, cold-chain integrity, shift patterns and
   whether a facility is operating — useful to a competitor and to a burglar.
3. **The threat model includes the network itself.** Wireless links are open to passive
   eavesdropping and to active injection, modification and replay.

Encryption alone answers only the first of those. A stream cipher without
authentication lets an attacker flip a bit in the ciphertext and flip the corresponding
bit in the plaintext — silently turning `24.75 °C` into something else. That is why this
study evaluates **AEAD** schemes, which bind confidentiality and integrity into one
primitive, and why it also implements **replay protection**, which AEAD does not provide.

NIST standardised Ascon in **SP 800-232** precisely for the constrained case. Whether
that translates into an advantage *in a given environment* is an empirical question —
which is this project.

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    SIMULATED SMART-WAREHOUSE FLEET                       │
│                                                                          │
│   WH-001    WH-002    WH-003    WH-004    WH-005                         │
│     │         │         │         │         │                            │
│     └─────────┴─────────┴────┬────┴─────────┘                            │
│                              │   src/sensor.py                           │
│                              ▼   seeded, reproducible random walk         │
│              { device_id, protocol_version, sequence,                    │
│                temperature, humidity, gas_level, timestamp }             │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │  src/serialization.py
                               │  canonical JSON → UTF-8 bytes
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   ┌──────────────────────┐        ┌──────────────────────────┐
   │   ASSOCIATED DATA    │        │        PLAINTEXT         │
   │  (clear, but signed) │        │  (encrypted + signed)    │
   ├──────────────────────┤        ├──────────────────────────┤
   │ device_id            │        │ temperature              │
   │ protocol_version     │        │ humidity                 │
   │ sequence             │        │ gas_level                │
   └──────────┬───────────┘        │ timestamp                │
              │                    └────────────┬─────────────┘
              │        ┌────────────────────────┘
              ▼        ▼
        ┌───────────────────────────────────────────┐
        │      AeadCipher   (src/aead_interface)    │  ← one interface, so the
        ├─────────────────────┬─────────────────────┤    benchmark harness cannot
        │   AES-128-GCM       │   Ascon-AEAD128     │    favour either path
        │   src/aes_gcm.py    │  src/ascon_aead.py  │
        │   OpenSSL / pyca    │  pyascon reference  │
        │   96-bit nonce      │  128-bit nonce      │
        │   128-bit tag       │  128-bit tag        │
        └─────────────────────┴──────────┬──────────┘
                                         │
                    SecurePacket{ algorithm, aad, nonce, ciphertext‖tag }
                                         │
        ─────────────────── hostile network ───────────────────
          tamper ✗   forge ✗   swap key ✗   truncate ✗   replay ✗
                                         │
                                         ▼
        ┌───────────────────────────────────────────────────────┐
        │            SecureReceiver  (src/receiver.py)          │
        │                                                       │
        │  1. select cipher from algorithm label                │
        │  2. cheap pre-filter on UNAUTHENTICATED sequence      │──► reject early
        │  3. AEAD verify + decrypt          ◄── trust starts here
        │  4. authoritative replay check, then commit counter   │──► reject replay
        │  5. structural validation → SensorReading             │
        └───────────────────────────────────────────────────────┘
                                         │
        ┌────────────────────────────────┴─────────────────────────────────┐
        ▼                                ▼                                 ▼
 src/security_tests.py           src/benchmark.py              src/analyze_results.py
 tamper / forge / replay         latency, throughput,          statistics, 8 figures
 → security_results.csv          memory, overhead              → summary_results.csv
                                 → raw_results.csv                results/graphs/
```

**Why steps 2 and 4 are separate.** Step 2 runs on data nobody has authenticated yet, so
it may only *reject*, never accept and never advance the counter. If the counter advanced
on unverified input, one forged packet claiming sequence `2147483647` would lock the real
device out permanently — a one-packet denial of service. Step 4 repeats the check on
now-authenticated data and only then commits.

## 4. Project structure

```
iot_crypto_project/
│
├── main.py                      CLI entry point for every stage
├── requirements.txt
├── pyproject.toml               packaging + pytest configuration
├── .gitignore
├── README.md
│
├── src/
│   ├── __init__.py
│   ├── config.py                every experimental parameter, in one place
│   ├── aead_interface.py        the abstract AEAD both ciphers implement
│   ├── aes_gcm.py               AES-128-GCM  (cryptography / OpenSSL)
│   ├── ascon_aead.py            Ascon-AEAD128 (pyascon reference)
│   ├── ascon_loader.py          implementation discovery + provenance
│   ├── kat.py                   NIST SP 800-232 conformance testing
│   ├── sensor.py                synthetic smart-warehouse data
│   ├── serialization.py         canonical encoding + AAD/payload split
│   ├── nonce.py                 nonce budgets, reuse detection, birthday bounds
│   ├── replay_protection.py     strict and sliding-window freshness policies
│   ├── receiver.py              the gateway pipeline
│   ├── security_tests.py        defensive tampering experiments
│   ├── benchmark.py             the measurement harness
│   ├── analyze_results.py       statistics and figures
│   └── environment_info.py      reproducibility metadata capture
│
├── tests/                       180 automated tests
│   ├── __init__.py
│   ├── conftest.py              import-path fix + shared fixtures
│   ├── test_sensor.py
│   ├── test_serialization.py
│   ├── test_aes.py
│   ├── test_ascon.py
│   ├── test_kat.py              ← conformance to official vectors
│   ├── test_security.py
│   ├── test_replay.py
│   ├── test_receiver.py
│   ├── test_nonce.py
│   └── test_benchmark.py
│
├── scripts/
│   └── setup_ascon.py           fetch + verify the Ascon reference code
│
├── third_party/                 created by setup_ascon.py
│   ├── pyascon/ascon.py         the implementation under test
│   ├── ascon_kat/…KAT….txt      official test vectors
│   └── PROVENANCE.json          URLs, commit hashes, SHA-256 of each file
│
├── data/
│   └── sensor_messages.csv      generated
│
├── results/
│   ├── raw_results.csv          every individual timing sample
│   ├── summary_results.csv      aggregated statistics
│   ├── summary_memory.csv
│   ├── memory_results.csv
│   ├── overhead_results.csv
│   ├── security_results.csv
│   ├── kat_results.csv
│   ├── environment.json
│   └── graphs/                  8 figures
│
└── docs/
    ├── METHODOLOGY.md
    ├── REPORT_GUIDE.md
    └── THESIS_EXTENSION.md
```

### Deviations from the structure in the brief, and why

| Addition | Reason |
|---|---|
| `src/aead_interface.py` | Both ciphers go through one abstract class, so the benchmark cannot advantage either through harness dispatch. This is a **fairness control**, not decoration. |
| `src/ascon_loader.py` | Isolates the fragile "where did the code come from?" concern from the clean cipher wrapper, and rejects the obsolete PyPI package explicitly. |
| `src/kat.py` + `tests/test_kat.py` | Conformance testing is a distinct research claim from correctness testing and deserves its own module. |
| `src/nonce.py` | Nonce management is a first-class research concern in the brief; giving it a module makes the birthday-bound argument testable. |
| `scripts/setup_ascon.py`, `third_party/` | Reproducibility: exact commit hashes and file hashes, recorded automatically. |
| `tests/conftest.py` | Fixes `ModuleNotFoundError: No module named 'src'` permanently. |
| Extra results files | `memory_results.csv`, `overhead_results.csv`, `kat_results.csv` — one file per measurement type is easier to cite than one wide file. |

---

## 5. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Windows | 10 or 11 | macOS and Linux also work unchanged |
| Python | 3.11 or 3.12 | `python --version`. 3.10 and below lack the `X \| Y` type syntax used here |
| Git | any recent | needed by `scripts/setup_ascon.py` |
| VS Code | any recent | with the Microsoft Python extension |
| Disk space | ~150 MB | a full benchmark run writes a raw CSV of tens of megabytes |

---

## 6. Installation — exact Windows commands

Run these in **PowerShell** or **Command Prompt**, one block at a time.

### 6.1 Create and enter the project folder

```powershell
cd %USERPROFILE%\Documents
mkdir iot_crypto_project
cd iot_crypto_project
```

Copy the project files into this folder, then open it in VS Code:

```powershell
code .
```

### 6.2 Create a virtual environment

```powershell
python -m venv .venv
```

### 6.3 Activate it

```powershell
:: Command Prompt
.venv\Scripts\activate.bat
```

```powershell
# PowerShell
.\.venv\Scripts\Activate.ps1
```

If PowerShell refuses with *"running scripts is disabled on this system"*:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Your prompt should now begin with `(.venv)`. **Every command below assumes it does.**

### 6.4 Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 6.5 Install the Ascon reference implementation

```powershell
python scripts\setup_ascon.py
```

See [§7 Ascon setup](#7-ascon-setup) for what this does and why it is not a `pip install`.

### 6.6 Freeze the exact dependency versions

```powershell
pip freeze > requirements-lock.txt
```

Commit `requirements-lock.txt` alongside your results. `requirements.txt` says what the
project needs; `requirements-lock.txt` says what actually produced your numbers.

### 6.7 Initialise Git

```powershell
git init
git add .
git commit -m "Initial commit: IoT AEAD comparison study"
```

### 6.8 Verify the whole environment

```powershell
python main.py check
```

Expected: your OS, CPU, RAM, Python version, OpenSSL version, and
`Ascon-AEAD128 (NIST SP 800-232) is available.`

---

## 7. Ascon setup

### 7.1 Which implementation this project uses

| Question | Answer |
|---|---|
| **Which implementation?** | `pyascon` — the Python reference implementation |
| **Where from?** | <https://github.com/meichlseder/pyascon> |
| **Who wrote it?** | Maria Eichlseder, one of Ascon's four designers |
| **Does it support final NIST SP 800-232?** | Its output matches the official SP 800-232 test vectors on all 1089 of them — see §7.3 |
| **Licence** | CC0-1.0 (public domain dedication) — safe to vendor and redistribute |
| **How to obtain** | `python scripts/setup_ascon.py` |
| **Version to record** | The commit hash written to `third_party/PROVENANCE.json` |

### 7.2 Why *not* `pip install ascon`

The `ascon` package on PyPI (0.0.9 at the time of writing) implements only the **Ascon
v1.2 competition candidates**:

```
Ascon-128    Ascon-128a    Ascon-80pq
```

These are **not** the standardised algorithm. NIST SP 800-232 specifies **Ascon-AEAD128**,
which differs in its initialisation vector, its rate and its padding conventions and
produces entirely different ciphertexts. A project that used the PyPI package while
claiming to evaluate the standard would be measuring the wrong algorithm.

`src/ascon_loader.py` therefore **rejects** any module that cannot perform an
`Ascon-AEAD128` operation, and says so explicitly rather than falling back silently.

### 7.3 How conformance is established — and why round-trip testing is not enough

A **Known-Answer Test (KAT)** is a published table of `(key, nonce, AD, plaintext) →
ciphertext` triples. You feed your implementation the inputs and require it to reproduce
the published output *byte for byte*.

This matters because a **round-trip test proves almost nothing about conformance**. An
implementation with the wrong IV, wrong round count or a byte-order error will encrypt
and decrypt perfectly *with itself* while being unable to interoperate with any other
implementation. Only a KAT catches that.

The vectors come from the Ascon team's **official C reference implementation**:

```
https://github.com/ascon/ascon-c
  → crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
```

whose README states it implements NIST SP 800-232. Because those vectors were produced by
an *independent* implementation, in a different language, by the algorithm's designers,
agreement on all of them is strong evidence of conformance. Checking pyascon against
vectors generated by pyascon would prove nothing.

Run it:

```powershell
python main.py kat
```

Expected output — and this is a result you should cite in your Methodology chapter:

```
Vectors tested   : 1089
Encrypt matches  : 1089/1089
Decrypt matches  : 1089/1089
Result           : PASS
```

### 7.4 How to cite the implementation in your report

> The Ascon-AEAD128 implementation used is the Python reference implementation
> `pyascon` by M. Eichlseder, obtained from <https://github.com/meichlseder/pyascon>
> at commit `<COMMIT FROM third_party/PROVENANCE.json>` (CC0-1.0). Conformance to
> NIST SP 800-232 was verified against the 1089 known-answer test vectors published in
> the Ascon team's reference C implementation, <https://github.com/ascon/ascon-c>,
> commit `<COMMIT FROM PROVENANCE.json>`; all vectors matched. `[VERIFY CITATION]` for
> the formal bibliography entries of NIST SP 800-232 and the Ascon specification.

Both commit hashes and the SHA-256 of both files are recorded automatically in
`third_party/PROVENANCE.json` and copied into `results/environment.json` on every run.

### 7.5 Manual alternative (if `git clone` is unavailable)

```powershell
python scripts\setup_ascon.py --manual
```

prints exact copy-paste instructions. Verify afterwards with:

```powershell
python scripts\setup_ascon.py --check
```

---

## 8. Commands

Every command accepts `--quick` (tiny iteration counts, smoke test) or `--full`
(default, reportable). Run from the project root with the virtual environment active.

| Purpose | Command |
|---|---|
| Verify environment + Ascon | `python main.py check` |
| Generate sensor data | `python main.py generate-data` |
| Run unit tests | `pytest` |
| Run conformance tests | `python main.py kat` |
| Run security tests | `python main.py security-tests` |
| **Quick** benchmark (smoke test) | `python main.py benchmark --quick` |
| **Full** benchmark | `python main.py benchmark --full` |
| Statistics + graphs | `python main.py analyze` |
| Live demonstration | `python main.py demo` |
| Everything, in order | `python main.py all` |

### Recommended first run

```powershell
python main.py check
pytest
python main.py generate-data
python main.py kat
python main.py security-tests
python main.py benchmark --quick
python main.py analyze
```

If all of that succeeds, commit, then run the real campaign:

```powershell
python main.py benchmark --full
python main.py analyze
```

### `pytest` — expected output

```powershell
pytest
```

You should see a run of `tests/test_*.py` files with dots, ending in a green
`N passed` line and **no failures and no errors**. Some tests are skipped if
`scripts/setup_ascon.py` has not been run — the skip reason names the fix.

Useful variants:

```powershell
pytest -v                        :: one line per test
pytest tests/test_kat.py -v      :: conformance only
pytest -m conformance            :: same, by marker
pytest -x                        :: stop at the first failure
pytest -k "replay or nonce"      :: run a subset by name
```

**A failure in `tests/test_kat.py` invalidates every Ascon measurement in the project.**
Fix it before running anything else.

### `python main.py demo` — what to run in your viva

Walks one message through the whole channel and prints, for both algorithms: the AAD/
payload split, key/nonce/tag sizes, the ciphertext, then live rejection of a flipped
ciphertext bit, a `WH-001 → WH-999` AAD forgery, a wrong key, and a replay. It fits on
one screen and demonstrates every security property in the project.

---

## 9. Expected output files

### `data/`

| File | Contents |
|---|---|
| `sensor_messages.csv` | 10 000 rows (default) with header `device_id, protocol_version, sequence, temperature, humidity, gas_level, timestamp`. Fully determined by `random_seed`; regenerating with the same seed gives a byte-identical file. |

### `results/`

| File | Contents |
|---|---|
| `raw_results.csv` | One row per timed operation: `algorithm, message_size, operation, experiment_run, iteration, time_ns, batch_size, plaintext_size, ciphertext_size, aad_size`. A full run produces roughly 360 000 rows / tens of MB. **Every number comes from execution; none is entered by hand.** |
| `summary_results.csv` | Aggregated by (algorithm, size, operation): `samples, mean_ns, median_ns, stdev_ns, min_ns, max_ns, p95_ns, ci95_lower_ns, ci95_upper_ns, throughput_mb_s_median, messages_per_second_median` |
| `memory_results.csv` / `summary_memory.csv` | `tracemalloc` peak Python-heap allocation per operation. **Read the caveat in §14.3 before quoting these.** |
| `overhead_results.csv` | `plaintext_size, ciphertext_size, tag_bytes, nonce_bytes, expansion_bytes, wire_overhead_bytes, overhead_percent` |
| `security_results.csv` | One row per (algorithm × scenario): `expected_result, actual_result, trials, unexpected_outcomes, passed` |
| `kat_results.csv` | Conformance outcome, vector count, source file, pass/fail |
| `environment.json` | OS, CPU, RAM, Python, OpenSSL version, `cryptography` version, Ascon commit + SHA-256, every experiment parameter, timestamp |
| `graphs/graph1_encrypt_latency.png` | Encryption latency vs message size (log-log, 95% CI error bars, harness noise floor drawn) |
| `graphs/graph2_decrypt_latency.png` | Decryption latency vs message size |
| `graphs/graph3_encrypt_throughput.png` | Encryption throughput (MB/s) vs message size |
| `graphs/graph4_decrypt_throughput.png` | Decryption throughput vs message size |
| `graphs/graph5_peak_python_memory.png` | Peak Python-heap allocation (caveated on the figure itself) |
| `graphs/graph6_communication_overhead.png` | Overhead as % of payload vs plaintext size |
| `graphs/graph7_ciphertext_size.png` | Absolute ciphertext size vs plaintext size |
| `graphs/graph8_small_payload_focus.png` | 32–512 byte range — the sizes most representative of IoT sensor traffic |

**No measured value appears anywhere in this repository that was not produced by running
the code.** There are no example numbers, no illustrative figures, and no placeholder
results.

---

## 10. Reproducibility

| Mechanism | What it fixes |
|---|---|
| `random_seed = 42` in `src/config.py` | Sensor values and benchmark execution order |
| `results/environment.json` | Machine, OS, Python, OpenSSL, package versions, all parameters |
| `third_party/PROVENANCE.json` | Exact upstream commit + SHA-256 of the Ascon code and vectors |
| `requirements-lock.txt` | Exact dependency versions (`pip freeze`) |

**The seed does not touch key or nonce generation.** Those always come from
`os.urandom`. A reproducible nonce is a reused nonce, and reusing a nonce under one key
breaks AES-GCM catastrophically. This is deliberate and is stated in
`src/nonce.py`, `src/aead_interface.py` and `results/environment.json`.

To reproduce a result set:

```powershell
python scripts\setup_ascon.py --force   :: restores the exact vendored files
python main.py all
```

Then compare your `results/environment.json` against the published one. Timing numbers
will differ — they are hardware-dependent — but ciphertext sizes, overhead figures,
KAT outcomes and security-test outcomes must match exactly.

---

## 11. Security notes

### What this project demonstrates

- **Confidentiality** — payload fields are unreadable without the key
- **Integrity** — any single-bit change to ciphertext, tag or AAD is detected
- **Authentication** — only a key holder can produce a verifying tag
- **Freshness** — replayed and stale messages are rejected at the protocol layer

### What it deliberately does not do

- No offensive tooling. Every "attack" is a function that flips a bit in a byte string
  the test itself generated moments earlier, in memory, under a key it generated itself.
- No network access, no scanning, no exploitation, no credential handling.
- No real personal or sensitive data. The dataset is synthetic.

### Practices followed in the code

- Keys and nonces from `os.urandom` only — never from the seeded RNG
- No hard-coded production keys. The one fixed key in the project is
  `tests/conftest.py::deterministic_key`, marked test-only and visibly artificial
- `AesGcmCipher` stores the `AESGCM` object rather than the raw key, so the secret cannot
  surface in a `repr` or a traceback
- All verification failures raise one exception type with one message, so a caller cannot
  learn *which* check failed — a receiver that explains failures is an oracle
- The receiver logs rejection *categories*, never key material, nonces, tags or plaintext
- `ascon_decrypt` returns `None` on failure; the wrapper converts that to an exception
  immediately, so a caller cannot proceed with `None` in place of a security failure

---

## 12. Nonce management

Both schemes are **nonce-respecting**: security holds only while no `(key, nonce)` pair
is used twice.

For AES-GCM the failure is catastrophic. GCM is counter mode plus GHASH; a repeated nonce
emits the same keystream twice, so XORing the two ciphertexts cancels it and leaks the
XOR of the plaintexts. Worse, the collision lets an adversary solve for the GHASH subkey
`H`, breaking *authentication* for every message under that key — the "forbidden attack".
`[VERIFY CITATION]` — Joux's original note, and Böck, Zauner, Devlin, Somorovsky &
Jovanovic, *Nonce-Disrespecting Adversaries*, USENIX WOOT 2016.

This project uses random nonces from the OS CSPRNG. That needs no state and no
coordination between devices, at the cost of a birthday bound. With an *n*-bit nonce,
after *q* messages the collision probability is approximately `q² / 2^(n+1)`:

| Scheme | Nonce | After 2³² messages under one key |
|---|---|---|
| AES-128-GCM | 96 bits | ≈ 2⁻³³ |
| Ascon-AEAD128 | 128 bits | ≈ 2⁻⁶⁵ |

`src/nonce.py` makes this budget **enforced rather than assumed**: `NonceBudget` refuses
to issue nonces past the configured limit, and `NonceReuseDetector` turns "we believe
nonces are unique" into a testable assertion. `tests/test_nonce.py` checks both, and
checks the birthday arithmetic against the closed form.

The 32-bit-longer Ascon nonce is a genuine trade-off worth discussing in your report: it
buys a far more comfortable bound, and costs 4 extra bytes on every packet.

---

## 13. Methodology in brief

Full detail in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

| Control | Implementation |
|---|---|
| Only the crypto call is timed | Input generation, serialisation and I/O all outside the timed region |
| High-resolution monotonic clock | `time.perf_counter_ns()` — integer nanoseconds |
| Sub-microsecond operations | Timed in batches of 100 and divided; `batch_size` recorded per row |
| Warm-up | 100 discarded iterations before every measured block |
| **Randomised execution order** | Cells shuffled with a seeded RNG, so thermal drift cannot favour one algorithm |
| **Setup costs separated** | `keygen` and `noncegen` are their own operations, never folded into latency |
| **Harness noise floor measured** | An empty call is timed through the identical path and reported |
| Memory measured separately | `tracemalloc` perturbs timing, so it gets its own pass |
| GC disabled during measurement | A collection cycle inside a sample would look like an outlier |
| Mean *and* median reported | Timing data is right-skewed; quoting only one hides that |
| 95% confidence intervals | Student's *t*, from the measured standard deviation |

### The harness noise floor — quote this in your Results chapter

Every timed sample includes a Python function-call frame, a loop step and two
`perf_counter_ns()` calls. For Ascon at hundreds of microseconds that is irrelevant. For
OpenSSL-backed AES-GCM at around a microsecond it is **not**.

Rather than silently subtracting a correction, the benchmark measures an empty callable
through the identical code path and records it as `operation = harness_baseline`. The
analysis prints it and draws it on the latency graphs. This is the single most important
honesty control in the experiment: it lets a reader see which measurements are
comfortably above the measurement limit of the setup and which are approaching it.

---

## 14. Limitations

**Read this before writing a single sentence of conclusion.**

### 14.1 This compares implementations, not algorithms

This is the most important limitation in the study.

- **AES-128-GCM** runs through `cryptography`, which calls **OpenSSL**, which on any
  modern x86-64 CPU dispatches to **AES-NI** and **PCLMULQDQ** hardware instructions.
  Effectively no Python executes per byte.
- **Ascon-AEAD128** runs through the **pure-Python reference implementation**, which is
  written for clarity and verifiability, not speed. Every permutation round executes as
  Python bytecode operating on Python integers.

The experiment therefore measures

> **algorithm + implementation + language runtime + hardware acceleration**

and not intrinsic algorithm performance. A reference implementation is chosen precisely
because it is auditable and conformance-testable — but it is not a performance artefact.

**Write your conclusions like this:**

> ✅ "In the evaluated software environment, using an OpenSSL-backed AES-GCM
> implementation and the pure-Python Ascon reference implementation, AES-128-GCM achieved
> substantially lower latency across all tested message sizes."
>
> ✅ "The tested Ascon-AEAD128 reference implementation demonstrated …"
>
> ✅ "These results characterise the implementations evaluated and cannot be generalised
> to optimised implementations or to constrained hardware."

**Never write:**

> ❌ "AES is faster than Ascon."
> ❌ "Ascon is more efficient than AES."
> ❌ "Ascon is unsuitable for IoT."

The last one would be a particularly serious error: the entire rationale for Ascon is its
behaviour on hardware *without* AES acceleration, which is exactly what this setup does
not test. A fair intrinsic comparison would require optimised C on both sides, or a
microcontroller with no AES-NI. That is future work — see
[`docs/THESIS_EXTENSION.md`](docs/THESIS_EXTENSION.md) — and is **not** required for this
proof-of-concept.

### 14.2 What *is* directly comparable

Not everything is contaminated by the implementation gap. These findings hold regardless
of implementation quality and are safe to state plainly:

- **Ciphertext expansion**: 16 bytes for both — a structural property of the schemes
- **Wire overhead**: 28 bytes (AES: 16 tag + 12 nonce) vs 32 bytes (Ascon: 16 + 16)
- **Every security property**: tamper detection, AAD integrity, wrong-key rejection,
  truncation handling, replay rejection — all verified for both
- **Conformance**: the Ascon implementation matches the official standard vectors
- **Relative cost across message sizes** within one implementation

### 14.3 Memory figures are Python-heap only

`tracemalloc` observes **Python heap allocations only**. AES-GCM's working memory is
allocated inside OpenSSL's C code and is invisible to it; the pure-Python Ascon
implementation allocates Python integers for its entire state. **The two numbers are not
comparable as algorithm memory footprints.**

Always describe them as *"peak Python-heap allocation observed in the evaluated
implementation"* — never as RAM usage on an embedded device. The figure is caption-warned
in the code, in the graph and here.

### 14.4 Further limitations for your Chapter 6

- Synthetic sensor data, not a real deployment
- Desktop/laptop, not a microcontroller
- Python runtime, not embedded C
- No energy or power measurement — arguably *the* decisive metric for battery IoT
- No physical radio link, no packet loss, no real latency
- No side-channel analysis (timing, power, EM)
- Single hardware platform; no diversity across CPU families
- No key-establishment protocol; keys are provisioned directly
- Replay state is in-memory and does not survive a receiver restart
- Single-threaded; no concurrency or multi-device scaling

---

## 15. Troubleshooting

<details>
<summary><b>ModuleNotFoundError: No module named 'src'</b></summary>

You are running from the wrong directory, or without the venv.

```powershell
cd path\to\iot_crypto_project
.venv\Scripts\activate.bat
python main.py check
```

For pytest this is already handled by `tests/conftest.py`, which inserts the project root
into `sys.path`. If it still fails, confirm `tests/conftest.py` exists and that you are
invoking `pytest` (not `python tests/test_aes.py` directly).
</details>

<details>
<summary><b>Ascon import failure / AsconUnavailableError</b></summary>

```powershell
python scripts\setup_ascon.py --check
```

It will tell you which file is missing. To fix:

```powershell
python scripts\setup_ascon.py --force
```

If git is blocked:

```powershell
python scripts\setup_ascon.py --manual
```

If you see *"An Ascon module was found but rejected"*, you have the obsolete PyPI package
installed. Remove it — it implements the wrong algorithm:

```powershell
pip uninstall ascon
python scripts\setup_ascon.py --check
```
</details>

<details>
<summary><b>ModuleNotFoundError: No module named 'cryptography' (or pandas, matplotlib…)</b></summary>

The virtual environment is not active — look for `(.venv)` in your prompt.

```powershell
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Verify VS Code is using the same interpreter: `Ctrl+Shift+P` → *Python: Select
Interpreter* → the one inside `.venv`.
</details>

<details>
<summary><b>SyntaxError involving <code>|</code> in a type hint</b></summary>

You are on Python 3.9 or earlier.

```powershell
python --version
```

Install 3.11 or 3.12 from python.org, then rebuild the venv:

```powershell
rmdir /s /q .venv
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```
</details>

<details>
<summary><b>PowerShell: "running scripts is disabled on this system"</b></summary>

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or use `.venv\Scripts\activate.bat` from Command Prompt instead.
</details>

<details>
<summary><b>FileNotFoundError: data/sensor_messages.csv</b></summary>

```powershell
python main.py generate-data
```
</details>

<details>
<summary><b>"Raw timing results not found" during analyze</b></summary>

Run a benchmark first:

```powershell
python main.py benchmark --quick
python main.py analyze
```
</details>

<details>
<summary><b>AuthenticationError during normal operation</b></summary>

This should never happen on a genuine message and indicates a real bug. Check that the
AAD used for decryption is byte-identical to the AAD used for encryption — the most
common cause is re-serialising a dict with different key ordering. `pytest
tests/test_serialization.py` will catch that class of error.
</details>

<details>
<summary><b>CSV shows blank lines between every row (Windows)</b></summary>

Caused by opening a file without <code>newline=""</code>. This project always passes it.
If you add your own CSV writing code, do the same:

```python
with path.open("w", newline="", encoding="utf-8") as handle:
```
</details>

<details>
<summary><b>Benchmark is very slow / seems to hang</b></summary>

Expected. The pure-Python Ascon implementation is orders of magnitude slower than
OpenSSL AES-GCM, and the full profile runs 320 000 timed operations plus setup and
memory passes. Progress prints every 10 cells.

To confirm the pipeline works before committing to a full run:

```powershell
python main.py benchmark --quick
```
</details>

<details>
<summary><b>Timing results are noisy / huge standard deviation</b></summary>

Close other applications, disable Windows Update, plug in the laptop and set the power
plan to *High performance* (battery saver throttles the CPU). Then re-run. Compare
`mean_ns` against `median_ns` in `summary_results.csv`: a large gap means outliers, and
`p95_ns` will show how heavy the tail is. Report the median alongside the mean and say
the machine was noisy — that is a legitimate finding, not a failure.
</details>

<details>
<summary><b>Graphs are empty or matplotlib errors about a display</b></summary>

The code already selects the headless `Agg` backend. If you added your own plotting
code, do the same before importing pyplot:

```python
import matplotlib
matplotlib.use("Agg")
```
</details>

---

## 16. Five-week plan

| Week | Tasks | Deliverable |
|---|---|---|
| **1 — Research & environment** | Read NIST SP 800-232 and SP 800-38D. Study AEAD, AES-GCM and Ascon. Set up Python, venv, VS Code, Git. Run `setup_ascon.py`. Generate sensor data. Begin literature review. | Working environment; `data/sensor_messages.csv`; annotated bibliography started |
| **2 — Cryptographic implementation** | Understand `aes_gcm.py` and `ascon_aead.py`. Run `pytest`. Run `main.py kat` and record the conformance result. Verify AAD handling and round trips. | Both algorithms verified; KAT PASS recorded; `pytest` green |
| **3 — Security tests & benchmarking** | Run `security-tests`. Study each scenario until you can explain *why* it must be rejected. Run `benchmark --quick`, then `--full`. | `security_results.csv`; `raw_results.csv`; `environment.json` |
| **4 — Analysis** | Run `analyze`. Read `summary_results.csv`. Compare mean vs median. Check every latency against the harness noise floor. Draft Results and Discussion. | Tables, 8 figures, `summary_results.csv`, first interpretation |
| **5 — Documentation** | Finish all seven chapters. Write the limitations chapter *carefully*. Resolve every `[VERIFY CITATION]`. Final `pytest`. Prepare the viva demo (`main.py demo`). | Submission-ready report, code and presentation |

---

## 17. Future thesis extension

This project is **Phase 1**. See [`docs/THESIS_EXTENSION.md`](docs/THESIS_EXTENSION.md)
for the architecture argument.

What exists now:

```
sensor simulation + secure message structure + AES-GCM + Ascon-AEAD128
+ AEAD/AAD handling + replay protection + benchmarking framework
+ security evaluation + conformance testing
```

What the thesis adds:

```
ML-KEM        → post-quantum key establishment
ML-DSA        → post-quantum authentication
crypto-agility→ algorithm negotiation and migration
IoT → Gateway → Cloud architecture
STRIDE        → structured threat modelling
smart warehouse → full case study
hardware benchmarking → microcontroller, optimised C, energy measurement
```

The key structural point for your proposal: `CIPHER_REGISTRY` in `src/receiver.py` is a
one-line-per-algorithm dictionary, and the `SecurePacket` already carries an algorithm
label that is covered by the authentication tag. Crypto-agility is not a rewrite — it is
an extension of a hook that already exists and is already tested
(`test_receiver.py::test_receiver_handles_both_algorithms_simultaneously`).

---

## 18. Licence and attribution

Project code: use as you see fit for your coursework.

Third-party material fetched by `scripts/setup_ascon.py`, both **CC0-1.0**:

- `pyascon` — Maria Eichlseder — <https://github.com/meichlseder/pyascon>
- `ascon-c` KAT vectors — the Ascon team — <https://github.com/ascon/ascon-c>

Exact commits and file hashes: `third_party/PROVENANCE.json`.

Standards referenced (verify full bibliographic details before submission —
`[VERIFY CITATION]`):

- NIST SP 800-232 — *Ascon-Based Lightweight Cryptography Standards for Constrained Devices*
- NIST SP 800-38D — *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*
- NIST FIPS 197 — *Advanced Encryption Standard (AES)*
