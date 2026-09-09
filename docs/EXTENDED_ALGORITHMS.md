# Extended comparison: Ascon-AEAD128 against five other lightweight AEAD schemes

This document covers the **extension** to the core study. It does not change
anything in the original experiment; it adds a second, self-contained
experiment alongside it.

---

## 1. Why the extension exists

The core study answers:

> How does Ascon-AEAD128 compare with the established baseline, AES-128-GCM?

That is a necessary comparison, but on its own it leaves the title's phrase
"compared to other lightweight cryptographic algorithms" unanswered by
measurement. It also has a structural weakness that an examiner will spot:
Ascon runs as interpreted Python while AES-GCM runs inside OpenSSL as
hand-optimised C using the CPU's AES-NI instructions, so the headline speed gap
is a statement about *implementations* rather than about *algorithms*.

The extension answers the second question and repairs the structural weakness
at the same time:

> How does Ascon-AEAD128 compare with the lightweight algorithms it was
> standardised ahead of, and with the AEAD that IoT networks deploy today, when
> every one of them is implemented the same way, in the same language, in the
> same measurement harness?

## 2. The five added algorithms, and why each one is there

| Algorithm | Key / Nonce / Tag (bits) | Why it is in the comparison |
|---|---|---|
| **TinyJAMBU-128** | 128 / 96 / **64** | NIST-LWC finalist. A keyed NLFSR, not a sponge: the smallest hardware footprint of the finalists. Its 64-bit tag is the interesting trade. |
| **Xoodyak** | 128 / 128 / 128 | NIST-LWC finalist from the Keccak team. The closest structural rival to Ascon: also a permutation-based duplex, so this is the cleanest head-to-head. |
| **Schwaemm256-128** (SPARKLE) | 128 / **256** / 128 | NIST-LWC finalist. The software-oriented ARX design, and therefore Ascon's toughest speed competitor on 32-bit microcontrollers. Its 256-bit nonce is expensive on the wire. |
| **GIFT-COFB** | 128 / 128 / 128 | NIST-LWC finalist. A *block cipher* (GIFT-128, 40 rounds) in COFB mode, so the study is not comparing only sponges with each other. |
| **AES-128-CCM** | 128 / 96 / 128 | Not a finalist -- it is what constrained IoT actually runs: IEEE 802.15.4, Zigbee, Thread, BLE, DTLS-for-IoT. If Ascon replaces anything in a real warehouse, it replaces this. |

Four of the five are finalists Ascon beat in the NIST Lightweight Cryptography
process (2019-2023). The fifth is the incumbent. Between them they turn "Ascon
is a good choice for small IoT messages" from a citation into a measurement.

## 3. Implementation provenance -- what to say, and what not to say

Every one of the five is a **pure-Python implementation written for this
project** from the public specification. They are *not* the designers'
reference code and must never be described as such. What makes them usable as
measurement instruments is that each one reproduces the published test vectors
exactly:

| Algorithm | Validation | Vectors | Result |
|---|---|---|---|
| TinyJAMBU-128 | `third_party/lwc_kat/TinyJAMBU-128.txt` | 1089 | 1089 / 1089 |
| Xoodyak | `third_party/lwc_kat/Xoodyak.txt` | 1089 | 1089 / 1089 |
| Schwaemm256-128 | `third_party/lwc_kat/Schwaemm256-128.txt` | 1089 | 1089 / 1089 |
| GIFT-COFB | `third_party/lwc_kat/GIFT-COFB.txt` | 1089 | 1089 / 1089 |
| AES-128-CCM | differential testing against OpenSSL | 40 randomised cases per run | 0 mismatches |

Each vector file covers **every** combination of plaintext length 0-32 bytes
and associated-data length 0-32 bytes, so every padding and boundary path in
each implementation is exercised.

Vector provenance is recorded in `third_party/lwc_kat/PROVENANCE.json`:
repository `rweather/lwc-finalists`, commit
`77b23e672543df736bdcc8577590e8957fe0c58c`, with a SHA-256 for each file.

The measurement run refuses to start if any vector fails
(`scripts/run_extended_comparison.py`, step 1). A timing measurement of an
implementation that computes the wrong function measures nothing.

**Security status.** None of these implementations is constant-time, and the
pure-Python AES core in `src/lightweight/_aes_core.py` is table-driven and
therefore cache-timing vulnerable. They are measurement instruments, not
security components, and nothing in the project uses them to protect real data.
Say this in the report before anyone asks.

## 4. The implementation-tier rule

This is the single most important methodological idea in the extension, and the
thing to have ready if an examiner challenges the results.

| Tier | Algorithms | What a comparison inside it means |
|---|---|---|
| `pure-python` | Ascon-AEAD128, TinyJAMBU-128, Xoodyak, Schwaemm256-128, GIFT-COFB, AES-128-CCM | A comparison of **algorithms**: same language, same coding style, same harness. |
| `native-c` | AES-128-GCM (OpenSSL, AES-NI) | Comparing it with the tier above is a comparison of **implementations**, and of whether the CPU has an AES instruction. |

Consequences that the figures enforce automatically:

* Every CSV row carries a `tier` column.
* Same-tier series are solid lines; AES-128-GCM is dashed.
* The ranking figure (graph13) and the relative-speed figure (graph14)
  **exclude** AES-128-GCM entirely, and say on the figure why.
* AES-128-GCM is still measured and still plotted in the sweeps, because the
  report needs the deployment-reality data point -- it is simply never
  presented as an algorithm-level result.

What you may claim from cross-tier numbers: "on a gateway with AES-NI, an
optimised AES-GCM implementation is far faster than an interpreted Ascon
implementation." What you may not claim: "AES-GCM is a faster algorithm than
Ascon." On an 8-bit or Cortex-M node with no AES accelerator the ordering can
invert -- that is the entire premise of the NIST Lightweight Cryptography
process.

## 5. What the extension measures

| Metric | File | Implementation independent? |
|---|---|---|
| Encryption / decryption latency, with 95% CIs | `results/extended/summary_extended.csv` | no |
| Throughput (MB/s of payload) | same | no |
| Raw per-sample timings | `results/extended/raw_extended.csv` | no |
| Peak Python-heap allocation per operation | `results/extended/memory_extended.csv` | no, and not valid across tiers |
| Communication overhead (nonce + tag) | `results/extended/overhead_extended.csv` | **yes** |
| End-to-end secured-message rate on the project's own sensor traffic | `results/extended/workload_extended.csv` | no |
| Machine, interpreter, OpenSSL, algorithm parameters | `results/extended/environment_extended.json` | -- |

On memory: `tracemalloc` observes CPython heap allocations only. It cannot see
OpenSSL's C-side buffers, and a Python integer holding a 64-bit lane costs far
more than the lane itself. Treat `memory_extended.csv` as a *relative* indicator
within the pure-Python tier, and treat the specification's state sizes (Ascon
320 bits, Xoodyak 384, SPARKLE 384, TinyJAMBU 128, GIFT-128 128 plus key
schedule) as the figures that transfer to real hardware.

## 6. Methodology, inherited deliberately

`src/extended_benchmark.py` imports its timing primitives from
`src/benchmark.py` rather than re-implementing them, so both experiments share:

* the same warm-up policy;
* the same batching rule for operations faster than the clock can resolve, with
  the same "iterations means cryptographic operations, not recorded samples"
  accounting;
* the same garbage-collection handling inside the measured region;
* the same seeded shuffling of execution order across (algorithm, size,
  operation, repetition) cells, so thermal drift cannot favour one algorithm;
* the same 48-byte associated-data size.

Statistics are computed the same way too: a two-sided 95% Student-t confidence
interval, plus `between_run_stdev_ns`, which reports the spread of the
per-repetition means so a reader can see run-to-run variability rather than only
within-run variability.

## 7. Profiles and run time

| Profile | Iterations/cell | Repetitions | Sizes | Typical run time |
|---|---|---|---|---|
| `quick` | 20 | 3 | 3 | under a minute |
| `extended` (default) | 100 | 10 | 8 | roughly 10-20 minutes |
| `full` | 1000 | 10 | 8 | hours |

`extended` keeps all ten repetitions -- which is what the confidence intervals
are computed across -- and reduces only the number of operations inside each
repetition. Six interpreted ciphers at 1000 operations x 8 sizes x 10
repetitions x 2 directions is a multi-hour job; the default profile brings it
into a single sitting without weakening the statistics that matter.

## 8. Figures produced

| Figure | File | What it shows |
|---|---|---|
| 9 | `graph09_lw_encrypt_latency.png` | Encryption latency vs payload size, all seven algorithms |
| 10 | `graph10_lw_decrypt_latency.png` | Decryption latency vs payload size (includes tag verification) |
| 11 | `graph11_lw_encrypt_throughput.png` | Encryption throughput vs payload size |
| 12 | `graph12_lw_decrypt_throughput.png` | Decryption throughput vs payload size |
| 13 | `graph13_lw_small_message_ranking.png` | **Headline ranking at a 128-byte IoT payload, with 95% CIs** |
| 14 | `graph14_lw_ascon_relative_speed.png` | **How many times slower each lightweight algorithm is than Ascon, per size** |
| 15 | `graph15_lw_communication_overhead.png` | Overhead percentage and its nonce/tag composition |
| 16 | `graph16_lw_peak_memory.png` | Transient Python-heap use per operation (same tier only) |
| 17 | `graph17_lw_end_to_end_rate.png` | Secured messages per second on the real synthetic sensor traffic |
| 18 | `graph18_lw_multimetric_summary.png` | Normalised multi-metric matrix plus an explicitly arbitrary composite |

Figures 13 and 14 are the two to put on a slide. Figure 15 is the one whose
conclusion survives being moved to different hardware.

## 9. Honest limitations of the extension

1. **Interpreted timings are not embedded timings.** Everything in the
   pure-Python tier is roughly a thousand times slower than a C implementation
   would be. The *ordering* between algorithms is informative; the absolute
   microsecond values are a property of CPython on the measuring machine.
2. **Implementation effort is not equal across algorithms.** All five ports are
   straightforward reference-style code with no algorithm-specific optimisation,
   which is the fairest available baseline, but a heavily optimised
   implementation of any one of them could change its position.
3. **The comparison set is not parameter-matched.** TinyJAMBU-128 has a 64-bit
   tag and Schwaemm256-128 a 256-bit nonce. Rankings that ignore this are
   misleading, which is why every ranking figure annotates it.
4. **The five ports are not side-channel resistant** and are not intended to be.
   Ascon's suitability for masking -- a major reason NIST selected it -- is
   invisible to this kind of timing study.
5. **One machine, one interpreter, one workload family.** Repetitions,
   shuffling and confidence intervals bound the noise; they do not make the
   result portable to different hardware.

The natural next step, and the strongest thing to name as future work, is to
port this comparison to a real constrained device (ESP32, nRF52, STM32) using
each algorithm's reference C implementation and measure cycles, flash, RAM and
energy per message. That converts the weakest metric in this study into its
strongest.
