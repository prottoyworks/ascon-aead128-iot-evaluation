# Report-writing guide

A chapter-by-chapter structure for the project report, with the specific traps that lose
marks in a cryptography evaluation.

**Two rules that override everything else in this document:**

1. **Never write a number you did not measure.** Every figure in your Results chapter must
   trace to a row in `results/`. If you cannot point to the file it came from, delete it.
2. **Never invent a citation.** Where you need a source you have not personally verified,
   write `[VERIFY CITATION]` and resolve it before submission. A fabricated reference is
   academic misconduct; an unresolved marker is a to-do item.

---

## Chapter 1 — Introduction (~1200–1800 words)

**1.1 Background: the Internet of Things.** What IoT deployments look like, the scale, the
class of device. Keep it short — the marker knows what IoT is.

**1.2 Why IoT security is distinctive.** Three pressures, developed properly: constrained
compute and energy; long deployment lifetimes with limited patching; physical accessibility
of devices. Contrast with a server, where none of these bind.

**1.3 Resource constraints and what they rule out.** Microcontroller RAM and clock budgets;
no AES hardware acceleration; battery life measured in years. This is the paragraph that
motivates lightweight cryptography — make it concrete, with real device classes, not
hand-waving. `[VERIFY CITATION]` for specific device specifications.

**1.4 Why encryption alone is insufficient.** The strongest paragraph you can write here:
a stream cipher without authentication lets an attacker flip a ciphertext bit and flip the
corresponding plaintext bit. Silently. A warehouse temperature of `24.75` becomes something
else and nothing detects it. This motivates AEAD better than any abstract definition.

**1.5 AEAD.** Confidentiality plus integrity plus authenticity in one primitive, with
associated data authenticated but not encrypted. Forward-reference §3 of your Methodology
for the split you actually used.

**1.6 AES-GCM.** NIST SP 800-38D. Counter mode plus GHASH. Ubiquitous in TLS 1.3, IPsec,
QUIC. Hardware-accelerated on essentially all modern general-purpose CPUs.

**1.7 Ascon and NIST SP 800-232.** Sponge-based permutation design. Selected in the NIST
Lightweight Cryptography process (2019–2023) and previously in the CAESAR portfolio.
Designed at TU Graz, Infineon and Radboud. Be careful and precise here about the
distinction between the **Ascon v1.2 competition candidates** (`Ascon-128`, `Ascon-128a`,
`Ascon-80pq`) and the **standardised Ascon-AEAD128** — they are different algorithms with
different IVs, rates and padding. Much of the older literature benchmarks the candidates.

**1.8 Motivation.** The gap: Ascon is now standardised, but published comparisons against
AES-GCM under controlled conditions on IoT-sized payloads, with the *final* standard, are
still limited. `[VERIFY CITATION]` — do the search before claiming a gap.

**1.9 Research question.** State it verbatim from the README.

**1.10 Objectives.** Numbered, each one testable:
1. Implement a simulated IoT channel using both AEAD schemes
2. Verify Ascon-AEAD128 conformance against official NIST SP 800-232 test vectors
3. Demonstrate confidentiality, integrity, authentication and replay resistance
4. Measure latency, throughput, memory and communication overhead across 32–4096 bytes
5. Analyse suitability for constrained IoT, bounded by the limitations of the setup

**1.11 Scope.** In: AEAD, simulated sensors, desktop Python, defensive tests. Out: ML,
IDS, blockchain, post-quantum, penetration testing, hardware. Say the out-of-scope items
are deferred to the thesis, and cross-reference.

---

## Chapter 2 — Literature review (~1500–2500 words)

Suggested themes. **Do not populate these with sources you have not read.**

| Theme | What to look for |
|---|---|
| IoT security landscape | Surveys of attack classes and deployment realities |
| Constrained-device cryptography | RAM/ROM/energy budgets; what fits |
| Authenticated encryption | The AEAD notion; why generic composition is error-prone |
| AES and GCM | FIPS 197; SP 800-38D; the nonce-reuse literature |
| NIST LWC process | Selection criteria, finalists, rationale for Ascon |
| Ascon | Original specification; the SP 800-232 standard |
| Prior AES vs Ascon benchmarking | **Check carefully which Ascon version each paper used** |
| Security/performance trade-offs | Energy cost of crypto on battery devices |

**The trap specific to this project.** Most Ascon benchmarking published before the
standard used **Ascon v1.2 candidates**, not Ascon-AEAD128. When you cite such a paper,
say which version it evaluated. Treating v1.2 results as SP 800-232 results is a
substantive error a knowledgeable examiner will spot immediately — and noticing it
yourself is worth marks.

**Second trap.** Papers reporting "Ascon is faster than AES" and papers reporting the
opposite are usually both correct — on different platforms. Platforms with AES-NI favour
AES; microcontrollers without it favour Ascon. If your review notes that pattern
explicitly, it becomes an argument rather than a list, and it sets up your own limitations
chapter perfectly.

End with a short synthesis: what is established, what is contested, what your study adds.

---

## Chapter 3 — Methodology (~2000–3000 words)

Draw heavily on `docs/METHODOLOGY.md`, but write it in your own words and in past tense.

**3.1 Research design.** Independent, dependent, controlled and uncontrolled variables.
The table in METHODOLOGY §1 transfers directly.

**3.2 Hardware and software environment.** **Copy the values from
`results/environment.json` — do not type them from memory.** CPU model, cores, RAM, OS
version, Python version, `cryptography` version, **OpenSSL version** (this one materially
affects the AES results), Ascon commit hash.

**3.3 Sensor simulation.** Fields, ranges, the random-walk model, the seed. Include the
§2 argument for why synthetic data is sufficient — that is a methodological argument, and
markers reward it.

**3.4 Serialisation.** Canonical JSON, sorted keys, no whitespace, UTF-8, fixed-decimal
rounding. Explain why determinism is *required*: the receiver must reconstruct the AAD
byte-for-byte to verify the tag.

**3.5 AAD design.** The table from README §3. Then the three explanations the brief asks
for, each in its own short paragraph:
- *Why AAD is not encrypted*: the gateway must route on `device_id` before it can decrypt
- *Why it is still authenticated*: it is absorbed into the AEAD state before the tag is
  computed
- *How modification causes failure*: the receiver recomputes the tag over the received AAD;
  a changed byte gives a different tag, and verification fails

**3.6 Key and nonce handling.** 128-bit keys from `os.urandom`. Random nonces: 96-bit for
AES-GCM per SP 800-38D, 128-bit for Ascon. The birthday-bound table. State explicitly that
the reproducibility seed never touches key or nonce generation, and why.

**3.7 The two implementations.** Library, API, version for each. For Ascon, the full
provenance chain: repository, commit, licence, and the conformance argument.

**3.8 Conformance testing.** What a KAT is; why round-tripping is insufficient; where the
vectors came from; that all 1089 matched.

**3.9 Security experiments.** The nine-scenario table. Emphasise that A is a control.

**3.10 Replay protection.** The two-phase design and the DoS it prevents. State clearly
that AEAD does not provide freshness and that this is a protocol-layer mechanism.

**3.11 Benchmark design.** Sizes, warm-up, iterations, repetitions, randomised order,
batching, GC handling, separated setup costs, the noise-floor measurement.

**3.12 Statistical analysis.** What was computed and why both mean and median.

**3.13 Reproducibility.** Seed, `environment.json`, `PROVENANCE.json`, lock file.

---

## Chapter 4 — Results (~1500–2500 words)

**Only measured values. No interpretation — that is Chapter 5.**

**4.1 Conformance.** One short paragraph and the numbers from `kat_results.csv`.
Establishes that what follows measures the right algorithm.

**4.2 Security-test outcomes.** Table from `security_results.csv`: algorithm, test, expected,
actual, trials, passed. Report exactly what happened.

**4.3 Encryption latency.** Table from `summary_results.csv` — mean, median, SD, 95% CI per
size — plus Figure 1. **State the harness noise floor** and identify which measurements sit
close to it.

**4.4 Decryption latency.** Same, Figure 2.

**4.5 Throughput.** MB/s and messages/second, Figures 3 and 4.

**4.6 Setup costs.** Key setup and nonce generation, reported separately with a sentence
explaining why they are not in §4.3.

**4.7 Memory.** Table and Figure 5, with the Python-heap caveat stated *in the section
itself*, not only in Chapter 6.

**4.8 Communication overhead.** Table and Figures 6 and 7. Highlight the 32-byte row: the
overhead is ~88% for AES-GCM and 100% for Ascon. That is a striking, structural result.

**4.9 Small-payload focus (32–512 bytes).** Figure 8. The brief asks for particular
attention here because it is the range that represents real sensor traffic.

**Writing discipline for this chapter.** "AES-128-GCM encrypted 256-byte messages with a
median latency of X µs" — a statement of fact. Not "AES-128-GCM was much faster, showing
its suitability" — that is Chapter 5, and the second clause is a conclusion you have not
yet earned.

---

## Chapter 5 — Cybersecurity analysis and discussion (~2000–3000 words)

**5.1 Confidentiality.** What was protected, from whom. Note that the AAD is deliberately
*not* confidential and what that leaks (which device is transmitting, and how often —
traffic analysis remains possible even with perfect encryption).

**5.2 Integrity.** Every single-bit modification detected across all tested positions.
Explain the mechanism: the tag is a function of key, nonce, AAD and ciphertext.

**5.3 Authentication.** Wrong-key rejection, including single-bit-different keys.

**5.4 The AEAD construction.** Why one primitive beats encrypt-then-MAC assembled by hand:
fewer ways to get it wrong, no key-separation mistakes, no ordering mistakes.

**5.5 AAD protection.** The `WH-001 → WH-999` result. Readable but not modifiable.

**5.6 Replay.** Your strongest discussion section, if you write it well. AEAD verifies a
replayed packet *perfectly* — the message genuinely was produced by the key holder and
genuinely was not altered. Freshness is a protocol property. Give the warehouse scenario:
an attacker rebroadcasting a captured "normal temperature" packet during a fire, with every
cryptographic check passing.

**5.7 Nonce management.** The catastrophic nature of GCM nonce reuse — keystream reuse *and*
GHASH subkey recovery. The birthday bounds. Why the 128-bit Ascon nonce is more comfortable,
and what those 4 extra bytes cost on the wire.

**5.8 Performance/security trade-offs.** Communication overhead versus payload size, and
what that means when a LoRaWAN frame budget is tens of bytes.

**5.9 IoT suitability.** Bounded conclusions only. Structural results (overhead, expansion,
security properties) generalise. Timing results characterise *these implementations in this
environment*. Say both, clearly.

---

## Chapter 6 — Limitations (~1000–1500 words)

Lead with the implementation gap. It is the most important thing in the report and putting
it first shows you understand your own experiment.

1. **Implementation gap** — OpenSSL/AES-NI versus pure-Python reference. Explain that a
   reference implementation is chosen for auditability, not speed. Explain that the platform
   has hardware AES acceleration and no hardware Ascon acceleration, and that this is
   precisely the case Ascon was *not* designed to win.
2. **Memory methodology** — `tracemalloc` sees Python allocations only.
3. **Synthetic sensor data** — sufficient for timing, insufficient for deployment claims.
4. **Desktop environment** — not a microcontroller.
5. **Python runtime** — an interpreter, not embedded C.
6. **No physical IoT device.**
7. **No energy or power measurement** — arguably *the* decisive metric for battery IoT, and
   entirely absent here.
8. **No physical network** — no loss, no jitter, no interference.
9. **No hardware-acceleration study** — AES-NI's contribution was not isolated.
10. **No side-channel analysis** — timing, power, EM all out of scope.
11. **Limited platform diversity** — one CPU family, one OS.
12. **No key establishment** — keys provisioned directly.
13. **Replay state is volatile** — does not survive a receiver restart.

For each: state it, explain why it matters, and say what a stronger design would do.

---

## Chapter 7 — Conclusion and future work (~800–1200 words)

**7.1 What was achieved.** Against your numbered objectives from §1.10, one by one.

**7.2 Answer to the research question.** Carefully bounded. A defensible shape:

> Both schemes provided the required authenticated-security properties in full: every
> tampering, forgery, wrong-key and truncation scenario was rejected, and replayed messages
> were rejected by the protocol-layer sequence check. The Ascon-AEAD128 implementation was
> confirmed conformant to NIST SP 800-232 against all 1089 official test vectors. In terms
> of communication overhead both schemes expand a message by a 16-byte tag, with Ascon
> requiring 4 additional bytes for its longer nonce — a difference that is negligible in
> absolute terms but reaches [X]% of payload at 32 bytes. In terms of latency, the
> measurements characterise the evaluated implementations rather than the algorithms: an
> OpenSSL-backed AES-GCM with hardware acceleration was compared against a pure-Python
> reference implementation, and the resulting difference cannot be attributed to algorithm
> design.

**7.3 Contribution.** A reproducible, conformance-verified comparison framework, with
provenance recorded and every measurement traceable to execution.

**7.4 Future work.** See `THESIS_EXTENSION.md`.

---

## Figures and tables

- Every figure needs a number, a caption, axis labels **with units**, and a legend
- Every figure caption must say where the data came from
  (*"Generated from `results/summary_results.csv`, run of [date], environment recorded in
  `results/environment.json`."*)
- Refer to every figure in the body text — an unreferenced figure is decoration
- Log axes need to be flagged in the caption; readers misjudge them otherwise
- Error bars need their meaning stated (here: 95% CI on the mean)

## Final checklist

- [ ] Every number traces to a file in `results/`
- [ ] No `[VERIFY CITATION]` markers remain
- [ ] Every citation corresponds to a source you have actually read
- [ ] No sentence claims one algorithm is universally faster
- [ ] The implementation gap appears in Abstract, Results, Discussion **and** Limitations
- [ ] Memory figures are described as Python-heap allocation everywhere they appear
- [ ] The harness noise floor is quoted in Results
- [ ] Ascon-AEAD128 is never confused with Ascon-128 / v1.2
- [ ] `environment.json` values match what you wrote in §3.2
- [ ] `pytest` passes on the final commit
- [ ] The conformance result appears before the performance results
