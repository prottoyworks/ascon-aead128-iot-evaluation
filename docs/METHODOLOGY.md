# Methodology

Why the experiment is structured the way it is. Written so that each design choice can be
defended in a viva, and so that a reader can identify what the experiment does *not*
establish.

---

## 1. Research design

**Type.** Controlled comparative experiment with a repeated-measures design.

**Independent variables**

| Variable | Levels |
|---|---|
| Algorithm | AES-128-GCM, Ascon-AEAD128 |
| Message size | 32, 64, 128, 256, 512, 1024, 2048, 4096 bytes |
| Operation | encrypt, decrypt |

**Dependent variables**

| Class | Measure |
|---|---|
| Primary | encryption latency, decryption latency, encryption throughput, decryption throughput, ciphertext size, tag overhead, wire overhead |
| Secondary | peak Python-heap allocation, key-setup latency, nonce-generation latency |
| Functional | accept/reject outcome for each of nine security scenarios |
| Conformance | agreement with 1089 official known-answer test vectors |

**Controlled variables.** Associated-data length is held at a constant 48 bytes across
every benchmark cell, so message size is the only thing varying along the size axis. Key
length is 128 bits for both. Tag length is 128 bits for both. The same machine, the same
Python process and the same interpreter run every cell.

**Uncontrolled variables**, acknowledged rather than hidden: operating-system scheduling,
CPU frequency scaling, thermal state, and background load. The randomised execution order
(§4) is what stops these from becoming *systematic* rather than merely noisy.

---

## 2. Why simulated sensor data is sufficient

Every dependent variable in this study is a function of input *length*, not input
*content*.

AES and Ascon both process data in fixed-size blocks with a fixed number of rounds. Neither
contains a data-dependent branch or a data-dependent memory access — that property is
exactly what makes them constant-time and therefore resistant to timing side channels. A
real 24.75 °C reading and a synthetic one of the same serialised length are cryptographically
indistinguishable in cost.

What simulation buys in return:

- an exact, reproducible message count fixed by a seed
- physically plausible values (a bounded random walk, not independent uniform draws, because
  real environmental sensors are strongly autocorrelated)
- monotonic per-device sequence numbers, which the replay logic depends on
- no privacy or ethics review, and no real personal data anywhere in the project

What it cannot support: any claim about real deployment conditions — duty cycles, radio
energy, packet loss, interference. No such claim is made.

---

## 3. Timing method

### The clock

`time.perf_counter_ns()`. It is monotonic (cannot go backwards when the system clock is
adjusted), offers the highest resolution the platform provides, and returns **integer**
nanoseconds so no floating-point rounding enters before aggregation.

`time.time()` would be wrong here: it is wall-clock, adjustable, and coarser.
`time.process_time()` would exclude time the process was descheduled, which sounds
attractive but would hide genuine latency that a real receiver would experience.

### What is inside the timed region

Only the cryptographic call. Every one of these happens **before** the clock starts:

- key generation, nonce generation
- plaintext and AAD generation
- for decryption, producing the ciphertext to be decrypted
- list allocation for results

And every one of these happens **after** it stops: CSV writing, statistics, graph
rendering, console output.

### Batching sub-microsecond operations

An OpenSSL AES-GCM call on a 32-byte message can complete in well under a microsecond.
Two problems follow:

1. `perf_counter_ns()` resolution on Windows is typically around 100 ns.
2. Calling the clock twice itself costs on the order of 50–100 ns.

Timing such an operation individually would produce a figure dominated by quantisation and
by the measurement apparatus. The harness therefore calibrates: it runs seven trial calls,
takes the median, and if it is below 20 µs it executes the operation in batches of 100 and
divides the elapsed time.

The trade-off is explicit: batching gives an unbiased mean but destroys per-call variance
information. `batch_size` is recorded in every raw row so no reader can mistake a batched
mean for a single-call sample. Ascon at the same message size takes hundreds of microseconds
and is never batched — and *that asymmetry is itself a finding worth reporting*.

### Warm-up

100 iterations are executed and discarded before every measured block. CPython specialises
bytecode on repeated execution, branch predictors need to warm, and OpenSSL may resolve
CPU-feature dispatch lazily. Including that transient would inflate the first samples of
whichever cell happened to run first.

### Garbage collection

`gc` is disabled across the measured region and restored afterwards. A collection cycle
triggered by unrelated allocation would land inside one sample and appear as a spurious
outlier attributable to nothing.

---

## 4. Execution order — the bias control that matters most

If every AES cell ran before every Ascon cell, then on a laptop that thermally throttles
partway through the run, whichever algorithm ran second would be systematically penalised.
The effect would look exactly like an algorithmic difference and would be invisible in the
results.

The harness therefore enumerates all `(algorithm, size, operation, repetition)` cells and
**shuffles them with a seeded RNG** before execution. The order is reproducible — the same
seed gives the same order — but it is uncorrelated with algorithm identity, so drift
affects both roughly equally and shows up as variance rather than bias.

`tests/test_benchmark.py::test_shuffling_interleaves_the_algorithms` asserts that the
shuffle actually interleaves rather than merely permuting within blocks.

---

## 5. Separating key and nonce costs

The brief requires this, and there is a substantive reason for it.

`AESGCM(key)` performs AES key expansion once, and a real IoT session then sends many
messages under that key — so constructing the object once and reusing it is the faithful
model. The pure-Python Ascon reference implementation has no cipher object at all; it
absorbs the key on every call.

If key setup were folded into per-message latency, AES would be charged for work it does
once per session while Ascon would be charged for work it does per message, and the two
numbers would not mean the same thing.

The harness therefore measures `keygen` and `noncegen` as **separate operations**, recorded
with `message_size = 0` so they can never be accidentally plotted on a latency-versus-size
curve. Both figures appear in the console summary and in `summary_results.csv`.

This asymmetry is real, it slightly favours AES-GCM, and it is reported rather than hidden.

---

## 6. The harness noise floor

Every timed sample contains, in addition to the cipher call: one Python function-call
frame, one loop step, and two `perf_counter_ns()` calls.

For Ascon at hundreds of microseconds this is negligible. For OpenSSL-backed AES-GCM at
around a microsecond it is **not** — it can be a meaningful fraction of the reported value.
Ignoring it would systematically inflate the faster algorithm's latency and understate its
throughput.

Two options existed. Silently subtracting a correction would be defensible but invisible to
a reader. Instead the harness **measures an empty callable through the identical code path**
and records it as `operation = harness_baseline`. `analyze_results.py` prints the floor and
draws it as a horizontal line on the latency figures.

This is the single most important honesty control in the experiment. It lets a reader
determine for themselves which measurements sit comfortably above the measurement limit of
the setup and which approach it. **Quote the floor in your Results chapter.**

---

## 7. Memory measurement, and its hard limit

`tracemalloc` is used, in a **separate pass** from the timing pass, because its
instrumentation adds large and uneven overhead to every allocation and would corrupt the
latency figures.

The limitation is fundamental and must be stated wherever the numbers appear:

> `tracemalloc` observes **Python heap allocations only**.

AES-GCM's real working memory — the key schedule, the GHASH tables, intermediate state — is
allocated inside OpenSSL's C code and is **completely invisible** to `tracemalloc`. What it
sees for AES-GCM is essentially just the output `bytes` object. The pure-Python Ascon
implementation, by contrast, allocates Python integers for its entire permutation state, all
of which `tracemalloc` sees.

**The two numbers are therefore not comparable as algorithm memory footprints.** They are
comparable as *"how much Python heap does this implementation churn"*, which is a real
property of the implementation but not of the algorithm.

Correct phrasing: *"peak Python-heap allocation observed in the evaluated implementation."*
Incorrect phrasing: anything mentioning RAM usage on an embedded device.

A defensible embedded memory comparison would require measuring stack and static allocation
of optimised C implementations cross-compiled for the target microcontroller. That is future
work.

---

## 8. Statistical analysis

Grouped by `(algorithm, message_size, operation)`. Reported per group:

| Statistic | Why |
|---|---|
| `samples` | Lets a reader compute their own intervals |
| `mean_ns` | Standard central tendency |
| `median_ns` | Robust to the right tail |
| `stdev_ns` | Sample standard deviation, `ddof=1` |
| `min_ns` | Closest observation to the true cost with no interference |
| `max_ns`, `p95_ns` | Characterise the tail |
| `ci95_*` | Precision of the estimated mean |

### Why both mean and median

Timing data on a general-purpose OS is **right-skewed**: a scheduler preemption, an
interrupt or a cache eviction lengthens a sample, but nothing can shorten it below the true
cost. The mean is pulled up by that tail; the median is not.

Where the two diverge sharply, the distribution is telling you the machine was busy. Report
both and say so. Quoting whichever is more flattering is exactly the kind of selective
reporting that makes a result indefensible.

### Confidence intervals

`mean ± t(0.975, n−1) · s/√n`, with the *t* critical value from a small embedded table
(`scipy` is deliberately not a dependency) falling back to the normal quantile 1.96 for
`df > 100`, where the difference is under 1%.

Note carefully what this interval means: it describes the precision of the estimated mean
**on this machine, in this run**. It says nothing about how the result transfers to other
hardware. A very tight interval on a badly-designed experiment is still a badly-designed
experiment.

### Throughput

Derived, never measured independently:

```
throughput (MB/s) = plaintext_bytes / latency_seconds / 10^6
messages/second   = 10^9 / latency_ns
```

Reporting throughput as a separate measurement would double-count the same samples. Median
latency is used for the headline throughput figure because it is robust to the tail; the
mean-derived value is also emitted.

---

## 9. Conformance testing

See README §7.3 for the full argument. In summary:

- A **round-trip test** proves self-consistency. An implementation with the wrong IV or
  round count round-trips perfectly with itself.
- A **known-answer test** proves conformance. Only it detects an implementation that is
  internally coherent but incompatible with the standard.

The vectors come from the Ascon team's official C reference implementation, an *independent*
implementation in a different language. Agreement on all 1089 vectors is strong evidence that
the Python code under test implements NIST SP 800-232 Ascon-AEAD128 and not one of the
superseded v1.2 candidates.

**If `tests/test_kat.py` fails, every Ascon measurement in the project is void.**

---

## 10. Security-experiment design

Nine scenarios per algorithm, each run over many independent trials with fresh random keys,
nonces and messages.

| ID | Scenario | Property |
|---|---|---|
| A | Valid message | Correctness (the control) |
| B | Ciphertext bit flipped | Payload integrity |
| C | AAD bit flipped | Metadata integrity |
| C2 | `device_id` `WH-001` → `WH-999` | Device-impersonation resistance |
| D | Wrong key | Authentication |
| E | Truncated ciphertext | Safe failure on malformed input |
| F | Tag bit flipped | Tag integrity |
| G | Wrong nonce | Nonce binding |
| H / I | Replay / stale sequence | Freshness (protocol layer) |

**Scenario A is not decoration.** Without a positive control, an implementation that
rejected *everything* would pass all eight negative tests. A is what makes the other eight
meaningful.

**Note the asymmetry in what these can show.** A single unexpected *acceptance* would be a
catastrophic finding. A run of rejections is consistent with a sound implementation but does
not prove one — absence of evidence within a finite trial count. Say this in your Discussion
rather than overclaiming.

`tests/test_security.py` goes further than the CSV suite: it exhausts *every* single-bit
flip position in the ciphertext, the tag and the AAD, and every truncation length, rather
than sampling randomly.

---

## 11. Replay-protection design

Two-phase, and the reason is a real attack.

`check()` is side-effect free and may run on unauthenticated data as a cheap pre-filter — it
can only reject. `commit()` mutates state and runs **only after** the AEAD tag verifies.

A single-phase design that committed on the pre-filter would let an attacker send one forged
packet claiming sequence `2147483647`; the counter would advance, and every subsequent
genuine message from that device would be rejected as stale. One packet, permanent denial of
service. `test_replay.py::test_forged_high_sequence_cannot_lock_out_a_device` and
`test_receiver.py::test_forged_high_sequence_does_not_lock_out_the_device` verify the
defence end to end.

Two policies are implemented. **Strict monotonic** is the default and is correct when the
transport preserves order. **Sliding window** (RFC 4303 / RFC 6347 style) tolerates
reordering within a window while still rejecting duplicates, which is what a real UDP-based
CoAP deployment needs. Both are tested against the same battery.

Neither survives a receiver reboot without persistent state, and neither bounds how *old* an
accepted message may be — that needs a timestamp or a challenge–response. State this in your
limitations.

---

## 12. Threats to validity

| Threat | Mitigation | Residual risk |
|---|---|---|
| Implementation gap dominates the comparison | Documented prominently; structural findings separated from timing findings | **High — this is the study's principal limitation** |
| Thermal/scheduling drift biases one algorithm | Seeded randomised execution order | Low |
| Harness overhead inflates fast operations | Noise floor measured and reported | Low |
| Clock resolution corrupts sub-µs timing | Calibrated batching, `batch_size` recorded | Low |
| GC pauses appear as outliers | GC disabled in the measured region | Low |
| Warm-up transient inflates early samples | 100 discarded warm-up iterations per block | Low |
| Key setup silently folded into latency | Measured as separate operations | None |
| Memory numbers misread as embedded RAM | Caveated in code, on the figure, in README and here | Medium — depends on the reader |
| Wrong Ascon variant used | Loader rejects non-SP-800-232 modules; 1089 KAT vectors verified | Very low |
| Synthetic data unrepresentative | Argued in §2; content-independence of the ciphers | Low for timing, high for deployment claims |
| Single hardware platform | None — acknowledged | **High for generalisation** |
