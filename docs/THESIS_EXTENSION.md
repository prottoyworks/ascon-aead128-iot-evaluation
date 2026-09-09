# From proof-of-concept to senior thesis

How this project becomes **Phase 1** of a full crypto-agile, post-quantum-ready IoT
security thesis — and, specifically, which hooks already exist so that the extension is an
addition rather than a rewrite.

**Nothing described here is implemented. Do not implement it now.** This document exists so
your thesis proposal can point at concrete extension points in working code.

---

## 1. What Phase 1 already provides

```
   Sensor simulation            reproducible, seeded, per-device sequence numbers
 + Secure message structure     AAD / payload split, algorithm-labelled packet
 + AES-128-GCM                  OpenSSL-backed baseline
 + Ascon-AEAD128                conformance-verified against 1089 official vectors
 + AEAD / AAD handling          one abstract interface, two implementations
 + Replay protection            two-phase, strict and sliding-window policies
 + Benchmarking framework       randomised order, noise floor, separated setup costs
 + Security evaluation          nine defensive scenarios, both algorithms
 + Reproducibility              environment capture, upstream provenance, 180 tests
```

The load-bearing parts for what follows are the **abstract cipher interface**, the
**algorithm-labelled packet**, and the **cipher registry**.

---

## 2. The extension points that already exist

### 2.1 `CIPHER_REGISTRY` — the crypto-agility hook

```python
# src/receiver.py
CIPHER_REGISTRY: dict[str, type[AeadCipher]] = {
    ALG_AES_GCM: AesGcmCipher,
    ALG_ASCON:   AsconAead128Cipher,
}
```

Adding a third AEAD is **one line**. Nothing else in the receiver changes, because the
receiver holds only an `AeadCipher` reference. This is already exercised:
`tests/test_receiver.py::test_receiver_handles_both_algorithms_simultaneously` runs one
receiver serving one device over two algorithms concurrently.

That test is crypto-agility in miniature. Your thesis generalises it.

### 2.2 `SecurePacket.algorithm` — the negotiation field

The packet already carries an algorithm label, and the label's *effect* is already
authenticated: substituting it causes the receiver to select a different cipher, whose tag
verification then fails. `tests/test_security.py::test_g_cross_algorithm_ciphertext_is_rejected`
confirms an attacker gains nothing by swapping it.

For the thesis, promote this field into the AAD itself so the label is bound into the tag
directly, and add a version/suite identifier. That is the beginning of a proper cipher-suite
negotiation and downgrade-resistance argument.

### 2.3 `AeadCipher` — the uniform abstraction

Any future AEAD (Ascon-AEAD128 with different parameters, ChaCha20-Poly1305, AES-256-GCM)
implements the same five members and immediately works with the receiver, the security suite
*and* the benchmark harness. The comparison methodology extends for free.

### 2.4 The benchmark harness

Randomised execution order, separated setup costs, and the noise-floor measurement are
algorithm-agnostic. Adding ML-KEM key encapsulation as a new `operation` value requires no
change to the harness's timing discipline.

---

## 3. Phase 2 — post-quantum key establishment (ML-KEM)

**The problem Phase 1 leaves open.** Every key in this project is provisioned directly.
Real devices must *establish* keys, and the classical algorithms used for that (ECDH, RSA)
are broken by a sufficiently large quantum computer. "Harvest now, decrypt later" makes this
urgent for devices with 10-year deployment lifetimes — traffic captured today can be
decrypted once such a machine exists.

**ML-KEM** (FIPS 203, the standardised form of CRYSTALS-Kyber) is the NIST-selected
key-encapsulation mechanism. `[VERIFY CITATION]` for FIPS 203 details.

**What to build.** A key-establishment layer producing the 128-bit AEAD keys this project
currently generates directly:

```
Device                                    Gateway
  |                                            |
  |<--------------- ML-KEM public key ---------|
  |                                            |
  |-- Encapsulate -> (ciphertext, shared secret)|
  |----------------- ciphertext -------------->|
  |                                Decapsulate |
  |                                            |
  |=== shared secret -> KDF -> AEAD session key ===|
  |                                            |
  |------ Ascon-AEAD128 / AES-128-GCM -------->|   ← Phase 1, unchanged
```

**What to measure.** The interesting question is not "is ML-KEM fast?" but **how the
handshake cost amortises**: ML-KEM-768 public keys and ciphertexts are on the order of a
kilobyte, which is enormous next to a 32-byte sensor reading and possibly larger than an
entire LoRaWAN frame budget. Measure handshake latency, handshake bytes, and the rekeying
interval at which handshake cost exceeds cumulative per-message cost. That break-even point
is a genuinely publishable result for constrained IoT.

**Where it plugs in.** `NonceBudget` in `src/nonce.py` already enforces a rekey point.
Phase 2 gives that rekey somewhere to go.

---

## 4. Phase 3 — post-quantum authentication (ML-DSA)

**ML-DSA** (FIPS 204, standardised CRYSTALS-Dilithium) provides post-quantum digital
signatures. `[VERIFY CITATION]`.

AEAD gives *symmetric* authentication: anyone holding the key can both produce and verify.
That is fine for a point-to-point device–gateway link and useless for anything needing
non-repudiation or public verifiability — firmware images, device certificates, audit
records a third party must trust.

**What to measure.** Signature size is the crunch point. ML-DSA signatures are on the order
of a few kilobytes. For per-message signing on 32-byte payloads that is plainly impractical,
which makes the research question *where signatures belong in the architecture*: firmware
update authentication, device enrolment, gateway-to-cloud batch attestation — not the sensor
uplink. Quantify the boundary rather than asserting it.

---

## 5. Phase 4 — crypto-agility

**The real problem.** Deployed IoT devices outlive the cryptography they ship with. A
warehouse sensor installed today may still be running in 2038. Algorithms get deprecated;
devices that cannot migrate become permanent liabilities.

**What to build on Phase 1's foundation:**

1. **Algorithm negotiation** — device and gateway agree a cipher suite at session setup,
   with the negotiation itself authenticated so it cannot be downgraded
2. **Versioned suite identifiers** — the existing `protocol_version` field generalises into
   a suite ID covering AEAD, KEM and signature algorithm together
3. **Graceful migration** — a device supporting both an old and a new suite during a
   transition window
4. **Downgrade resistance** — an attacker who can strip suites from an offer must not be
   able to force the weakest option
5. **A capability model** — which suites a given device class can actually run

**What to measure.** Negotiation overhead, migration-window behaviour, and the cost of
carrying multiple implementations in constrained flash.

**Why Phase 1 makes this tractable.** The registry, the abstract interface and the
algorithm-labelled packet are exactly the three pieces a negotiation layer needs. Your thesis
proposal can say so and point at the tests.

---

## 6. Phase 5 — the full IoT → Gateway → Cloud architecture

Phase 1 models one hop. A real deployment has at least two, with different constraints on
each:

```
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│  IoT device  │        │   Gateway    │        │    Cloud     │
│              │        │              │        │              │
│ constrained  │──AEAD─>│ moderate     │──TLS──>│ unconstrained│
│ battery      │  hop 1 │ mains power  │ hop 2  │              │
│ Ascon?       │        │ aggregation  │        │ AES-GCM      │
└──────────────┘        └──────────────┘        └──────────────┘
```

**Research questions that only appear at this scale:**

- **Termination vs end-to-end.** If the gateway decrypts and re-encrypts, it becomes a
  point of compromise holding every device's plaintext. If encryption is end-to-end to the
  cloud, the gateway cannot filter, aggregate or rate-limit. This trade-off is the heart of
  the OSCORE/CoAP design debate. `[VERIFY CITATION]` — RFC 8613.
- **Algorithm asymmetry.** Should hop 1 use Ascon (constrained sender) and hop 2 use
  AES-GCM (accelerated hardware both ends)? Your crypto-agility layer makes this a
  configuration choice rather than an architecture rewrite.
- **Key management at scale.** Per-device keys at the gateway; rotation; revocation of a
  compromised device.
- **Gateway as an attack surface.** It holds many keys. Threat-model it explicitly.

---

## 7. Phase 6 — STRIDE threat modelling

Phase 1 tests six specific threats found by inspection. A thesis needs a *systematic* method,
so that coverage is argued rather than assumed.

| STRIDE category | Question for this architecture | Phase 1 status |
|---|---|---|
| **S**poofing | Can an attacker impersonate a device? | Addressed — AEAD authentication, tested |
| **T**ampering | Can a message be modified in transit? | Addressed — integrity, exhaustively tested |
| **R**epudiation | Can a device deny sending a message? | **Not addressed** — needs ML-DSA (Phase 3) |
| **I**nformation disclosure | What leaks? | Partly — payload encrypted, but AAD and traffic patterns are visible |
| **D**enial of service | Can an attacker exhaust the gateway? | Partly — pre-filter helps; no rate limiting |
| **E**levation of privilege | Can a device act beyond its role? | **Not addressed** — no authorisation model |

Writing this table honestly, with three "not addressed" rows, is stronger work than
claiming full coverage. Each gap becomes a thesis contribution.

Add a data-flow diagram, trust boundaries, and a mitigation-tracking table.

---

## 8. Phase 7 — hardware benchmarking

**This is what fixes Phase 1's principal limitation**, and it is the single most valuable
extension.

**The target.** An ARM Cortex-M microcontroller — M0+ for the genuinely constrained case,
M4 for a mid-range node. Critically: **no AES hardware acceleration**, which is exactly the
environment Ascon was designed for and exactly what a desktop x86 CPU cannot simulate.

**What changes:**

| Aspect | Phase 1 | Phase 7 |
|---|---|---|
| AES-GCM implementation | OpenSSL + AES-NI | Optimised C, software only |
| Ascon implementation | Pure-Python reference | Optimised C from `ascon-c` |
| Platform | Desktop x86-64 | Cortex-M, no crypto accelerator |
| Timing | `perf_counter_ns` | Hardware cycle counter (DWT) |
| Memory | Python-heap `tracemalloc` | Actual stack high-water mark, `.bss`/`.data` from the map file |
| Energy | Not measured | **Measured** — shunt resistor or a power-profiling probe |

**Why this changes the answer.** On a platform with no AES-NI, AES-GCM must compute the
S-box and GHASH in software. Ascon's permutation is bitsliced-friendly and needs no lookup
tables. The comparison may invert — and even if it does not, *the result will finally be
about the algorithms rather than about OpenSSL*.

**Energy is the metric that matters most** and is entirely absent from Phase 1. For a
battery sensor transmitting a few times an hour for five years, joules per message decides
deployability, and it is not simply proportional to latency: radio transmission usually
dominates, which is why the 4-byte nonce difference measured in Phase 1 may matter more
than any latency difference.

The `ascon-c` repository already vendored by `scripts/setup_ascon.py` contains the optimised
and masked C implementations you will need.

---

## 9. Phase 8 — the smart-warehouse case study

Turn the simulation into a scenario with stakes:

- **Assets**: cold-chain integrity, occupancy patterns, inventory, safety alarms
- **Actors**: operator, staff, maintenance contractor, competitor, opportunistic attacker
- **Attack scenarios**: replay of a "normal temperature" packet during a cold-chain failure;
  suppression of a gas alarm; traffic analysis revealing shift patterns and thus when the
  building is empty
- **Regulatory context**: food-safety cold-chain record-keeping requirements
  `[VERIFY CITATION]` for the relevant jurisdiction
- **Cost model**: device cost, battery replacement labour, cost of an undetected failure

This is what turns a benchmark into a thesis: the numbers acquire consequences.

---

## 10. Suggested thesis structure

```
1  Introduction
2  Literature review
   2.1  IoT security and constrained devices
   2.2  Authenticated encryption and AEAD
   2.3  Lightweight cryptography and the NIST LWC process
   2.4  Post-quantum cryptography: ML-KEM and ML-DSA
   2.5  Crypto-agility
3  Threat model (STRIDE)
4  System architecture: IoT -> Gateway -> Cloud
5  Phase 1: AEAD comparison            ← THIS PROJECT
6  Phase 2: Post-quantum key establishment
7  Phase 3: Post-quantum authentication
8  Phase 4: Crypto-agility framework
9  Phase 5: Hardware evaluation         ← fixes Phase 1's main limitation
10 Smart-warehouse case study
11 Results and discussion
12 Conclusion and future work
```

Chapter 5 is your current report, largely unchanged. Chapters 3, 4 and 9 are where the new
contribution lives — and Chapter 9 is what lets you finally answer the question this
proof-of-concept can only pose.
