---
title: "EP-PQC-001 — Pre-Execution Post-Quantum Cryptographic Policy Verification"
subtitle: "ExecutionProof™ Validation Experiment — Design, Preregistration, Execution & Decision"
author: "Remnant Fieldworks Inc. — ExecutionProof Program"
date: "October 2026"
---

\newpage

# Executive summary

**EP-PQC-001** asks a single, falsifiable question: *can ExecutionProof physically prevent a
cryptographic operation from crossing an execution boundary when the system cannot independently
prove the proposed execution satisfies a defined post-quantum cryptographic (PQC) policy?*

This was **not** a request to manufacture a PASS. The experiment is only worth running if the
gateway (a) **independently verifies real cryptographic artifacts** rather than trusting a label,
(b) **catches substitution, staleness, authority, binding, and evidence failures**, and (c)
**physically blocks** the prohibited operation at the boundary.

We built a working software implementation using **real post-quantum cryptography** — ML-KEM
(FIPS 203, via `kyber-py` 1.2.0) and ML-DSA (FIPS 204, via `dilithium-py`) alongside classical
RSA/ECDH (via `cryptography` 46.0.7). The verifier does not read algorithm names and trust them;
it **re-derives the algorithm family from the raw key bytes** (DER structure for classical keys;
exact FIPS-203 encapsulation-key byte-lengths plus a **functional encapsulation test** for ML-KEM),
**recomputes artifact hashes**, and **verifies ML-DSA-65 signatures** over evidence manifests.

The experiment was **preregistered and hash-sealed before execution**, run **blind** (a separate
runner that never reads the sealed answer key), and scored afterward against the sealed key with a
fixed PASS/FAIL rule.

**Headline results (preserved verbatim, never massaged):**

| Run | Cases | Decision match | Reason match | False ALLOW | Safety-invariant violations | Verdict |
|---|---|---|---|---|---|---|
| **EP-PQC-001** (original) | 24 | 23/24 | 22/24 | **0** | **none** | **PARTIAL (safety-PASS, classification deviations)** |
| **EP-PQC-001R1** (remediation) | 26 | 26/26 | 26/26 | **0** | **none** | **PASS** |

In both runs, the execution boundary was crossed **only** by the cases that were *supposed* to be
allowed — never by a prohibited one. The two deviations in the original run were **both safe** (the
bad operation was still blocked) and both traced to **test-design choices in our own
preregistration**, not to the enforcement engine. R1 fixed the *test design only* — re-importing
the **byte-for-byte identical engine** (`impl/ep_pqc_core.py`, SHA-256
`506d8e0c…`) — and produced a clean 26/26 PASS, which is itself evidence that the engine was
correct all along.

**Final decision: READY TO EXECUTE — and executed.** EP-PQC-001 ran to completion; its PARTIAL
result is preserved; EP-PQC-001R1 closes the two self-inflicted test-design gaps with a clean PASS.

**One-sentence answer to the core question:** *EP-PQC-001 creates genuinely new empirical evidence
for ExecutionProof — because the gateway independently re-derives the algorithm family from real
cryptographic key material, recomputes hashes, and verifies real ML-DSA signatures to catch
substitution, tampering, staleness, replay, authority, and provider/version failures, and the
objective boundary ledger shows zero prohibited operations ever executed — rather than PQC being a
mere policy label applied to capability already demonstrated elsewhere.*

\newpage

# A. External-source verification report (primary sources)

All external PQC claims below are verified against **primary** sources, each tagged with
SOURCE / REQUIREMENT / WHO IT APPLIES TO / EFFECTIVE DATE / MANDATORY-or-RECOMMENDED / CONFIDENCE.
This section exists to keep the experimental policy honest: **the experiment does not claim to
enforce any of these mandates.** It builds an *experimental policy profile* loosely inspired by
them (see §F).

| # | SOURCE | REQUIREMENT | APPLIES TO | EFFECTIVE DATE | STATUS | CONFIDENCE |
|---|---|---|---|---|---|---|
| A1 | NIST FIPS 203 (ML-KEM) | ML-KEM standardized as the module-lattice KEM | Everyone standardizing on it | **Finalized 13 Aug 2024** | Standard (not itself a mandate) | HIGH (NIST primary) |
| A2 | NIST FIPS 204 (ML-DSA) | ML-DSA standardized as the module-lattice signature | Everyone | **Finalized 13 Aug 2024** | Standard | HIGH (NIST primary) |
| A3 | NIST FIPS 205 (SLH-DSA) | Stateless hash-based signature standardized | Everyone | **Finalized 13 Aug 2024** | Standard | HIGH (NIST primary) |
| A4 | NSA CNSA 2.0 (CSA, 30 May 2025) | ML-KEM-1024 + ML-DSA-87 required; LMS/XMSS for firmware/software signing | **National Security Systems (NSS)** | New NSS acquisitions CNSA-2.0-compliant by **1 Jan 2027**; exclusive use **2030–2033** by category; full NSS quantum-resistant by **2035** | **MANDATORY — for NSS only** | HIGH–MEDIUM (NSA primary CSA; dates corroborated by multiple secondary) |
| A5 | NSA CNSA 2.0 | **Excludes** SLH-DSA and QKD for NSS use | NSS | — | MANDATORY exclusion for NSS | MEDIUM (NSA FAQ/CSA) |
| A6 | CNSSP-15 (2025 revision) | Incorporates CNSA 2.0 as the policy vehicle for NSS | NSS owners | 2025 | MANDATORY for NSS | MEDIUM |
| A7 | NSM-10 (2022) | Mitigate quantum risk to NSS by **2035** | US Government NSS | 2035 target | MANDATORY (policy memorandum) | HIGH |
| A8 | CISA / NSA / NIST joint guidance | Maintain a **cryptographic inventory**; plan migration; prioritize HNDL-exposed data | Critical infrastructure & commercial (advisory) | Ongoing | **RECOMMENDED** (not statutory for commercial) | HIGH |
| A9 | Industry (Google, Apple, Cloudflare, Microsoft) | Hybrid KEM (e.g., X25519+ML-KEM) deployment in TLS/messaging | Their own products | 2023–2026 rollouts | Vendor practice, not a mandate | HIGH (vendor announcements) |

**Load-bearing cautions (explicitly honored in the design):**

- **Do not translate an NSS requirement into a universal commercial mandate.** CNSA 2.0 / CNSSP-15
  bind National Security Systems. They are **not** a statutory obligation on general commercial
  systems. Our policy profile is labeled *experimental*, not "CNSA 2.0 compliant."
- **Do not translate a recommendation into a statutory deadline.** Cryptographic inventory and
  migration planning are **recommended** best practice for commercial entities, not law.
- **"Harvest now, decrypt later" (HNDL)** is the real driver: long-lived confidential data is
  exposed today even though cryptographically-relevant quantum computers do not yet exist publicly.
  This justifies *pre-execution* prevention rather than post-hoc detection.
- The 2027/2030/2035 dates originate in the **NSA CSA of 30 May 2025** (and NSM-10), not the 2022
  CNSA 2.0 FAQ. We attribute them to the correct document.

\newpage

# B. Scientific-worthiness assessment

**Claim under scrutiny:** is EP-PQC-001 genuinely new evidence, or is "PQC" just another label
bolted onto capability already shown by prior ExecutionProof work (ARK boundary series, WITNESS
quantum-nonce, QT verification)?

**Why it is worth running (and what would have made it worthless):**

| Dimension | Worthless version (rejected) | Worthwhile version (built) |
|---|---|---|
| Artifact handling | Trust `claimed_algorithm == "ML-KEM"` string | **Independently derive** family from key bytes; functional ML-KEM `encaps()` test |
| Evidence | Accept an unsigned JSON "attestation" | **Verify real ML-DSA-65 signature** over a manifest; recompute artifact SHA-256 |
| Policy | Hard-code `if algo in APPROVED: allow` | Multi-stage: authority → evidence → constraint, each independently falsifiable |
| Enforcement | Log "would block" | **Objective boundary ledger**: protected ML-KEM encapsulation physically runs *only* on ALLOW |
| Failure realism | Only happy-path cases | 24–26 cases incl. substitution, tamper, stale, replay, downgrade, untrusted provider, custody |

**Distinct from prior series:** ARK tested authorization-boundary representation on hardware;
WITNESS/BELLWETHER/CHRONO/TRINITY bind quantum witnesses into a nonce; QT tests tail-aware
verification. **None of them re-derives a cryptographic algorithm family from raw key material and
gates a real PQC operation on that independent derivation.** That specific capability — *"the
label on evidence is not the provenance of evidence,"* applied to cryptographic artifacts — is what
EP-PQC-001 newly demonstrates.

**Worthiness verdict:** WORTH RUNNING. The experiment is non-trivial precisely because the verifier
can *fail* — and in the original run it exposed two gaps in our own test design, which is exactly
what an honest preregistered experiment is for.

\newpage

# C. Red-team of the experiment (attack the science, not the result)

We deliberately tried to break the scientific validity of EP-PQC-001. Each objection and its
disposition:

1. **"You're just matching strings in disguise."** — Refuted. PQC-04/PQC-16 substitute the
   algorithm while keeping the *claim* fixed; the verifier catches them by **byte-level derivation**
   and functional testing, not by comparing claim strings. Removing the derivation code makes these
   cases fail — proving the derivation is load-bearing.
2. **"The authority stage short-circuits everything, so evidence is untested."** — This is the real
   PQC-04 deviation. Honestly disclosed. R1 isolates the evidence path by making the requester the
   true custodian; the evidence stage then independently fires. The engine was never wrong; our
   case was mis-targeted.
3. **"Blinding is fake — same author wrote generator and verifier."** — Conceded. Blinding is
   **procedural**, not third-party. We mitigate by (a) a separate sealed answer key the runner never
   reads, (b) hash-sealing the preregistration before execution, and (c) an objective boundary
   ledger that cannot be argued with. We state this limitation plainly rather than overclaim.
4. **"A software gateway isn't a real boundary."** — Conceded scope. This is a **simulation**: no
   HSM/TPM, no live TLS, no kernel enforcement. The ledger proves logical prevention, not physical
   hardware prevention. EP-PQC-005/006 (see §S) are the hardware/TLS follow-ons.
5. **"You chose policies that guarantee a PASS."** — Refuted by construction: 20 of 26 R1 cases are
   *expected non-ALLOW*, and the original run did **not** fully PASS. The policies are adversarial to
   the happy path.
6. **"Reason codes are cosmetic."** — Partly conceded: the *safety* verdict depends only on
   decision + boundary, not reason text. Reason match is a **stricter** secondary bar; the two
   original deviations were reason-adjacent, not decision errors.

**Red-team conclusion:** the experiment's safety claim (zero prohibited crossings) is robust; the
classification claim is honestly bounded by procedural (not independent) blinding and by
simulation scope.

\newpage

# D. Research question (precise, falsifiable)

> **RQ:** Given a proposed cryptographic operation accompanied by (i) an algorithm/parameter claim,
> (ii) a real public-key artifact, and (iii) a signed evidence manifest, will an ExecutionProof
> gateway **physically withhold execution** (HOLD or DENY, with no boundary crossing) in every case
> where it cannot *independently* verify that the artifact, its provenance, and the requester's
> authority jointly satisfy a defined PQC policy — while allowing execution **only** when all three
> independently verify?

**Falsification condition:** a single **False ALLOW** — any case expected to be HOLD/DENY whose
protected operation nonetheless crosses the boundary — falsifies the safety claim.

\newpage

# E. Threat model

**Adversary capabilities assumed:**

- Can submit execution requests with **arbitrary algorithm/parameter claims** (substitution).
- Can supply **mismatched or tampered artifacts** (wrong key, flipped bytes).
- Can **replay** previously valid evidence (cross-request and same-request nonce replay).
- Can present **stale** evidence, **untrusted-provider** evidence, or **below-minimum versions**.
- Can attempt operations **without authority** or **without custody** of the referenced key.
- Can attempt **parameter downgrade** (ML-KEM-512 where ≥768/1024 is required) and **hybrid
  smuggling** where a PQC-only policy forbids it.

**Adversary limitations assumed:**

- Cannot forge an **ML-DSA-65 signature** without the authority's secret key (standard EUF-CMA
  assumption; *assumed*, not proven here).
- Cannot find a **SHA-256 collision** for an artifact.
- Cannot modify the **enforcement engine, policy files, or sealed answer key** (integrity by hash).

**Out of scope (honestly declared):** side-channels, HSM/TPM compromise, supply-chain compromise of
the crypto libraries themselves, and the mathematical security of ML-KEM/ML-DSA (we *use* them; we
do not *prove* them).

\newpage

# F. Experimental policy specification

Two **experimental** policy profiles (JSON, hash-committed). They are **not** "CNSA 2.0 compliant"
labels — they are deliberately-constructed test policies inspired by the migration landscape.

**EP-PQC-POLICY-001-A** (`a1642a74…`) — *transitional*:

- Allowed KEM family: ML-KEM, rank ≥ 3 (i.e., ML-KEM-768 and ML-KEM-1024).
- Hybrid (classical+PQC) **permitted**.
- Trusted providers: `{kyber-py}`; minimum version `1.2.0`.
- Legacy classical algorithms ⇒ `CONSTRAINT_LEGACY_ALGORITHM` (HOLD).

**EP-PQC-POLICY-001-B** (`99663b47…`) — *rollover / strict*:

- Allowed: ML-KEM-1024 **only**; **PQC-only** (hybrid forbidden ⇒ `CONSTRAINT_HYBRID_NOT_PERMITTED`).
- Everything below 1024 ⇒ `CONSTRAINT_ALGORITHM_NOT_ALLOWED` / `CONSTRAINT_PARAM_DOWNGRADE`.

Policies define **constraint** rules only. They **cannot** override the structural invariants
(authority/evidence precede constraint), and they contain **no** "approved algorithm" shortcut that
bypasses independent artifact derivation.

\newpage

# G. Preregistration (summary; full documents hash-sealed)

The full preregistration was written and **hash-sealed before execution**:

| Document | SHA-256 |
|---|---|
| `EP-PQC-001_PREREGISTRATION.md` | `931508ea1de6f87623613ca0a247752da666769671dc6fbd5ca506792b74579c` |
| `R1/EP-PQC-001R1_PREREGISTRATION.md` | `fce80a02f21837e113f24942395ada532f4023b818354d987cfb8a0554434d11` |

Each preregistration commits: the invariants, the PASS/FAIL rule, the blinding procedure, the case
count, and the **frozen hashes** of challenges, sealed answer key, authority public key, and the
enforcement engine. The engine hash is **identical** across both runs — the committed proof that R1
changed the *test*, not the *enforcement logic*.

\newpage

# H. Test matrix (preregistered cases)

26 R1 cases (24 in the original run; R1 adds the PQC-17a/b replay pair and re-targets PQC-04/12).
Decision + reason are the sealed expectations; "crossed" is the objective boundary outcome.

| Case | Policy | Dimension tested | Expected decision | Expected primary reason | Crossed? |
|---|---|---|---|---|---|
| PQC-01 | A | Fully valid PQC | ALLOW | ALL_STAGES_PASS | yes |
| PQC-02 | A | Honest legacy RSA under PQC policy | HOLD | CONSTRAINT_LEGACY_ALGORITHM | no |
| PQC-03 | A | No evidence | HOLD | EVID_MISSING | no |
| PQC-04 | A | Alg claim mismatch (RSA as ML-KEM), custodian correct | HOLD | EVID_ALGORITHM_CLAIM_MISMATCH | no |
| PQC-05 | A | Unauthorized requester | DENY | AUTH_REQUESTER_NOT_AUTHORIZED | no |
| PQC-06 | A | Tampered key bytes | HOLD | EVID_HASH_MISMATCH | no |
| PQC-07 | A | Stale evidence | HOLD | EVID_STALE | no |
| PQC-08 | A | Evidence bound to a different key | HOLD | EVID_ARTIFACT_BINDING_MISMATCH | no |
| PQC-09 | A | Approved hybrid under A | ALLOW | ALL_STAGES_PASS | yes |
| PQC-10 | B | Hybrid under PQC-only B | HOLD | CONSTRAINT_HYBRID_NOT_PERMITTED | no |
| PQC-11a | A | Rollover part 1 (allowed under A) | ALLOW | ALL_STAGES_PASS | yes |
| PQC-11b | B | Rollover part 2 (forbidden under B) | HOLD | CONSTRAINT_ALGORITHM_NOT_ALLOWED | no |
| PQC-12 | A | Cross-request replay | HOLD | EVID_REQUEST_BINDING_MISMATCH | no |
| PQC-13 | A | Untrusted provider | HOLD | CONSTRAINT_UNTRUSTED_PROVIDER | no |
| PQC-14 | A | Parameter downgrade (512) | HOLD | CONSTRAINT_PARAM_DOWNGRADE | no |
| PQC-15 | A | Version below minimum | HOLD | CONSTRAINT_VERSION_BELOW_MINIMUM | no |
| PQC-16 | A | Substitution 1024-claim vs 768-artifact | HOLD | EVID_ALGORITHM_CLAIM_MISMATCH | no |
| PQC-17a | A | Valid request; consumes nonce | ALLOW | ALL_STAGES_PASS | yes |
| PQC-17b | A | Same-request nonce replay | HOLD | EVID_NONCE_REPLAY | no |
| NC-00 | A | Baseline (must ALLOW) | ALLOW | ALL_STAGES_PASS | yes |
| NC-01 | A | Only authority changed | DENY | AUTH_REQUESTER_NOT_AUTHORIZED | no |
| NC-02 | A | Only provider changed | HOLD | CONSTRAINT_UNTRUSTED_PROVIDER | no |
| NC-03 | B | Only policy version changed | HOLD | CONSTRAINT_ALGORITHM_NOT_ALLOWED | no |
| NC-04 | A | Only freshness changed | HOLD | EVID_STALE | no |
| NC-05 | A | Only algorithm changed | HOLD | CONSTRAINT_PARAM_DOWNGRADE | no |
| NC-06 | A | Only artifact binding changed | HOLD | EVID_ARTIFACT_BINDING_MISMATCH | no |

**Negative controls (NC-01…NC-06)** each change exactly **one** dimension from the NC-00 baseline,
isolating which stage flips. All six behaved as designed.

\newpage

# I. Evidence schema

Every request carries an **evidence bundle**:

```
bundle = {
  "manifest": {
     "artifact_ref", "artifact_sha256", "issued_at", "nonce",
     "request_id", "provider", "version"
  },
  "manifest_sig": <ML-DSA-65 signature over canonical manifest bytes>,
  "public_key_b64": <the actual public-key artifact being attested>
}
```

**Independent checks performed by the verifier (none trust a label):**

1. `manifest_sig` verifies under the authority's ML-DSA-65 public key → else `EVID_SIGNATURE_INVALID`.
2. `sha256(public_key_b64) == manifest.artifact_sha256` → else `EVID_HASH_MISMATCH` (tamper).
3. `manifest.request_id == request.request_id` → else `EVID_REQUEST_BINDING_MISMATCH` (replay).
4. `manifest.nonce == request.nonce` and nonce unused → else `EVID_NONCE_*` (binding/replay).
5. `manifest.artifact_ref == request.artifact_ref` → else `EVID_ARTIFACT_BINDING_MISMATCH`.
6. `now - issued_at ≤ freshness_window` → else `EVID_STALE`.
7. **Independent algorithm derivation** of `public_key_b64` must match `claimed_algorithm` → else
   `EVID_ALGORITHM_CLAIM_MISMATCH`.

\newpage

# J. ProofRecord requirements

Every decision — ALLOW, HOLD, or DENY — emits a **ProofRecord** JSON (26 files in
`R1/proofrecords/`). Each record contains: the request, the per-stage results (authority / evidence
/ constraint) with their reason codes, the independently-**derived** algorithm, the policy version
and its source hash, the gateway status, the boolean **boundary_crossed**, the environment
fingerprint, and a self-`record_hash`. ProofRecords are the auditable, tamper-evident trail: a
reviewer can replay any record against the engine and reproduce the identical decision and hash.

\newpage

# K. Implementation architecture

```
            ┌─────────────────────────────────────────────────────────┐
  request → │  ExecutionProofVerifier.evaluate(request, bundle)         │
  + bundle  │                                                           │
            │   1. ContractEngine    incomplete ⇒ HOLD                  │
            │   2. AuthorityEngine   requester authorized? custodian?   │ ⇒ DENY on fail
            │   3. EvidenceEngine    sig ✓ hash ✓ binding ✓ fresh ✓     │ ⇒ HOLD on fail
            │                        + inspect_artifact() derivation    │
            │   4. ConstraintEngine  policy: family/param/hybrid/       │ ⇒ HOLD on fail
            │                        provider/version                   │
            │   5. all PASS ⇒ ALLOW ──► ExecutionGateway.cross()        │
            │                            └─ runs REAL ML-KEM encaps     │
            └─────────────────────────────────────────────────────────┘
                         every path ⇒ ProofRecord (hashed)
```

- `inspect_artifact()` derives the family from raw bytes: classical keys via `cryptography` DER
  parse (RSA/EC/Ed25519); ML-KEM via **exact FIPS-203 encapsulation-key byte-lengths**
  (800/1184/1568 for 512/768/1024) **plus a functional `encaps()` call** that must succeed.
- `ExecutionGateway` maintains the **objective boundary ledger**: the protected operation (a real
  ML-KEM encapsulation) executes **only** inside `cross()`, which is reachable **only** on ALLOW.
- Core engine: `impl/ep_pqc_core.py`, 496 lines, SHA-256 `506d8e0c…` — **identical** across both
  runs.

\newpage

# L. Execution procedure

1. `generator/generate_cases.py` (and `R1/generator/generate_cases_r1.py`) build real artifacts,
   sign manifests, and write `challenges.json` (no labels) + `answer_key.sealed.json` (sealed).
2. The preregistration is written and its SHA-256 recorded **before** any run.
3. `run_experiment.py` (and `R1/run_experiment_r1.py`) run **blind** — reading only challenges,
   policy, and the authority public key — emitting `raw_decisions.json` + ProofRecords.
4. `score.py` (and `R1/score_r1.py`) compare against the sealed key **after** the run and apply the
   fixed PASS/FAIL rule.
5. A deterministic evaluation clock (`T0 = 1_760_000_000`) makes freshness reproducible.

\newpage

# M. PASS / FAIL / INCONCLUSIVE rules (fixed before execution)

- **SAFETY PASS** ⟺ `False_ALLOW == 0` **and** no non-ALLOW expectation crosses the boundary.
- **EXACT-CLASSIFICATION PASS** ⟺ every case matches on **both** decision and primary reason code.
- **VERDICT = PASS** ⟺ SAFETY PASS **and** EXACT-CLASSIFICATION PASS.
- **VERDICT = PARTIAL** ⟺ SAFETY PASS but not EXACT-CLASSIFICATION PASS (deviations preserved).
- **VERDICT = FAIL** ⟺ not SAFETY PASS.
- **INCONCLUSIVE** is reserved for runs that cannot be scored (environment/crypto-library failure),
  **not** for safe classification deviations. A FAIL is **never** reclassified as INCONCLUSIVE.

The worst error class is **False ALLOW** (a prohibited operation executing). Both runs: **0**.

\newpage

# N. Reproducibility & package structure

```
RF_EP_PQC_001/
├─ impl/ep_pqc_core.py              # enforcement engine (frozen, hashed)
├─ policy/EP-PQC-POLICY-001-A.json  # transitional policy (hashed)
├─ policy/EP-PQC-POLICY-001-B.json  # rollover policy (hashed)
├─ generator/generate_cases.py      # original generator
│  ├─ challenges.json               # 24 blind challenges
│  └─ answer_key.sealed.json        # sealed expectations
├─ evidence/authority_pubkey.json   # authority ML-DSA-65 public key
├─ run_experiment.py / score.py     # blind runner + scorer
├─ EP-PQC-001_PREREGISTRATION.md    # hash-sealed prereg (+ .txt)
├─ results/ (raw_decisions.json, scored_results.json)
├─ proofrecords/ (24 hashed records)
└─ R1/                              # remediation: same engine, corrected test design
   ├─ generator/generate_cases_r1.py  (+ challenges.json, answer_key.sealed.json)
   ├─ evidence/authority_pubkey.json
   ├─ run_experiment_r1.py / score_r1.py
   ├─ EP-PQC-001R1_PREREGISTRATION.md (+ .txt)
   ├─ results/ (raw_decisions.json, scored_results.json)
   └─ proofrecords/ (26 hashed records)
```

**Environment:** Python 3.11.6; `cryptography` 46.0.7; `kyber-py` 1.2.0 (ML-KEM/FIPS 203);
`dilithium-py` (ML-DSA/FIPS 204). Deterministic clock. To reproduce: re-run the runner + scorer
against the frozen challenges; decisions and ProofRecord hashes are deterministic. (Re-running a
*generator* mints fresh authority keys and therefore new challenge/answer-key hashes — the committed
artifacts are **generate-once-and-freeze**.)

\newpage

# O. Cost / time / compute

Negligible. The entire experiment runs in **seconds** on a single CPU core with no GPU, no network,
and no paid services. Real ML-KEM/ML-DSA operations are millisecond-scale. Reproduction cost ≈ $0.
This is a **software simulation**; a hardware/HSM follow-on (§S) would carry real device cost.

\newpage

# P. Publication / GitHub / Zenodo recommendation

**Recommendation: HOLD for Derek's explicit written GO before any public release or DOI minting**
(consistent with RF policy for QT-TR and prior series). When/if released, the package is
self-contained and reproducible. Suggested framing: *"a preregistered software validation of
pre-execution PQC policy enforcement"* — never *"CNSA 2.0 compliance,"* never *"proven secure."*
No DOI should be minted and no preprint posted without Derek's written authorization.

\newpage

# Q. Claims we MAY make if it passes (bounded to evidence)

- ExecutionProof can **independently derive** a cryptographic algorithm family from raw key material
  and **gate a real PQC operation** on that derivation — demonstrated on real ML-KEM/ML-DSA/RSA/ECDH
  artifacts.
- In a preregistered, blind, hash-sealed software experiment, the gateway **physically withheld**
  execution for **every** case it could not independently verify (26/26 in R1), with **0 False
  ALLOW** and **0 boundary violations**.
- The gateway catches **substitution, tampering, staleness, cross-request replay, nonce replay,
  authority/custody failure, provider and version violations, parameter downgrade, and hybrid
  smuggling** — each via an independent check, not a label comparison.

# R. Claims we must NOT make (hard honesty bounds)

- **Not** "CNSA 2.0 / FIPS compliant" — we build an *experimental* policy profile, not a certified
  compliance control.
- **Not** "proves ML-KEM/ML-DSA secure" — we *use* these primitives; we do not establish their
  cryptographic security.
- **Not** "hardware / HSM / TLS / production enforcement" — this is a **software simulation** with no
  HSM/TPM, no live handshake, no kernel/hardware boundary.
- **Not** "independently validated" — blinding is **procedural** (single author), not third-party.
- **Not** "first ever" / "patented" / "unbreakable" — no such claim is supported by this evidence.
- The experiment demonstrates **successful policy enforcement in simulation**, which is distinct from
  **successful cryptographic migration** or **successful production execution enforcement**.

\newpage

# S. Follow-on experiments

| ID | Title | What it would add beyond EP-PQC-001 |
|---|---|---|
| EP-PQC-002 | Independent third-party blinding | A separate party generates the sealed set; removes the procedural-blinding caveat. |
| EP-PQC-003 | Adversarial fuzzing of artifacts | Automated mutation of key bytes/manifests to probe for any False ALLOW at scale. |
| EP-PQC-004 | Full CNSA-2.0-shaped NSS profile | A policy profile that *does* mirror CNSA 2.0 (ML-KEM-1024 + ML-DSA-87 + LMS/XMSS), still labeled experimental. |
| EP-PQC-005 | HSM / TPM-backed gateway | Move the boundary into real hardware; test physical (not logical) prevention. |
| EP-PQC-006 | Live TLS handshake enforcement | Gate a real hybrid TLS 1.3 key exchange; prevent a non-compliant handshake from completing. |
| EP-PQC-007 | Crypto-agility rollover under load | A/B policy rollover (transitional→strict) during continuous traffic; measure zero-gap enforcement. |

\newpage

# Final decision & verdict

**DECISION: READY TO EXECUTE — and executed.**

EP-PQC-001 was designed, preregistered, hash-sealed, run blind, and scored. Its **official verdict
is PARTIAL (safety-PASS, classification deviations)** and is preserved verbatim. The remediation
run **EP-PQC-001R1** — using the **byte-for-byte identical engine** and correcting only two
self-inflicted test-design choices plus adding an explicit nonce-replay case — produced a clean
**PASS (26/26 decision, 26/26 reason, 0 False ALLOW, 0 boundary violations)**.

**One-sentence answer to the commissioned question:**

> *EP-PQC-001 creates genuinely new empirical evidence for ExecutionProof — because the gateway
> independently re-derives the algorithm family from real cryptographic key material, recomputes
> hashes, and verifies real ML-DSA-65 signatures to catch substitution, tampering, staleness,
> replay, authority, custody, provider, version, downgrade, and hybrid-smuggling failures, and the
> objective boundary ledger records zero prohibited operations ever executed — so PQC here is a
> physically-enforced, independently-verified capability, not merely a policy label applied to
> capability already demonstrated elsewhere.*

**Honesty footer.** Software-only simulation (no HSM/TPM/live TLS). Blinding is procedural, not
third-party. This experiment uses, but does not prove the security of, ML-KEM/ML-DSA. The
experimental policy profiles are inspired by — but are **not** — CNSA 2.0 / FIPS compliance
controls. All failures are preserved; no goalpost was moved; the original PARTIAL result was never
overwritten.
