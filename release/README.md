# EP-PQC-001 — Pre-Execution Post-Quantum Cryptographic Policy Verification

**An ExecutionProof™ validation experiment · Remnant Fieldworks Inc.**

EP-PQC-001 is a **software-only** experiment that tests one narrow question:

> Can a pre-execution verification gateway **physically block** a cryptographic operation
> from crossing an execution boundary when the system **cannot independently prove** that the
> proposed operation satisfies a defined post-quantum cryptography (PQC) policy?

The gateway does **not** trust labels. For every request it independently re-derives the true
algorithm family from the **raw key bytes** (DER parsing for classical RSA/ECDH; exact FIPS-203
byte-lengths plus a functional `encaps()` probe for ML-KEM), recomputes artifact hashes,
verifies a **real ML-DSA-65** evidence-manifest signature, and checks authority, freshness,
binding, nonce single-use, and policy constraints. The protected operation (a real ML-KEM
encapsulation) runs **only** on an `ALLOW`.

This repository is for **scientific review and reproduction**. It is not a product, not a
compliance control, and not a security proof. See **Limitations** below — please read it before
citing or reusing anything here.

---

## Results (preserved verbatim — never massaged)

| Run | Cases | Decision match | Reason match | False ALLOW | Safety violations | Verdict |
|---|---|---|---|---|---|---|
| **EP-PQC-001** (root) | 24 | 23/24 | 22/24 | **0** | none | **PARTIAL (safety-PASS)** |
| **EP-PQC-001R1** (remediation) | 26 | 26/26 | 26/26 | **0** | none | **PASS** |

In **both** runs the only operations that crossed the execution boundary were **exactly** the
expected-`ALLOW` cases — there were **zero false ALLOWs** and **zero safety-invariant violations**.

### The root run is PARTIAL, and we say so plainly

EP-PQC-001 (root) did **not** achieve exact classification on every case. Two cases deviated
from their expected reason code:

- **PQC-04** — expected `HOLD` / `EVID_ALGORITHM_CLAIM_MISMATCH`; the engine returned
  `DENY` / `AUTH_CUSTODY_MISMATCH`. The requester was not the RSA custodian, so the **authority**
  stage short-circuited before the evidence stage could flag the false algorithm claim.
- **PQC-12** — expected `HOLD` / `EVID_NONCE_BINDING_MISMATCH`; the engine returned
  `HOLD` / `EVID_REQUEST_BINDING_MISMATCH`. Request-binding is checked before nonce-binding, so
  the earlier bound fired first.

**Both deviations were SAFE** — in each case the operation was still blocked (no boundary
crossing, no false ALLOW) — and **both traced to our own test-case design, not to the enforcement
engine.** We did not reclassify these as "inconclusive," and we did not move the goalposts. The
root verdict stands as **PARTIAL / safety-PASS**.

### R1 fixed the test design only — not the engine

EP-PQC-001R1 re-used the **byte-identical** enforcement engine
(`impl/ep_pqc_core.py`, SHA-256 `506d8e0c…`). The R1 generator **imports that same unmodified
engine**. Only the *test design* was corrected (route PQC-04 through the RSA custodian so the
evidence stage is reached; align PQC-12's expected reason with the documented check order; add a
PQC-17a/17b nonce-replay pair). The result was a clean **PASS (26/26, 26/26, 0 false ALLOW)**.
Because the engine bytes are identical across both runs, R1 demonstrates a test-design fix, **not**
a weakening of enforcement.

---

## What's in this repository

| Path | What it is |
|---|---|
| `impl/ep_pqc_core.py` | The enforcement engine (identical in both runs), SHA-256 `506d8e0c…` |
| `policy/EP-PQC-POLICY-001-A.json` | **Experimental** transitional profile (ML-KEM ≥ rank 3; hybrid permitted) |
| `policy/EP-PQC-POLICY-001-B.json` | **Experimental** rollover profile (ML-KEM-1024 only; PQC-only) |
| `EP-PQC-001_PREREGISTRATION.md` | Hash-sealed root preregistration (`931508ea…`), sealed **before** execution |
| `R1/EP-PQC-001R1_PREREGISTRATION.md` | Hash-sealed R1 preregistration (`fce80a02…`), sealed **before** R1 |
| `results/` · `R1/results/` | Raw decisions + scored results for both runs |
| `proofrecords/` · `R1/proofrecords/` | Per-decision, hash-sealed ProofRecords (24 + 26) |
| `verify_proofrecords.py` | **Standalone** integrity verifier — stdlib only, does **not** import the engine |
| `make_hashes.py` · `HASHES.txt` | Consolidated SHA-256 manifest generator + manifest |
| `requirements.txt` · `DEPENDENCIES.md` | Pinned, reproducible environment |
| `ERRATA.md` | Disclosed, non-fatal label discrepancies (see below) |
| `INTEGRITY_AUDIT.md` | Full post-gap-closure integrity audit |
| `src/EP-PQC-001_REPORT.md` (+ `pdf/`, `docx/`) | Full A–S report, final decision, one-sentence verdict |

---

## Reproduce

```bash
python3 -m pip install -r requirements.txt

# independent integrity check (no engine import; exit 0 = PASS)
python3 verify_proofrecords.py

# consolidated manifest check
python3 make_hashes.py --check        # or: sha256sum -c HASHES.txt

# re-run the experiments (artifacts are generate-once-and-frozen)
python3 run_experiment.py && python3 score.py          # root
python3 R1/run_experiment_r1.py && python3 R1/score_r1.py   # remediation
```

Pinned environment: **Python 3.11.6**; `kyber-py==1.2.0` (ML-KEM / FIPS 203);
`dilithium-py==1.4.0` (ML-DSA / FIPS 204); `cryptography==46.0.7` (classical RSA/ECDH).
Full environment record and the resolution of the earlier ML-DSA version-pin gap are in
`DEPENDENCIES.md`.

---

## Errata (disclosed, non-fatal)

The standalone verifier surfaces cosmetic label discrepancies that do **not** affect any
decision, reason code, hash, or verdict. The most notable:

- **`R1/proofrecords/proofrecord_PQC-17b.json`** carries an internal `request_id` of `"PQC-17a"`
  (a copy-paste typo in the R1 generator); it should read `"PQC-17b"`. The record is otherwise
  correct — decision `HOLD`, reason `EVID_NONCE_REPLAY` — and its `record_hash` matches the frozen
  `results/raw_decisions.json` row for PQC-17b **exactly**. Scoring treats PQC-17a and PQC-17b as
  two distinct rows, so the PASS verdict is unaffected.

**The frozen artifact was intentionally not modified**, because editing a sealed ProofRecord would
change its `record_hash` and break the evidence chain with `raw_decisions.json`. Under our standing
rule — *preserve sealed outputs; disclose rather than silently correct* — the defect is recorded in
`ERRATA.md` instead of being edited away. Full details: **`ERRATA.md`**.

---

## Limitations (read before citing)

EP-PQC-001 is a **bounded software experiment**. It demonstrates **software-only, pre-execution
verification of PQC-related artifacts under an experimental policy**, and nothing beyond that.

This work does **NOT**:

- claim **CNSA 2.0 compliance** — the policy profiles are experimental, not CNSA-2.0/CNSSP-15 controls;
- claim **NIST certification or validation** — it *uses*, but does not certify, FIPS 203/204 algorithms;
- **prove the cryptographic security** of ML-KEM or ML-DSA — it relies on them, it does not analyze them;
- claim **quantum resistance of ExecutionProof** itself — ExecutionProof is a verification/gating
  pattern, not a cryptographic primitive;
- involve any **HSM, TPM, secure enclave, or live TLS** — there is no hardware boundary and no live
  network handshake; the execution boundary is a software gateway;
- constitute **production readiness** — this is a research simulation, not a deployable control;
- constitute **defense readiness** or any national-security assurance;
- include **independent third-party validation** — blinding here is **procedural** (single author),
  not external.

Standards context (for background only): NIST finalized FIPS 203/204/205 on **13 Aug 2024**. NSA's
CNSA 2.0 (CSA, 30 May 2025) requires ML-KEM-1024 + ML-DSA-87 for **National Security Systems**, with
new NSS acquisitions compliant by **1 Jan 2027**, exclusive use **2030–2033**, and full NSS
quantum-resistance by **2035**. These timelines apply to NSS via CNSSP-15; they are **not** a
universal commercial mandate, and nothing in this repository should be read as asserting compliance
with them.

---

## Citation

See `CITATION.cff`. A DOI will be added here **only after** a Zenodo deposit is explicitly
authorized; until then no DOI exists for this work.

## License

License is **recommended but not yet finalized** — see `LICENSE_RECOMMENDATION.md`. Until a
`LICENSE` file is added to the repository, all rights are reserved by Remnant Fieldworks Inc.

---

*Remnant Fieldworks Inc. · ExecutionProof™ research program. ExecutionProof is a trademark of
Remnant Fieldworks Inc. Mention of FIPS, CNSA 2.0, NIST, or NSA is for standards context only and
does not imply endorsement, certification, or affiliation.*
