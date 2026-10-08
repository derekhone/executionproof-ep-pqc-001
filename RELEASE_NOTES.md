# Release notes

**Release title:**
`EP-PQC-001 v1.0.1 — Pre-Execution Post-Quantum Cryptographic Policy Verification`

**Tag:** `v1.0.1`  ·  **Date:** 2026-10-08  ·  **Status:** published (GitHub + Zenodo)

> **v1.0.1 is a documentation-only correction of v1.0.0.** It corrects the DOI terminology so the
> package unambiguously distinguishes the Zenodo **concept DOI** from each **version DOI**. **No**
> scientific artifact changed: the engine, preregistrations, policies, ProofRecords, raw results,
> scored results, and both verdicts (root = PARTIAL / safety-PASS; R1 = PASS) are byte-identical to
> v1.0.0. **v1.0.0 is preserved permanently** and remains publicly visible (GitHub tag `v1.0.0`,
> Zenodo version DOI `10.5281/zenodo.23248212`). See `CHANGELOG.md`.

---

## Summary

First public release of **EP-PQC-001**, a software-only ExecutionProof™ experiment testing whether a
pre-execution gateway can physically block a cryptographic operation when the system cannot
independently prove the operation satisfies a defined post-quantum cryptography (PQC) policy.

## Results (preserved verbatim)

- **EP-PQC-001 (root), 24 cases → PARTIAL (safety-PASS).** Decision 23/24, reason 22/24,
  **0 false ALLOW**, no safety-invariant violations. Two deviations (PQC-04, PQC-12) were **SAFE**
  (operation still blocked) and traced to **test-case design, not the enforcement engine**. Not
  reclassified, not softened.
- **EP-PQC-001R1 (remediation), 26 cases → PASS.** Decision 26/26, reason 26/26, **0 false ALLOW**.
  Re-used the **byte-identical** engine (`506d8e0c…`); only the test design was corrected and a
  nonce-replay pair (PQC-17a/17b) added.

## What's included

- Enforcement engine (`impl/ep_pqc_core.py`), identical across both runs.
- Two **experimental** policy profiles (transitional A; rollover B).
- Hash-sealed preregistrations for both runs (sealed before execution).
- Raw + scored results and per-decision hash-sealed ProofRecords (24 + 26).
- **Standalone** integrity verifier (`verify_proofrecords.py`, no engine import).
- Consolidated SHA-256 manifest (`HASHES.txt`) + generator (`make_hashes.py`).
- Pinned environment (`requirements.txt`, `DEPENDENCIES.md`).
- Full A–S report (`src/EP-PQC-001_REPORT.md`, plus PDF/DOCX).
- `ERRATA.md`, `INTEGRITY_AUDIT.md`.

## Integrity

- All 50 ProofRecords (24 root + 26 R1) self-verify and reconcile with raw + scored results.
- Engine SHA-256 `506d8e0c…`; root prereg `931508ea…`; R1 prereg `fce80a02…`;
  policy A `a1642a74…`; policy B `99663b47…`.
- Verify with `python3 verify_proofrecords.py` and `sha256sum -c HASHES.txt`.

## Disclosed erratum (non-fatal)

`R1/proofrecords/proofrecord_PQC-17b.json` has an internal `request_id` of `"PQC-17a"` (generator
typo). The record is otherwise correct (`HOLD` / `EVID_NONCE_REPLAY`) and its `record_hash` matches
the frozen `raw_decisions.json` row for PQC-17b exactly. The frozen artifact was **intentionally not
modified**, because editing a sealed ProofRecord would change its hash and break the evidence chain.
See `ERRATA.md`.

## Limitations

Software simulation only. **No** CNSA 2.0 compliance, **no** NIST certification, **no** claim of
quantum resistance of ExecutionProof, **no** production or defense readiness, **no** HSM/TPM/live-TLS
validation, and **no** third-party validation. Uses — does not prove the security of — ML-KEM/ML-DSA.
Policy profiles are experimental, not compliance controls. Blinding is procedural (single author).
See the README "Limitations" section.

## Citation & license

- Citation metadata: `CITATION.cff`. **Concept DOI: [10.5281/zenodo.23248211](https://doi.org/10.5281/zenodo.23248211)** (always latest); **v1.0.1 version DOI: [10.5281/zenodo.23248351](https://doi.org/10.5281/zenodo.23248351)** (current); **v1.0.0 version DOI: [10.5281/zenodo.23248212](https://doi.org/10.5281/zenodo.23248212)** (original, preserved).
- License: **Apache-2.0** for code (`LICENSE`) + **CC BY 4.0** for docs/data (`LICENSE-docs`); see `NOTICE`
  and `LICENSE_RECOMMENDATION.md` for rationale.
