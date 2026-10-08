# EP-PQC-001 — Pre-Execution Post-Quantum Cryptographic Policy Verification

ExecutionProof™ validation experiment, Remnant Fieldworks Inc. Software-only simulation using
**real** post-quantum cryptography (ML-KEM / FIPS 203 via `kyber-py`; ML-DSA / FIPS 204 via
`dilithium-py`; classical RSA/ECDH via `cryptography`).

## Result (preserved verbatim — never massaged)

| Run | Cases | Decision | Reason | False ALLOW | Safety violations | Verdict |
|---|---|---|---|---|---|---|
| EP-PQC-001 | 24 | 23/24 | 22/24 | 0 | none | **PARTIAL (safety-PASS)** |
| EP-PQC-001R1 | 26 | 26/26 | 26/26 | 0 | none | **PASS** |

Boundary crossings in both runs = exactly the expected-ALLOW cases. The two original deviations
were safe and traced to our own test design, not the engine. R1 re-used the **byte-identical
engine** (`impl/ep_pqc_core.py`, SHA-256 `506d8e0c…`) and fixed only the test design → clean PASS.

## Read this first

- **`src/EP-PQC-001_REPORT.md`** — full A–S report + final decision + one-sentence verdict.
  Rendered: `pdf/EP-PQC-001_REPORT.pdf`, `docx/EP-PQC-001_REPORT.docx`.
- `EP-PQC-001_PREREGISTRATION.md` + `R1/EP-PQC-001R1_PREREGISTRATION.md` — hash-sealed preregs.
- `results/scored_results.json` + `R1/results/scored_results.json` — official scored outcomes.
- `proofrecords/` + `R1/proofrecords/` — per-decision hashed ProofRecords (24 + 26).

## Reproduce

```bash
# original run (artifacts are generate-once-and-frozen; do NOT re-run the generator)
python3 run_experiment.py && python3 score.py
# remediation run
python3 R1/run_experiment_r1.py && python3 R1/score_r1.py
```

Environment: Python 3.11.6, `cryptography` 46.0.7, `kyber-py` 1.2.0, `dilithium-py`.

## Reproducibility & integrity

- **`verify_proofrecords.py`** — standalone, engine-independent ProofRecord verifier
  (stdlib only). Recomputes every `record_hash` from first principles and reconciles it
  with `results/raw_decisions.json` and `results/scored_results.json` for both runs.
  Run: `python3 verify_proofrecords.py` (exit 0 = PASS).
- **`HASHES.txt`** — consolidated SHA-256 manifest of every package file. Verify with
  `sha256sum -c HASHES.txt` or `python3 make_hashes.py --check`; regenerate with
  `python3 make_hashes.py`.
- **`requirements.txt`** + **`DEPENDENCIES.md`** — pinned environment; resolves the
  ML-DSA (`"dilithium_py":"n/a"`) recording gap to `dilithium-py==1.4.0` without editing
  frozen artifacts.
- **`ERRATA.md`** — disclosed, non-fatal label discrepancies surfaced by the verifier
  (all hashes and results intact).

## Honesty bounds

Software simulation (no HSM/TPM/live TLS). Blinding is procedural (single author), not third-party.
Uses — does not prove the security of — ML-KEM/ML-DSA. Policy profiles are **experimental**, not
CNSA 2.0 / FIPS compliance controls. No DOI/publication without Derek's explicit written GO.
