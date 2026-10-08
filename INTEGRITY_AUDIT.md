# EP-PQC-001 — Integrity Audit (post gap-closure)

**Date:** 2026-10-08 · **Scope:** close the three reproducibility gaps only; do not alter
root/R1 results, preregistrations, engine, policies, or scored outputs. **No DOI/publication**
without Derek's separate written GO.

## Gaps closed

| # | Gap | Resolution | Added file(s) |
|---|---|---|---|
| A | No standalone ProofRecord verifier | Engine-independent, stdlib-only verifier recomputes every `record_hash` and reconciles with raw + scored results for both runs | `verify_proofrecords.py` |
| B | No consolidated hash manifest | Reproducible SHA-256 manifest of all 83 files; verifiable with `sha256sum -c` or `make_hashes.py --check` | `HASHES.txt`, `make_hashes.py` |
| C | ML-DSA version recorded as `"n/a"` (unpinned) | Resolved to `dilithium-py==1.4.0` via distribution metadata; root cause documented; frozen records left verbatim | `requirements.txt`, `DEPENDENCIES.md` |

Plus `ERRATA.md` disclosing non-fatal label discrepancies the new verifier surfaced.

## Audit results (reproduced this run)

1. **Standalone verifier** — `python3 verify_proofrecords.py` → **PASS (exit 0)**.
   - Root run: 24/24 ProofRecords self-hash verified; record_hashes reconcile with
     `results/raw_decisions.json` (24 cases); decisions match `scored_results.json` (24 rows).
   - R1 run: 26/26 ProofRecords self-hash verified; reconcile (26 cases); decisions match (26 rows).
   - Boundary invariant (`boundary_crossed` iff ALLOW) holds for all 50 records.
2. **Manifest** — `sha256sum -c HASHES.txt` and `make_hashes.py --check` → **OK** (all files match).
3. **Frozen artifacts unchanged** (byte-identical to pre-closure):
   - engine `impl/ep_pqc_core.py` = `506d8e0c830f…`
   - root prereg = `931508ea1de6…` · R1 prereg = `fce80a02f218…`
   - `results/` + `R1/results/` scored & raw outputs, and `policy/*.json` all untouched.

## Preserved verdicts (never massaged)

- EP-PQC-001 (root): 24 cases, decision 23/24, reason 22/24, **False_ALLOW=0**, no safety
  violations → **PARTIAL (safety-PASS)**. Two deviations SAFE, traced to test design.
- EP-PQC-001R1: 26 cases, decision 26/26, reason 26/26, **False_ALLOW=0**, no safety
  violations → **PASS**.

## Disclosed errata (non-fatal — see ERRATA.md)

- E-1: NC ProofRecords use short internal `request_id` vs descriptive file/case id (benign).
- E-2: `R1/proofrecords/proofrecord_PQC-17b.json` internal `request_id="PQC-17a"` typo;
  decision (HOLD/`EVID_NONCE_REPLAY`), hash, and scoring all correct. Not edited in place to
  preserve the sealed R1 hash chain.

## Readiness determination

**GITHUB READY: YES.** Self-contained, reproducible, standalone verifier passes, consolidated
manifest present, dependencies pinned, honesty bounds and errata disclosed.

**ZENODO READY: YES, pending founder GO.** The package is technically complete and
self-verifying. Per standing rule, **no DOI will be minted and nothing will be published
without Derek's separate written GO.** Recommended pre-upload step: regenerate `HASHES.txt`
once more if any file is touched during repo setup (LICENSE/`.gitignore`), since those would
otherwise appear as untracked in `make_hashes.py --check`.
