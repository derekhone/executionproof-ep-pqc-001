# EP-PQC-001 — Errata (disclosed, non-fatal)

Surfaced by the standalone ProofRecord verifier (`verify_proofrecords.py`). These are
**cosmetic label discrepancies only**. In every case the decision, reason code, boundary
outcome, `record_hash`, and reconciliation with `results/raw_decisions.json` and
`results/scored_results.json` are **correct and intact**. Per RF doctrine, the frozen
artifacts are preserved verbatim (editing them would change their hashes) and the defects
are disclosed here rather than silently corrected.

## E-1 — Negative-control shorthand `request_id` (benign, by construction)

Files `proofrecord_NC-0X-*.json` (both root and R1) carry a short internal
`request_id` (`NC-00` … `NC-06`) while the file name and the scored `case_id` use the
descriptive form (`NC-00-baseline` … `NC-06-artifactbinding`). This is a naming shorthand,
not a collision: each NC file maps 1:1 to its scored row, and all hashes reconcile.
**Impact: none.** The verifier keys off the authoritative file name, so no case is hidden
or duplicated.

## E-2 — `proofrecord_PQC-17b.json` internal `request_id` typo (R1 only)

The R1 file `proofrecord_PQC-17b.json` has internal `request_id = "PQC-17a"` (a
copy-paste typo in the R1 generator); it should read `"PQC-17b"`. The record is otherwise
correct and is the intended replay case:

- decision = **HOLD**, reason = **`EVID_NONCE_REPLAY`**, `boundary_crossed = false`;
- its `record_hash` (`ce6292ca…`) is internally consistent and **matches** the frozen
  `results/raw_decisions.json` row for `PQC-17b` exactly;
- `results/scored_results.json` scores `PQC-17a` (ALLOW) and `PQC-17b` (HOLD) as two
  distinct rows, so scoring and the PASS verdict are unaffected.

**Impact: none on results, scoring, safety taxonomy, or hash-chain integrity.** The only
effect is that the label inside one JSON file disagrees with its file name. It is NOT
corrected in place because that would alter a frozen, hash-sealed R1 artifact.

### Correction forward (non-binding)

A future regeneration (a hypothetical R2) should set `request_id` from the case id at
emit time and source the ML-DSA version from `importlib.metadata` (see `DEPENDENCIES.md`).
No R2 is authorized or implied by this errata note.
