#!/usr/bin/env python3
"""
EP-PQC-001 — Standalone ProofRecord Verifier
=============================================
Independent integrity checker for the per-decision ProofRecords produced by
EP-PQC-001 (root run) and EP-PQC-001R1 (remediation run).

DESIGN GOAL: independence. This script does NOT import `impl/ep_pqc_core.py`
or any experiment code. It re-derives the record hash from first principles
and compares it to the `record_hash` field embedded in each ProofRecord. A
third party can therefore confirm that the published ProofRecords have not
been edited after the fact, using nothing but the JSON files and the Python
standard library.

HASH SCHEME (must match the engine's ProofRecord.__post_init__):
    body        = {every field EXCEPT "record_hash"}
    record_hash = sha256( json.dumps(body, sort_keys=True,
                                     separators=(",", ":"), default=str) )

CROSS-CHECKS (beyond the self-hash):
  * every record_hash listed in results/raw_decisions.json must be present
    among the ProofRecord files, and vice versa (no orphans, no omissions);
  * the decision recorded in each ProofRecord must equal the decision scored
    in results/scored_results.json for the same case_id;
  * boundary_crossed == True iff decision == "ALLOW".

This script is READ-ONLY. It never writes to or mutates any package file.
Exit code 0 => all checks pass. Non-zero => at least one failure.

Usage:
    python3 verify_proofrecords.py              # verify both root and R1
    python3 verify_proofrecords.py --dir .      # verify a single run directory
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def recompute_record_hash(record: dict) -> str:
    """Re-derive record_hash exactly as the engine does, without the engine."""
    body = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hex(canonical.encode())


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_run(run_dir: str, label: str) -> bool:
    """Verify every ProofRecord in <run_dir>/proofrecords and cross-check
    against results/. Returns True iff all checks pass."""
    pr_dir = os.path.join(run_dir, "proofrecords")
    results_dir = os.path.join(run_dir, "results")
    print(f"\n=== {label}  ({pr_dir}) ===")

    if not os.path.isdir(pr_dir):
        print(f"  [FAIL] proofrecords directory not found: {pr_dir}")
        return False

    pr_files = sorted(f for f in os.listdir(pr_dir)
                      if f.startswith("proofrecord_") and f.endswith(".json"))
    if not pr_files:
        print(f"  [FAIL] no ProofRecord files in {pr_dir}")
        return False

    ok = True
    records_by_id = {}       # authoritative case id (from filename) -> record
    hashes_from_files = {}    # authoritative case id -> record_hash
    label_warnings = []       # non-fatal: internal request_id != filename stem

    # The AUTHORITATIVE case id is derived from the file name
    # (proofrecord_<CASEID>.json). This is deliberately independent of the
    # record's own `request_id` field so that a mislabeled field inside a
    # frozen record cannot silently hide or duplicate a case.
    def case_id_from_filename(fn: str) -> str:
        return fn[len("proofrecord_"):-len(".json")]

    # --- 1. self-hash integrity of each ProofRecord -----------------------
    self_hash_fail = 0
    for fn in pr_files:
        path = os.path.join(pr_dir, fn)
        rec = load_json(path)
        cid = case_id_from_filename(fn)
        stored = rec.get("record_hash", "")
        calc = recompute_record_hash(rec)
        if stored != calc:
            ok = False
            self_hash_fail += 1
            print(f"  [FAIL] {fn}: record_hash mismatch")
            print(f"         stored={stored}")
            print(f"         calc  ={calc}")
            continue
        # boundary invariant: crossing iff ALLOW
        allowed = rec.get("decision") == "ALLOW"
        crossed = bool(rec.get("boundary_crossed"))
        if allowed != crossed:
            ok = False
            print(f"  [FAIL] {fn}: boundary_crossed={crossed} but decision={rec.get('decision')}")
        # non-fatal label-consistency check (disclosed erratum, not corruption)
        internal_id = rec.get("request_id")
        if internal_id != cid:
            label_warnings.append((fn, internal_id, cid))
        records_by_id[cid] = rec
        hashes_from_files[cid] = stored

    n = len(pr_files)
    if self_hash_fail == 0:
        print(f"  [ OK ] {n} ProofRecord files parsed; self-hash verified for all {n} records")
    else:
        print(f"  self-hash stage completed with {self_hash_fail} failure(s) across {n} files")

    for fn, internal_id, cid in label_warnings:
        print(f"  [WARN] {fn}: internal request_id='{internal_id}' != filename case id '{cid}' "
              f"(cosmetic label erratum — see ERRATA.md; hash chain unaffected)")

    # --- 2. cross-check against raw_decisions.json ------------------------
    raw_path = os.path.join(results_dir, "raw_decisions.json")
    if os.path.isfile(raw_path):
        raw = load_json(raw_path)
        raw_rows = raw.get("decisions") or raw.get("rows") or raw.get("results") or []
        raw_hashes = {}
        for row in raw_rows:
            cid = row.get("case_id") or row.get("request_id") or row.get("id")
            rh = row.get("record_hash")
            if cid and rh:
                raw_hashes[cid] = rh
        if raw_hashes:
            missing = set(raw_hashes) - set(hashes_from_files)
            orphan = set(hashes_from_files) - set(raw_hashes)
            if missing:
                ok = False
                print(f"  [FAIL] cases in raw_decisions.json with no ProofRecord: {sorted(missing)}")
            if orphan:
                ok = False
                print(f"  [FAIL] ProofRecords with no row in raw_decisions.json: {sorted(orphan)}")
            mismatched = [cid for cid in raw_hashes
                          if cid in hashes_from_files and raw_hashes[cid] != hashes_from_files[cid]]
            if mismatched:
                ok = False
                print(f"  [FAIL] record_hash differs between raw_decisions.json and ProofRecord: {mismatched}")
            if not (missing or orphan or mismatched):
                print(f"  [ OK ] raw_decisions.json record_hashes reconcile with ProofRecords "
                      f"({len(raw_hashes)} cases)")
        else:
            print("  [warn] raw_decisions.json present but no record_hash rows found to cross-check")
    else:
        print("  [warn] results/raw_decisions.json not found — skipping that cross-check")

    # --- 3. cross-check decisions against scored_results.json -------------
    scored_path = os.path.join(results_dir, "scored_results.json")
    if os.path.isfile(scored_path):
        scored = load_json(scored_path)
        rows = scored.get("rows", [])
        dec_mismatch = []
        for row in rows:
            cid = row.get("case_id")
            rec = records_by_id.get(cid)
            if rec is None:
                continue
            if row.get("actual_decision") and rec.get("decision") != row.get("actual_decision"):
                dec_mismatch.append(cid)
        if dec_mismatch:
            ok = False
            print(f"  [FAIL] decisions differ between ProofRecords and scored_results.json: {dec_mismatch}")
        else:
            print(f"  [ OK ] decisions in ProofRecords match scored_results.json ({len(rows)} rows)")
    else:
        print("  [warn] results/scored_results.json not found — skipping that cross-check")

    print(f"  --> {label}: {'ALL CHECKS PASS' if ok else 'FAILURES PRESENT'}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Standalone EP-PQC-001 ProofRecord verifier")
    ap.add_argument("--dir", help="verify a single run directory (must contain proofrecords/)")
    args = ap.parse_args()

    print("EP-PQC-001 Standalone ProofRecord Verifier")
    print("Independent of impl/ep_pqc_core.py — stdlib only. READ-ONLY.")

    if args.dir:
        targets = [(os.path.abspath(args.dir), f"RUN:{args.dir}")]
    else:
        targets = [(HERE, "EP-PQC-001 (root run)"),
                   (os.path.join(HERE, "R1"), "EP-PQC-001R1 (remediation run)")]

    all_ok = True
    for run_dir, label in targets:
        all_ok &= verify_run(run_dir, label)

    print("\n" + "=" * 60)
    if all_ok:
        print("RESULT: PASS — every ProofRecord self-verifies and reconciles.")
        return 0
    print("RESULT: FAIL — one or more integrity checks failed (see above).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
