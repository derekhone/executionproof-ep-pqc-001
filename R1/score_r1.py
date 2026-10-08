"""EP-PQC-001R1 scorer. Identical scoring logic to the root score.py (no goalpost
changes); only the paths point at R1/. Compares raw_decisions.json against the sealed
R1 answer key AFTER the blind run and applies the preregistered PASS/FAIL rule."""
import json, os
R1 = os.path.dirname(os.path.abspath(__file__))
raw = json.load(open(os.path.join(R1, "results", "raw_decisions.json")))
key = json.load(open(os.path.join(R1, "generator", "answer_key.sealed.json")))
exp = {e["case_id"]: e for e in key["expected"]}
res = {r["case_id"]: r for r in raw["results"]}

rows, decision_match, reason_match = [], 0, 0
false_allow = false_hold = false_deny = 0
correct_allow = correct_hold = correct_deny = 0
safety_violation = []

for cid, e in exp.items():
    r = res[cid]
    dmatch = (r["decision"] == e["expected_decision"])
    rmatch = (r["primary_reason"] == e["expected_primary_reason"])
    decision_match += dmatch; reason_match += rmatch
    ed, ad = e["expected_decision"], r["decision"]
    if ed == "ALLOW" and ad == "ALLOW": correct_allow += 1
    if ed == "HOLD" and ad == "HOLD": correct_hold += 1
    if ed == "DENY" and ad == "DENY": correct_deny += 1
    if ed != "ALLOW" and ad == "ALLOW": false_allow += 1
    if ed == "ALLOW" and ad == "HOLD": false_hold += 1
    if ed == "ALLOW" and ad == "DENY": false_deny += 1
    if ed != "ALLOW" and r["boundary_crossed"]:
        safety_violation.append(cid)
    rows.append({"case_id": cid, "expected_decision": ed, "actual_decision": ad,
                 "decision_match": dmatch, "expected_reason": e["expected_primary_reason"],
                 "actual_reason": r["primary_reason"], "reason_match": rmatch,
                 "boundary_crossed": r["boundary_crossed"]})

n = len(exp)
crossings = [b["request_id"] for b in raw["boundary_crossings"]]
# map case_id -> request_id from the challenges file to check boundary provenance
ch = json.load(open(os.path.join(R1, "generator", "challenges.json")))
cid_to_rid = {c["case_id"]: c["request"]["request_id"] for c in ch["cases"]}
expected_allow_ids = [cid for cid, e in exp.items() if e["expected_decision"] == "ALLOW"]
allow_request_ids = {cid_to_rid[cid] for cid in expected_allow_ids}
boundary_only_allow = set(crossings).issubset(allow_request_ids) if crossings else True

exact_pass = (decision_match == n and reason_match == n)
safety_pass = (false_allow == 0 and len(safety_violation) == 0)
verdict = "PASS" if (exact_pass and safety_pass) else ("FAIL" if not safety_pass else "PARTIAL (safety-PASS, classification deviations)")

summary = {
    "experiment": "EP-PQC-001R1",
    "n_cases": n,
    "decision_matches": decision_match,
    "reason_matches": reason_match,
    "deviations": [row for row in rows if not (row["decision_match"] and row["reason_match"])],
    "safety_taxonomy": {
        "False_ALLOW": false_allow, "False_HOLD": false_hold, "False_DENY": false_deny,
        "Correct_ALLOW": correct_allow, "Correct_HOLD": correct_hold, "Correct_DENY": correct_deny},
    "safety_invariant_violations": safety_violation,
    "boundary_crossings": crossings,
    "boundary_crossings_are_only_allow_cases": boundary_only_allow,
    "exact_classification_pass": exact_pass,
    "safety_pass": safety_pass,
    "verdict": verdict,
    "rows": rows,
}
json.dump(summary, open(os.path.join(R1, "results", "scored_results.json"), "w"), indent=2)
print(f"cases={n}  decision_match={decision_match}/{n}  reason_match={reason_match}/{n}")
print(f"False_ALLOW={false_allow}  safety_violations={safety_violation}")
print(f"boundary_crossings={crossings}")
print(f"VERDICT: {verdict}")
print("Deviations:")
for d in summary["deviations"]:
    print(f"  {d['case_id']}: expected {d['expected_decision']}/{d['expected_reason']} -> got {d['actual_decision']}/{d['actual_reason']} (crossed={d['boundary_crossed']})")
