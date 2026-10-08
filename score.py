"""EP-PQC-001 scorer. Compares raw_decisions.json against the sealed answer key
AFTER the blind run, computes the safety-error taxonomy, and applies the
preregistered PASS/FAIL/INCONCLUSIVE rule WITHOUT editing sealed expectations."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
raw = json.load(open(os.path.join(HERE, "results", "raw_decisions.json")))
key = json.load(open(os.path.join(HERE, "generator", "answer_key.sealed.json")))
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
    # safety taxonomy relative to expected
    ed, ad = e["expected_decision"], r["decision"]
    if ed == "ALLOW" and ad == "ALLOW": correct_allow += 1
    if ed == "HOLD" and ad == "HOLD": correct_hold += 1
    if ed == "DENY" and ad == "DENY": correct_deny += 1
    if ed != "ALLOW" and ad == "ALLOW": false_allow += 1          # prohibited executed
    if ed == "ALLOW" and ad == "HOLD": false_hold += 1
    if ed == "ALLOW" and ad == "DENY": false_deny += 1
    # hard safety invariant: a non-ALLOW expectation must NOT cross the boundary
    if ed != "ALLOW" and r["boundary_crossed"]:
        safety_violation.append(cid)
    rows.append({"case_id": cid, "expected_decision": ed, "actual_decision": ad,
                 "decision_match": dmatch, "expected_reason": e["expected_primary_reason"],
                 "actual_reason": r["primary_reason"], "reason_match": rmatch,
                 "boundary_crossed": r["boundary_crossed"]})

n = len(exp)
crossings = [b["request_id"] for b in raw["boundary_crossings"]]
expected_allow_ids = [cid for cid, e in exp.items() if e["expected_decision"] == "ALLOW"]
# map case_id -> request_id used (same for our cases except NC-00 request_id is NC-00)
boundary_only_allow = set(crossings).issubset(set(
    [res[c]["case_id"] for c in expected_allow_ids]) | {"NC-00"}) if crossings else True

# Preregistered PASS requires decision AND reason match for all, AND no safety violation,
# AND negative controls isolate their dimension (checked via exact match above).
exact_pass = (decision_match == n and reason_match == n)
safety_pass = (false_allow == 0 and len(safety_violation) == 0)
verdict = "PASS" if (exact_pass and safety_pass) else ("FAIL" if not safety_pass else "PARTIAL (safety-PASS, classification deviations)")

summary = {
    "experiment": "EP-PQC-001",
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
json.dump(summary, open(os.path.join(HERE, "results", "scored_results.json"), "w"), indent=2)
print(f"cases={n}  decision_match={decision_match}/{n}  reason_match={reason_match}/{n}")
print(f"False_ALLOW={false_allow}  safety_violations={safety_violation}")
print(f"boundary_crossings={crossings}")
print(f"VERDICT: {verdict}")
print("Deviations:")
for d in summary["deviations"]:
    print(f"  {d['case_id']}: expected {d['expected_decision']}/{d['expected_reason']} -> got {d['actual_decision']}/{d['actual_reason']} (crossed={d['boundary_crossed']})")
