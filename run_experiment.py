"""
EP-PQC-001 blind runner.
Reads ONLY generator/challenges.json + policy files + evidence/authority_pubkey.json.
Does NOT read answer_key.sealed.json. Emits results/raw_decisions.json and ProofRecords.
"""
import json, os, sys, platform
from dataclasses import asdict
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "impl"))
from ep_pqc_core import (ExecutionProofVerifier, AuthorityEngine, ExecutionGateway,
                         Policy, b64d, sha256_hex)

HERE = os.path.dirname(os.path.abspath(__file__))
ch = json.load(open(os.path.join(HERE, "generator", "challenges.json")))
authpk = json.load(open(os.path.join(HERE, "evidence", "authority_pubkey.json")))
T0 = ch["eval_clock_T0"]
now_fn = lambda: T0

import kyber_py, dilithium_py, cryptography
ENV = {"python": platform.python_version(), "platform": platform.platform(),
       "cryptography": cryptography.__version__, "kyber_py": getattr(kyber_py, "__version__", "1.2.0"),
       "dilithium_py": getattr(dilithium_py, "__version__", "n/a"),
       "eval_clock_T0": T0}

policies = {p: Policy.load(os.path.join(HERE, "policy", p))
            for p in {c["policy_file"] for c in ch["cases"]}}
auth_engine = AuthorityEngine(set(ch["authorized_requesters"]), ch["key_custody"])
gateway = ExecutionGateway()          # ONE gateway: objective boundary ledger
used_nonces = set()                   # shared anti-replay state across the run
authority_pk = b64d(authpk["public_key_b64"])

os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
os.makedirs(os.path.join(HERE, "proofrecords"), exist_ok=True)

results = []
for case in ch["cases"]:
    pol = policies[case["policy_file"]]
    verifier = ExecutionProofVerifier(pol, auth_engine, authpk["level"], authority_pk,
                                      gateway, used_nonces, ENV, now_fn=now_fn)
    pr = verifier.evaluate(case["request"], case["bundle"])
    prd = asdict(pr)
    # flatten nested StageResult dataclasses
    for k in ("authority", "evidence", "constraint"):
        prd[k] = asdict(getattr(pr, k)) if hasattr(getattr(pr, k), "__dataclass_fields__") else prd[k]
    results.append({"case_id": case["case_id"], "decision": pr.decision,
                    "primary_reason": (pr.reason_codes[0] if pr.reason_codes else ""),
                    "reason_codes": pr.reason_codes, "gateway_status": pr.gateway_status,
                    "boundary_crossed": pr.boundary_crossed, "derived_algorithm": pr.derived_algorithm,
                    "policy_version": pr.policy_version, "record_hash": pr.record_hash})
    json.dump(prd, open(os.path.join(HERE, "proofrecords", f"proofrecord_{case['case_id']}.json"), "w"),
              indent=2, default=str)

raw = {"experiment": "EP-PQC-001", "environment": ENV,
       "challenges_sha256": sha256_hex(open(os.path.join(HERE,"generator","challenges.json"),"rb").read()),
       "policy_hashes": {p: policies[p].source_hash for p in policies},
       "authority_pubkey_sha256": authpk["public_key_sha256"],
       "n_cases": len(results),
       "boundary_crossings": gateway.boundary_crossings,
       "results": results}
json.dump(raw, open(os.path.join(HERE, "results", "raw_decisions.json"), "w"), indent=2)

print("ran", len(results), "cases")
print("boundary crossings (protected ops actually executed):",
      [b["request_id"] for b in gateway.boundary_crossings])
for r in results:
    print(f"  {r['case_id']:>16}  {r['decision']:<5}  crossed={int(r['boundary_crossed'])}  {r['primary_reason']}")
