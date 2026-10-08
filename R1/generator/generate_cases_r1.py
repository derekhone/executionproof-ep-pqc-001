"""
EP-PQC-001R1 test-case generator. Uses the IDENTICAL, UNMODIFIED enforcement engine
(../../impl/ep_pqc_core.py). Only the TEST DESIGN is corrected vs EP-PQC-001:

  R1-FIX-1 (PQC-04): requester set to the RSA key's authorized custodian (svc-vpn-gw) so
                     the authority stage passes and the EVIDENCE algorithm-mismatch path is
                     actually exercised (original run short-circuited at authority -> DENY).
  R1-FIX-2 (PQC-12): expected primary reason corrected to EVID_REQUEST_BINDING_MISMATCH,
                     the honest detection for cross-request replay (request-binding is the
                     dominant anti-replay control; it fires before nonce-binding).
  R1-ADD (PQC-17a/b): explicit nonce-consumption replay — identical signed evidence
                     resubmitted for the SAME request; second submission must be caught by
                     the consumed-nonce control (EVID_NONCE_REPLAY).

No change is made to the enforcement engine, invariants, or policy files.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "impl"))
from ep_pqc_core import (EvidenceAuthority, sha256_hex, b64e,
                         ML_KEM_512, ML_KEM_768, ML_KEM_1024)
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(__file__)
EVID = os.path.join(HERE, "..", "evidence")
os.makedirs(EVID, exist_ok=True)
T0 = 1_760_000_000; FRESH = T0 - 60; STALE = T0 - 7200
authority = EvidenceAuthority(level="ML-DSA-65")

def kem_pub(impl): ek,_=impl.keygen(); return ek
def rsa_pub_der(bits=2048):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
def ecdh_pub_der():
    k = ec.generate_private_key(ec.SECP256R1())
    return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

ART = {"KEY-KEM768-A": kem_pub(ML_KEM_768), "KEY-KEM768-B": kem_pub(ML_KEM_768),
       "KEY-KEM1024": kem_pub(ML_KEM_1024), "KEY-KEM512": kem_pub(ML_KEM_512),
       "KEY-RSA2048": rsa_pub_der(2048), "KEY-ECDH256": ecdh_pub_der()}

def manifest(aref, pub, nonce, rid, provider="kyber-py", version="1.2.0", issued_at=FRESH):
    return {"artifact_ref": aref, "artifact_sha256": sha256_hex(pub), "issued_at": issued_at,
            "nonce": nonce, "request_id": rid, "provider": provider, "version": version}
def bundle(aref, nonce, rid, provider="kyber-py", version="1.2.0", issued_at=FRESH, deliver_pub=None, sign_pub=None):
    deliver = deliver_pub if deliver_pub is not None else ART[aref]
    signed = sign_pub if sign_pub is not None else deliver
    m = manifest(aref, signed, nonce, rid, provider, version, issued_at)
    return {"manifest": m, "manifest_sig": authority.sign_manifest(m), "public_key_b64": b64e(deliver)}
def req(rid, requester, action, algo, pset, lib, ver, mode, aref, nonce, pver):
    return {"request_id": rid, "requester": requester, "action": action, "claimed_algorithm": algo,
            "claimed_param_set": pset, "claimed_library": lib, "claimed_version": ver, "mode": mode,
            "artifact_ref": aref, "evidence_ref": f"EVID-{rid}", "nonce": nonce, "policy_version": pver}

CASES = []
def add(cid, request, bndl, pol, dec, reason, rationale):
    CASES.append({"case_id": cid, "request": request, "bundle": bndl, "policy_file": pol,
                  "expected_decision": dec, "expected_primary_reason": reason, "rationale": rationale})
A="EP-PQC-POLICY-001-A.json"; B="EP-PQC-POLICY-001-B.json"

add("PQC-01", req("PQC-01","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n01",A),
    bundle("KEY-KEM768-A","n01","PQC-01"), A, "ALLOW","ALL_STAGES_PASS","Fully valid PQC request.")
add("PQC-02", req("PQC-02","svc-vpn-gw","kem-establish","RSA-2048","2048","kyber-py","1.2.0","pqc-only","KEY-RSA2048","n02",A),
    bundle("KEY-RSA2048","n02","PQC-02"), A, "HOLD","CONSTRAINT_LEGACY_ALGORITHM","Honest legacy RSA under PQC-required policy.")
add("PQC-03", req("PQC-03","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n03",A),
    {}, A, "HOLD","EVID_MISSING","No evidence supplied.")
# R1-FIX-1: requester is now the RSA key custodian so authority PASSES and evidence catches the false claim.
add("PQC-04", req("PQC-04","svc-vpn-gw","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-RSA2048","n04",A),
    bundle("KEY-RSA2048","n04","PQC-04"), A, "HOLD","EVID_ALGORITHM_CLAIM_MISMATCH",
    "Claims ML-KEM-768 but artifact independently derived as RSA-2048; authority passes (custodian correct) so EVIDENCE catches it.")
add("PQC-05", req("PQC-05","svc-unauthorized","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n05",A),
    bundle("KEY-KEM768-A","n05","PQC-05"), A, "DENY","AUTH_REQUESTER_NOT_AUTHORIZED","Unauthorized requester.")
good=ART["KEY-KEM768-A"]; tampered=bytes([good[0]^0x01])+good[1:]
add("PQC-06", req("PQC-06","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n06",A),
    bundle("KEY-KEM768-A","n06","PQC-06",deliver_pub=tampered,sign_pub=good), A, "HOLD","EVID_HASH_MISMATCH","Tampered key bytes.")
add("PQC-07", req("PQC-07","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n07",A),
    bundle("KEY-KEM768-A","n07","PQC-07",issued_at=STALE), A, "HOLD","EVID_STALE","Stale evidence.")
add("PQC-08", req("PQC-08","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n08",A),
    bundle("KEY-KEM768-B","n08","PQC-08"), A, "HOLD","EVID_ARTIFACT_BINDING_MISMATCH","Evidence for a different key.")
add("PQC-09", req("PQC-09","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n09",A),
    bundle("KEY-KEM768-A","n09","PQC-09"), A, "ALLOW","ALL_STAGES_PASS","Approved hybrid under policy A.")
add("PQC-10", req("PQC-10","svc-tls-frontend","kem-establish","ML-KEM-1024","1024","kyber-py","1.2.0","hybrid","KEY-KEM1024","n10",B),
    bundle("KEY-KEM1024","n10","PQC-10"), B, "HOLD","CONSTRAINT_HYBRID_NOT_PERMITTED","Hybrid under PQC-only policy B.")
add("PQC-11a", req("PQC-11a","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n11a",A),
    bundle("KEY-KEM768-A","n11a","PQC-11a"), A, "ALLOW","ALL_STAGES_PASS","Rollover pt1 under A.")
add("PQC-11b", req("PQC-11b","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n11b",B),
    bundle("KEY-KEM768-A","n11b","PQC-11b"), B, "HOLD","CONSTRAINT_ALGORITHM_NOT_ALLOWED","Rollover pt2 under B, fresh nonce.")
# R1-FIX-2: cross-request replay is honestly caught by request-binding first.
b12=bundle("KEY-KEM768-A","n-prev","PQC-PRIOR")
add("PQC-12", req("PQC-12","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n12",A),
    b12, A, "HOLD","EVID_REQUEST_BINDING_MISMATCH","Cross-request replay; request-binding is the dominant anti-replay control.")
add("PQC-13", req("PQC-13","svc-tls-frontend","kem-establish","ML-KEM-768","768","sketchy-pqc-lib","9.9.9","pqc-only","KEY-KEM768-A","n13",A),
    bundle("KEY-KEM768-A","n13","PQC-13",provider="sketchy-pqc-lib",version="9.9.9"), A, "HOLD","CONSTRAINT_UNTRUSTED_PROVIDER","Untrusted provider.")
add("PQC-14", req("PQC-14","svc-tls-frontend","kem-establish","ML-KEM-512","512","kyber-py","1.2.0","pqc-only","KEY-KEM512","n14",A),
    bundle("KEY-KEM512","n14","PQC-14"), A, "HOLD","CONSTRAINT_PARAM_DOWNGRADE","Parameter downgrade.")
add("PQC-15", req("PQC-15","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.0.0","pqc-only","KEY-KEM768-A","n15",A),
    bundle("KEY-KEM768-A","n15","PQC-15",version="1.0.0"), A, "HOLD","CONSTRAINT_VERSION_BELOW_MINIMUM","Version below minimum.")
add("PQC-16", req("PQC-16","svc-tls-frontend","kem-establish","ML-KEM-1024","1024","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n16",A),
    bundle("KEY-KEM768-A","n16","PQC-16"), A, "HOLD","EVID_ALGORITHM_CLAIM_MISMATCH","Substitution 1024 vs 768.")
# R1-ADD: nonce-consumption replay. 17a consumes the nonce (ALLOW); 17b replays the SAME
# signed evidence to the SAME request_id, so request-binding passes and the consumed-nonce control fires.
add("PQC-17a", req("PQC-17a","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n17",A),
    bundle("KEY-KEM768-A","n17","PQC-17a"), A, "ALLOW","ALL_STAGES_PASS","Valid request; consumes nonce n17.")
add("PQC-17b", req("PQC-17a","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n17",A),
    bundle("KEY-KEM768-A","n17","PQC-17a"), A, "HOLD","EVID_NONCE_REPLAY","Replay of identical evidence for the same request; nonce n17 already consumed.")

# negative controls (unchanged semantics)
add("NC-00-baseline", req("NC-00","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc00",A),
    bundle("KEY-KEM768-A","nc00","NC-00"), A, "ALLOW","ALL_STAGES_PASS","Unchanged baseline must ALLOW.")
add("NC-01-authority", req("NC-01","svc-unauthorized","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc01",A),
    bundle("KEY-KEM768-A","nc01","NC-01"), A, "DENY","AUTH_REQUESTER_NOT_AUTHORIZED","Only authority changed.")
add("NC-02-provider", req("NC-02","svc-tls-frontend","kem-establish","ML-KEM-768","768","sketchy-pqc-lib","1.2.0","pqc-only","KEY-KEM768-A","nc02",A),
    bundle("KEY-KEM768-A","nc02","NC-02",provider="sketchy-pqc-lib"), A, "HOLD","CONSTRAINT_UNTRUSTED_PROVIDER","Only provider changed.")
add("NC-03-policyversion", req("NC-03","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc03",B),
    bundle("KEY-KEM768-A","nc03","NC-03"), B, "HOLD","CONSTRAINT_ALGORITHM_NOT_ALLOWED","Only policy version changed.")
add("NC-04-freshness", req("NC-04","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc04",A),
    bundle("KEY-KEM768-A","nc04","NC-04",issued_at=STALE), A, "HOLD","EVID_STALE","Only freshness changed.")
add("NC-05-algorithm", req("NC-05","svc-tls-frontend","kem-establish","ML-KEM-512","512","kyber-py","1.2.0","pqc-only","KEY-KEM512","nc05",A),
    bundle("KEY-KEM512","nc05","NC-05"), A, "HOLD","CONSTRAINT_PARAM_DOWNGRADE","Only algorithm changed.")
add("NC-06-artifactbinding", req("NC-06","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc06",A),
    bundle("KEY-KEM768-B","nc06","NC-06"), A, "HOLD","EVID_ARTIFACT_BINDING_MISMATCH","Only artifact binding changed.")

challenges = {"experiment":"EP-PQC-001R1","eval_clock_T0":T0,"authority_level":"ML-DSA-65",
    "authorized_requesters":["svc-tls-frontend","svc-vpn-gw","ca-root-signer"],
    "key_custody":{"KEY-KEM768-A":"svc-tls-frontend","KEY-KEM768-B":"svc-tls-frontend","KEY-KEM1024":"svc-tls-frontend",
                   "KEY-KEM512":"svc-tls-frontend","KEY-RSA2048":"svc-vpn-gw","KEY-ECDH256":"svc-vpn-gw"},
    "cases":[{"case_id":c["case_id"],"request":c["request"],"bundle":c["bundle"],"policy_file":c["policy_file"]} for c in CASES]}
answer_key = {"experiment":"EP-PQC-001R1","expected":[{"case_id":c["case_id"],"expected_decision":c["expected_decision"],
    "expected_primary_reason":c["expected_primary_reason"],"rationale":c["rationale"]} for c in CASES]}
json.dump(challenges, open(os.path.join(HERE,"challenges.json"),"w"), indent=2)
json.dump(answer_key, open(os.path.join(HERE,"answer_key.sealed.json"),"w"), indent=2)
json.dump({"level":"ML-DSA-65","public_key_b64":b64e(authority.pk),"public_key_sha256":authority.pk_fpr},
          open(os.path.join(EVID,"authority_pubkey.json"),"w"), indent=2)
print("R1 cases:", len(CASES))
print("challenges.json sha256:", sha256_hex(open(os.path.join(HERE,'challenges.json'),'rb').read()))
print("answer_key.sealed.json sha256:", sha256_hex(open(os.path.join(HERE,'answer_key.sealed.json'),'rb').read()))
print("authority pubkey sha256:", authority.pk_fpr)
