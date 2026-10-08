"""
EP-PQC-001 test-case generator.

Produces REAL cryptographic artifacts (synthetic/test keys only), signs evidence
manifests with a real ML-DSA-65 evidence authority, and emits:
  - generator/challenges.json      (requests + evidence bundles, NO expected labels)
  - generator/answer_key.sealed.json (expected decisions + rationale, committed separately)
  - evidence/authority_pubkey.json (authority public key the verifier will trust)

Blinding note: generator and verifier are separate programs; the verifier reads only
challenges.json and has no access to answer_key.sealed.json at decision time. This is
procedural separation, not third-party blinding (same author). Documented honestly.
"""
import json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl"))
from ep_pqc_core import (EvidenceAuthority, sha256_hex, b64e,
                         ML_KEM_512, ML_KEM_768, ML_KEM_1024)
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(__file__)
EVID = os.path.join(HERE, "..", "evidence")
os.makedirs(EVID, exist_ok=True)

# Deterministic evaluation clock so freshness tests are reproducible.
T0 = 1_760_000_000  # fixed Unix time for the experiment ("now")
FRESH = T0 - 60     # 1 minute old  -> within 3600s window
STALE = T0 - 7200   # 2 hours old   -> violates 3600s window

authority = EvidenceAuthority(level="ML-DSA-65")

# ---- real key material (synthetic/test only) ---------------------------------
def kem_pub(impl):
    ek, _dk = impl.keygen()
    return ek

def rsa_pub_der(bits=2048):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return k.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)

def ecdh_pub_der():
    k = ec.generate_private_key(ec.SECP256R1())
    return k.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)

ART = {
    "KEY-KEM768-A": kem_pub(ML_KEM_768),
    "KEY-KEM768-B": kem_pub(ML_KEM_768),
    "KEY-KEM1024":  kem_pub(ML_KEM_1024),
    "KEY-KEM512":   kem_pub(ML_KEM_512),
    "KEY-RSA2048":  rsa_pub_der(2048),
    "KEY-ECDH256":  ecdh_pub_der(),
}

def manifest(artifact_ref, pub_bytes, nonce, request_id, provider="kyber-py",
             version="1.2.0", issued_at=FRESH):
    return {
        "artifact_ref": artifact_ref,
        "artifact_sha256": sha256_hex(pub_bytes),
        "issued_at": issued_at,
        "nonce": nonce,
        "request_id": request_id,
        "provider": provider,
        "version": version,
    }

def bundle(artifact_ref, nonce, request_id, provider="kyber-py", version="1.2.0",
           issued_at=FRESH, deliver_pub=None, sign_pub=None):
    """deliver_pub = bytes actually shipped to verifier; sign_pub = bytes the manifest
    hash is computed over (defaults to deliver_pub). Differing them simulates tamper."""
    deliver = deliver_pub if deliver_pub is not None else ART[artifact_ref]
    signed = sign_pub if sign_pub is not None else deliver
    m = manifest(artifact_ref, signed, nonce, request_id, provider, version, issued_at)
    sig = authority.sign_manifest(m)
    return {"manifest": m, "manifest_sig": sig, "public_key_b64": b64e(deliver)}

def req(rid, requester, action, algo, pset, lib, ver, mode, artifact_ref, nonce, pver):
    return {"request_id": rid, "requester": requester, "action": action,
            "claimed_algorithm": algo, "claimed_param_set": pset, "claimed_library": lib,
            "claimed_version": ver, "mode": mode, "artifact_ref": artifact_ref,
            "evidence_ref": f"EVID-{rid}", "nonce": nonce, "policy_version": pver}

CASES = []  # (id, request, bundle, policy_file, expected_decision, expected_reason, rationale)
def add(cid, request, bndl, pol, dec, reason, rationale):
    CASES.append({"case_id": cid, "request": request, "bundle": bndl, "policy_file": pol,
                  "expected_decision": dec, "expected_primary_reason": reason, "rationale": rationale})

A = "EP-PQC-POLICY-001-A.json"
B = "EP-PQC-POLICY-001-B.json"
RQ = "svc-tls-frontend"

# ---- PQC-01: fully valid PQC request -> ALLOW
add("PQC-01",
    req("PQC-01","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n01",A),
    bundle("KEY-KEM768-A","n01","PQC-01"), A, "ALLOW", "ALL_STAGES_PASS",
    "Authorized requester, complete contract, approved algorithm, approved implementation, valid/fresh/bound evidence, constraints satisfied.")

# ---- PQC-02: legacy-only algorithm under PQC-required policy -> HOLD
add("PQC-02",
    req("PQC-02","svc-vpn-gw","kem-establish","RSA-2048","2048","kyber-py","1.2.0","pqc-only","KEY-RSA2048","n02",A),
    bundle("KEY-RSA2048","n02","PQC-02"), A, "HOLD", "CONSTRAINT_LEGACY_ALGORITHM",
    "Honest legacy RSA-2048 declaration; evidence consistent; constraint engine rejects legacy under PQC-required policy A.")

# ---- PQC-03: missing cryptographic evidence -> HOLD
r03 = req("PQC-03","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n03",A)
add("PQC-03", r03, {}, A, "HOLD", "EVID_MISSING",
    "Contract complete and requester authorized, but no manifest/signature/public-key evidence supplied.")

# ---- PQC-04: falsified algorithm declaration -> HOLD
add("PQC-04",
    req("PQC-04","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-RSA2048","n04",A),
    bundle("KEY-RSA2048","n04","PQC-04"), A, "HOLD", "EVID_ALGORITHM_CLAIM_MISMATCH",
    "Contract claims ML-KEM-768 but the supplied artifact is independently derived to be RSA-2048.")

# ---- PQC-05: unauthorized requester -> DENY
add("PQC-05",
    req("PQC-05","svc-unauthorized","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n05",A),
    bundle("KEY-KEM768-A","n05","PQC-05"), A, "DENY", "AUTH_REQUESTER_NOT_AUTHORIZED",
    "Cryptography technically valid, but requester is not in the authority registry; authority FAIL -> DENY.")

# ---- PQC-06: tampered evidence -> HOLD (deliver flipped bytes vs signed hash)
good = ART["KEY-KEM768-A"]
tampered = bytes([good[0] ^ 0x01]) + good[1:]
add("PQC-06",
    req("PQC-06","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n06",A),
    bundle("KEY-KEM768-A","n06","PQC-06", deliver_pub=tampered, sign_pub=good), A, "HOLD", "EVID_HASH_MISMATCH",
    "Evidence manifest signed over the original key; delivered key has one byte flipped -> recomputed hash != manifest hash.")

# ---- PQC-07: stale evidence -> HOLD
add("PQC-07",
    req("PQC-07","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n07",A),
    bundle("KEY-KEM768-A","n07","PQC-07", issued_at=STALE), A, "HOLD", "EVID_STALE",
    "Evidence was valid when issued but violates the 3600s freshness window at evaluation time.")

# ---- PQC-08: artifact mismatch -> HOLD (manifest bound to KEY-B, request names KEY-A)
b08 = bundle("KEY-KEM768-B","n08","PQC-08")       # manifest.artifact_ref = KEY-KEM768-B
add("PQC-08",
    req("PQC-08","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n08",A),
    b08, A, "HOLD", "EVID_ARTIFACT_BINDING_MISMATCH",
    "Evidence corresponds to approved key KEY-KEM768-B while execution requests KEY-KEM768-A.")

# ---- PQC-09: approved hybrid transition -> ALLOW (policy A permits hybrid)
add("PQC-09",
    req("PQC-09","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n09",A),
    bundle("KEY-KEM768-A","n09","PQC-09"), A, "ALLOW", "ALL_STAGES_PASS",
    "Hybrid classical+PQC transition expressly permitted by policy A; complete evidence; approved ML-KEM-768 PQC half.")

# ---- PQC-10: unauthorized hybrid under PQC-only policy B -> HOLD
add("PQC-10",
    req("PQC-10","svc-tls-frontend","kem-establish","ML-KEM-1024","1024","kyber-py","1.2.0","hybrid","KEY-KEM1024","n10",B),
    bundle("KEY-KEM1024","n10","PQC-10"), B, "HOLD", "CONSTRAINT_HYBRID_NOT_PERMITTED",
    "Hybrid mode presented where policy B requires PQC-only exclusive use; algorithm itself (ML-KEM-1024) is allowed, isolating the hybrid dimension.")

# ---- PQC-11: policy rollover (same config under A then B), fresh nonces, no cache
add("PQC-11a",
    req("PQC-11a","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n11a",A),
    bundle("KEY-KEM768-A","n11a","PQC-11a"), A, "ALLOW", "ALL_STAGES_PASS",
    "Rollover part 1: ML-KEM-768 hybrid is permitted under policy version A.")
add("PQC-11b",
    req("PQC-11b","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","hybrid","KEY-KEM768-A","n11b",B),
    bundle("KEY-KEM768-A","n11b","PQC-11b"), B, "HOLD", "CONSTRAINT_ALGORITHM_NOT_ALLOWED",
    "Rollover part 2: identical configuration is prohibited under later policy version B (768 withdrawn + hybrid withdrawn), evaluated fresh with a new nonce.")

# ---- PQC-12: replay -> HOLD (manifest bound to another request/nonce)
b12 = bundle("KEY-KEM768-A","n-prev","PQC-PRIOR")   # evidence bound to a prior request & nonce
add("PQC-12",
    req("PQC-12","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n12",A),
    b12, A, "HOLD", "EVID_NONCE_BINDING_MISMATCH",
    "Valid authorization/evidence from a prior request is replayed for a new request; manifest nonce/request binding does not match the new request. Predeclared HOLD (evidence binding failure).")

# ---- PQC-13: untrusted provider -> HOLD
add("PQC-13",
    req("PQC-13","svc-tls-frontend","kem-establish","ML-KEM-768","768","sketchy-pqc-lib","9.9.9","pqc-only","KEY-KEM768-A","n13",A),
    bundle("KEY-KEM768-A","n13","PQC-13", provider="sketchy-pqc-lib", version="9.9.9"), A, "HOLD", "CONSTRAINT_UNTRUSTED_PROVIDER",
    "Correct algorithm supplied by a provider/library outside the policy allow-list.")

# ---- PQC-14: parameter downgrade -> HOLD
add("PQC-14",
    req("PQC-14","svc-tls-frontend","kem-establish","ML-KEM-512","512","kyber-py","1.2.0","pqc-only","KEY-KEM512","n14",A),
    bundle("KEY-KEM512","n14","PQC-14"), A, "HOLD", "CONSTRAINT_PARAM_DOWNGRADE",
    "Valid ML-KEM family but parameter set ML-KEM-512 is below the policy-A minimum rank (768+).")

# ---- PQC-15: library version below minimum -> HOLD
add("PQC-15",
    req("PQC-15","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.0.0","pqc-only","KEY-KEM768-A","n15",A),
    bundle("KEY-KEM768-A","n15","PQC-15", version="1.0.0"), A, "HOLD", "CONSTRAINT_VERSION_BELOW_MINIMUM",
    "Approved algorithm/provider but library version 1.0.0 is below the policy minimum 1.2.0.")

# ---- PQC-16: algorithm substitution (wrong parameter family) -> HOLD
add("PQC-16",
    req("PQC-16","svc-tls-frontend","kem-establish","ML-KEM-1024","1024","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","n16",A),
    bundle("KEY-KEM768-A","n16","PQC-16"), A, "HOLD", "EVID_ALGORITHM_CLAIM_MISMATCH",
    "Contract claims ML-KEM-1024 but the supplied artifact is independently derived to be ML-KEM-768 (substitution).")

# =============================== NEGATIVE CONTROLS ============================
# Baseline = PQC-01. Each NC changes exactly ONE dimension from baseline.
add("NC-00-baseline",
    req("NC-00","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc00",A),
    bundle("KEY-KEM768-A","nc00","NC-00"), A, "ALLOW", "ALL_STAGES_PASS",
    "Control: unchanged baseline must still ALLOW.")
add("NC-01-authority",
    req("NC-01","svc-unauthorized","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc01",A),
    bundle("KEY-KEM768-A","nc01","NC-01"), A, "DENY", "AUTH_REQUESTER_NOT_AUTHORIZED",
    "Change ONLY requester authority -> decision must change (DENY).")
add("NC-02-provider",
    req("NC-02","svc-tls-frontend","kem-establish","ML-KEM-768","768","sketchy-pqc-lib","1.2.0","pqc-only","KEY-KEM768-A","nc02",A),
    bundle("KEY-KEM768-A","nc02","NC-02", provider="sketchy-pqc-lib"), A, "HOLD", "CONSTRAINT_UNTRUSTED_PROVIDER",
    "Change ONLY library/provider -> HOLD.")
add("NC-03-policyversion",
    req("NC-03","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc03",B),
    bundle("KEY-KEM768-A","nc03","NC-03"), B, "HOLD", "CONSTRAINT_ALGORITHM_NOT_ALLOWED",
    "Change ONLY policy version (A->B) -> HOLD (768 withdrawn under B).")
add("NC-04-freshness",
    req("NC-04","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc04",A),
    bundle("KEY-KEM768-A","nc04","NC-04", issued_at=STALE), A, "HOLD", "EVID_STALE",
    "Change ONLY evidence freshness -> HOLD.")
add("NC-05-algorithm",
    req("NC-05","svc-tls-frontend","kem-establish","ML-KEM-512","512","kyber-py","1.2.0","pqc-only","KEY-KEM512","nc05",A),
    bundle("KEY-KEM512","nc05","NC-05"), A, "HOLD", "CONSTRAINT_PARAM_DOWNGRADE",
    "Change ONLY algorithm/parameter set (768->512) -> HOLD.")
add("NC-06-artifactbinding",
    req("NC-06","svc-tls-frontend","kem-establish","ML-KEM-768","768","kyber-py","1.2.0","pqc-only","KEY-KEM768-A","nc06",A),
    bundle("KEY-KEM768-B","nc06","NC-06"), A, "HOLD", "EVID_ARTIFACT_BINDING_MISMATCH",
    "Change ONLY artifact/key binding -> HOLD.")

# ------------------------------------------------------------------------------
challenges = {
    "experiment": "EP-PQC-001",
    "eval_clock_T0": T0,
    "authority_level": "ML-DSA-65",
    "authorized_requesters": ["svc-tls-frontend", "svc-vpn-gw", "ca-root-signer"],
    "key_custody": {"KEY-KEM768-A": "svc-tls-frontend", "KEY-KEM768-B": "svc-tls-frontend",
                    "KEY-KEM1024": "svc-tls-frontend", "KEY-KEM512": "svc-tls-frontend",
                    "KEY-RSA2048": "svc-vpn-gw", "KEY-ECDH256": "svc-vpn-gw"},
    "cases": [{"case_id": c["case_id"], "request": c["request"], "bundle": c["bundle"],
               "policy_file": c["policy_file"]} for c in CASES],
}
answer_key = {
    "experiment": "EP-PQC-001",
    "expected": [{"case_id": c["case_id"], "expected_decision": c["expected_decision"],
                  "expected_primary_reason": c["expected_primary_reason"],
                  "rationale": c["rationale"]} for c in CASES],
}

with open(os.path.join(HERE, "challenges.json"), "w") as f:
    json.dump(challenges, f, indent=2)
with open(os.path.join(HERE, "answer_key.sealed.json"), "w") as f:
    json.dump(answer_key, f, indent=2)
with open(os.path.join(EVID, "authority_pubkey.json"), "w") as f:
    json.dump({"level": "ML-DSA-65", "public_key_b64": b64e(authority.pk),
               "public_key_sha256": authority.pk_fpr}, f, indent=2)

ch_bytes = open(os.path.join(HERE, "challenges.json"), "rb").read()
ak_bytes = open(os.path.join(HERE, "answer_key.sealed.json"), "rb").read()
print("cases:", len(CASES))
print("challenges.json sha256:", sha256_hex(ch_bytes))
print("answer_key.sealed.json sha256:", sha256_hex(ak_bytes))
print("authority pubkey sha256:", authority.pk_fpr)
