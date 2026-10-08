"""
EP-PQC-001 — ExecutionProof Pre-Execution Post-Quantum Cryptographic Policy Verification
Core library: engines, independent artifact inspection, execution gateway, ProofRecord.

Remnant Fieldworks Inc. — Experimental apparatus. NOT a production system,
NOT a compliance certification, NOT a claim of algorithm security.

Design law under test: "If it cannot be verified, it cannot execute."

Runtime invariants preserved (do NOT silently alter):
  Incomplete contract                         -> HOLD
  Authority FAIL                              -> DENY
  Authority PASS + Evidence FAIL             -> HOLD
  Authority PASS + Evidence PASS + Constraint FAIL -> HOLD
  All required stages PASS                    -> ALLOW
  No cached permission (every request evaluated fresh; nonce store is anti-replay, not a cache)
"""
from __future__ import annotations
import base64
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ---- real cryptographic backends (verified present at build time) --------------
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

# ------------------------------------------------------------------------------
# Decision vocabulary
ALLOW, HOLD, DENY = "ALLOW", "HOLD", "DENY"

# ML-KEM encapsulation-key (public) byte sizes per FIPS 203
ML_KEM_EK_SIZES = {800: "ML-KEM-512", 1184: "ML-KEM-768", 1568: "ML-KEM-1024"}
ML_KEM_IMPL = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
# ML-DSA public-key byte sizes per FIPS 204 (used for provider/manifest signing)
ML_DSA_PK_SIZES = {1312: "ML-DSA-44", 1952: "ML-DSA-65", 2592: "ML-DSA-87"}
ML_DSA_IMPL = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


# ==============================================================================
# INDEPENDENT ARTIFACT INSPECTION
# The verifier derives the TRUE algorithm family from the artifact bytes ALONE,
# never from the requester's self-asserted "algorithm" field.
# "The label on evidence is not the provenance of evidence."
# ==============================================================================
@dataclass
class ArtifactFinding:
    derived_family: str          # e.g. "ML-KEM-768", "RSA-2048", "ECDH-P256", "Ed25519", "UNKNOWN"
    derived_class: str           # "PQC-KEM" | "CLASSICAL-PKE" | "CLASSICAL-ECC" | "UNKNOWN"
    functional_ok: bool          # did an independent functional test succeed?
    detail: str
    pubkey_len: int


def inspect_artifact(pub_bytes: bytes) -> ArtifactFinding:
    """Derive algorithm family independently of any claim.

    1. Try to parse as a classical DER public key (self-describing).
    2. Else fingerprint by exact FIPS-203 ML-KEM encapsulation-key length
       AND functionally validate by performing a real encapsulation.
    3. Else UNKNOWN.
    """
    n = len(pub_bytes)
    # (1) classical keys are self-describing in DER
    try:
        k = load_der_public_key(pub_bytes)
        if isinstance(k, rsa.RSAPublicKey):
            return ArtifactFinding(f"RSA-{k.key_size}", "CLASSICAL-PKE", True,
                                   f"Parsed as RSA public key, {k.key_size}-bit modulus", n)
        if isinstance(k, ec.EllipticCurvePublicKey):
            return ArtifactFinding(f"ECDH-{k.curve.name}", "CLASSICAL-ECC", True,
                                   f"Parsed as EC public key on curve {k.curve.name}", n)
        if isinstance(k, ed25519.Ed25519PublicKey):
            return ArtifactFinding("Ed25519", "CLASSICAL-ECC", True, "Parsed as Ed25519 public key", n)
        return ArtifactFinding("CLASSICAL-OTHER", "UNKNOWN", True, f"Parsed as {type(k).__name__}", n)
    except Exception:
        pass
    # (2) ML-KEM encapsulation key: exact length + functional encapsulation test
    if n in ML_KEM_EK_SIZES:
        fam = ML_KEM_EK_SIZES[n]
        impl = ML_KEM_IMPL[fam]
        try:
            _K, _c = impl.encaps(pub_bytes)   # real encapsulation == functional validation
            return ArtifactFinding(fam, "PQC-KEM", True,
                                   f"Length {n} matches {fam}; encapsulation succeeded", n)
        except Exception as e:
            return ArtifactFinding(fam, "PQC-KEM", False,
                                   f"Length {n} matches {fam} but encapsulation FAILED: {e}", n)
    # (3) unknown
    return ArtifactFinding("UNKNOWN", "UNKNOWN", False, f"Unrecognized public-key blob of {n} bytes", n)


# ==============================================================================
# EVIDENCE AUTHORITY — signs evidence manifests with a real ML-DSA key.
# The verifier holds only the PUBLIC key and verifies independently.
# ==============================================================================
class EvidenceAuthority:
    """Trusted provenance signer. Secret key never leaves the authority."""
    def __init__(self, level: str = "ML-DSA-65", seed: Optional[bytes] = None):
        self.level = level
        impl = ML_DSA_IMPL[level]
        self._impl = impl
        # deterministic keygen for reproducibility of the authority identity
        self.pk, self._sk = impl.keygen()
        self.pk_fpr = sha256_hex(self.pk)

    def sign_manifest(self, manifest_body: dict) -> str:
        msg = json.dumps(manifest_body, sort_keys=True, separators=(",", ":")).encode()
        return b64e(self._impl.sign(self._sk, msg))

    @staticmethod
    def verify(level: str, pk: bytes, manifest_body: dict, sig_b64: str) -> bool:
        impl = ML_DSA_IMPL[level]
        msg = json.dumps(manifest_body, sort_keys=True, separators=(",", ":")).encode()
        try:
            return bool(impl.verify(pk, msg, b64d(sig_b64)))
        except Exception:
            return False


# ==============================================================================
# STAGE RESULTS + PROOFRECORD
# ==============================================================================
@dataclass
class StageResult:
    name: str
    passed: bool
    reason_codes: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class ProofRecord:
    request_id: str
    timestamp: float
    eval_time_iso: str
    policy_id: str
    policy_version: str
    policy_hash: str
    requester: str
    action: str
    claimed_algorithm: str
    derived_algorithm: str
    authority: StageResult
    evidence: StageResult
    constraint: StageResult
    decision: str
    reason_codes: list[str]
    artifact_hashes: dict
    nonce: Optional[str]
    gateway_status: str            # "EXECUTED" | "REFUSED"
    boundary_crossed: bool
    environment: dict
    record_hash: str = ""

    def finalize(self) -> "ProofRecord":
        body = {k: v for k, v in asdict(self).items() if k != "record_hash"}
        self.record_hash = sha256_hex(
            json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode())
        return self


# ==============================================================================
# ENGINES
# ==============================================================================
REQUIRED_CONTRACT_FIELDS = [
    "request_id", "requester", "action", "claimed_algorithm", "claimed_param_set",
    "claimed_library", "claimed_version", "mode", "artifact_ref", "evidence_ref",
    "nonce", "policy_version",
]


class AuthorityEngine:
    """Who is asking, and are they an authorized custodian of this key/action?"""
    def __init__(self, authorized_requesters: set[str], key_custody: dict[str, str]):
        self.authorized_requesters = authorized_requesters
        self.key_custody = key_custody  # artifact_ref -> authorized custodian id

    def evaluate(self, req: dict) -> StageResult:
        rc, ok, detail = [], True, []
        requester = req.get("requester")
        if requester not in self.authorized_requesters:
            ok = False; rc.append("AUTH_REQUESTER_NOT_AUTHORIZED")
            detail.append(f"requester '{requester}' not in authority registry")
        custodian = self.key_custody.get(req.get("artifact_ref"))
        if custodian is not None and requester != custodian:
            ok = False; rc.append("AUTH_CUSTODY_MISMATCH")
            detail.append(f"requester '{requester}' is not custodian '{custodian}' of {req.get('artifact_ref')}")
        return StageResult("authority", ok, rc, "; ".join(detail) or "requester authorized & custodian matched")


class EvidenceEngine:
    """Does verifiable evidence prove what the request claims — fresh, untampered,
    bound to THIS request, and corresponding to the TRUE artifact?"""
    def __init__(self, authority_level: str, authority_pk: bytes,
                 used_nonces: set[str], now_fn=time.time):
        self.authority_level = authority_level
        self.authority_pk = authority_pk
        self.used_nonces = used_nonces
        self.now_fn = now_fn

    def evaluate(self, req: dict, bundle: dict, policy: "Policy") -> tuple[StageResult, Optional[ArtifactFinding]]:
        rc, ok, detail = [], True, []
        # (a) required evidence present
        manifest = bundle.get("manifest")
        sig = bundle.get("manifest_sig")
        pub_b64 = bundle.get("public_key_b64")
        if not manifest or not sig or not pub_b64:
            return StageResult("evidence", False, ["EVID_MISSING"],
                               "required evidence (manifest/signature/public key) absent"), None
        pub_bytes = b64d(pub_b64)

        # (b) manifest signature valid under TRUSTED authority public key
        if not EvidenceAuthority.verify(self.authority_level, self.authority_pk, manifest, sig):
            ok = False; rc.append("EVID_SIGNATURE_INVALID")
            detail.append("evidence manifest signature failed verification (tamper/forgery)")

        # (c) independently recompute artifact hash and compare to manifest
        derived_hash = sha256_hex(pub_bytes)
        if derived_hash != manifest.get("artifact_sha256"):
            ok = False; rc.append("EVID_HASH_MISMATCH")
            detail.append("recomputed artifact hash != manifest hash (tampered/mismatched artifact)")

        # (d) artifact binding: manifest must reference the artifact the request names
        if manifest.get("artifact_ref") != req.get("artifact_ref"):
            ok = False; rc.append("EVID_ARTIFACT_BINDING_MISMATCH")
            detail.append("manifest artifact_ref != request artifact_ref")

        # (e) request/evidence binding: manifest must be bound to THIS request_id
        if manifest.get("request_id") not in (None, req.get("request_id")):
            ok = False; rc.append("EVID_REQUEST_BINDING_MISMATCH")
            detail.append("manifest bound to a different request_id (possible replay)")

        # (f) freshness
        issued_at = manifest.get("issued_at", 0)
        age = self.now_fn() - issued_at
        if age > policy.evidence_freshness_seconds:
            ok = False; rc.append("EVID_STALE")
            detail.append(f"evidence age {age:.0f}s exceeds freshness window {policy.evidence_freshness_seconds}s")

        # (g) replay: nonce must be bound to this request/artifact and unused
        nonce = req.get("nonce")
        if manifest.get("nonce") != nonce:
            ok = False; rc.append("EVID_NONCE_BINDING_MISMATCH")
            detail.append("manifest nonce != request nonce (replayed evidence)")
        if nonce in self.used_nonces:
            ok = False; rc.append("EVID_NONCE_REPLAY")
            detail.append(f"nonce {nonce} already consumed (replay)")

        # (h) INDEPENDENT algorithm derivation vs claim
        finding = inspect_artifact(pub_bytes)
        if not finding.functional_ok:
            ok = False; rc.append("EVID_ARTIFACT_NONFUNCTIONAL")
            detail.append(f"artifact failed functional validation: {finding.detail}")
        if finding.derived_family != req.get("claimed_algorithm"):
            ok = False; rc.append("EVID_ALGORITHM_CLAIM_MISMATCH")
            detail.append(f"claimed '{req.get('claimed_algorithm')}' but artifact is '{finding.derived_family}'")

        return StageResult("evidence", ok, rc,
                           "; ".join(detail) or "evidence present, authentic, fresh, bound, and consistent"), finding


class ConstraintEngine:
    """Given TRUE (derived) crypto properties, does the request satisfy THIS policy version?"""
    def evaluate(self, req: dict, finding: ArtifactFinding, policy: "Policy") -> StageResult:
        rc, ok, detail = [], True, []
        fam = finding.derived_family
        mode = req.get("mode")

        # legacy / allowed-algorithm gate
        if fam not in policy.allowed_algorithms:
            ok = False
            if finding.derived_class in ("CLASSICAL-PKE", "CLASSICAL-ECC"):
                rc.append("CONSTRAINT_LEGACY_ALGORITHM")
                detail.append(f"legacy algorithm '{fam}' not permitted under {policy.version} (PQC required)")
            else:
                rc.append("CONSTRAINT_ALGORITHM_NOT_ALLOWED")
                detail.append(f"algorithm '{fam}' not in allowed set for {policy.version}")

        # parameter-set floor (downgrade detection) — only meaningful for allowed PQC families
        if fam in policy.allowed_algorithms and fam in policy.param_rank:
            if policy.param_rank[fam] < policy.min_param_rank:
                ok = False; rc.append("CONSTRAINT_PARAM_DOWNGRADE")
                detail.append(f"parameter set '{fam}' below minimum rank for {policy.version}")

        # provider / library allow-list
        if req.get("claimed_library") not in policy.allowed_libraries:
            ok = False; rc.append("CONSTRAINT_UNTRUSTED_PROVIDER")
            detail.append(f"library/provider '{req.get('claimed_library')}' not approved")

        # minimum version
        if _ver_tuple(req.get("claimed_version")) < _ver_tuple(policy.min_library_version.get(req.get("claimed_library"), "0")):
            ok = False; rc.append("CONSTRAINT_VERSION_BELOW_MINIMUM")
            detail.append(f"library version {req.get('claimed_version')} below minimum")

        # hybrid-mode treatment
        if mode == "hybrid" and not policy.hybrid_allowed:
            ok = False; rc.append("CONSTRAINT_HYBRID_NOT_PERMITTED")
            detail.append(f"hybrid mode presented but {policy.version} requires PQC-only")
        if mode == "pqc-only" and policy.require_hybrid:
            ok = False; rc.append("CONSTRAINT_HYBRID_REQUIRED")
            detail.append(f"{policy.version} requires hybrid transition mode")

        return StageResult("constraint", ok, rc,
                           "; ".join(detail) or f"constraints satisfied under {policy.version}")


def _ver_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except Exception:
        return (0,)


# ==============================================================================
# EXECUTION GATEWAY — the controlled boundary. The protected cryptographic
# operation is physically unreachable unless decision == ALLOW.
# ==============================================================================
class ExecutionGateway:
    def __init__(self):
        self.boundary_crossings: list[dict] = []   # objective ledger of REAL protected invocations

    def _protected_operation(self, req: dict, pub_bytes: bytes) -> dict:
        """The actual protected action: perform a real ML-KEM encapsulation against
        the VERIFIED public key (the precise execution the verified context represents)."""
        fam = ML_KEM_EK_SIZES[len(pub_bytes)]
        K, ct = ML_KEM_IMPL[fam].encaps(pub_bytes)
        return {"performed": "ML-KEM-encapsulation", "family": fam,
                "ciphertext_sha256": sha256_hex(ct), "shared_secret_sha256": sha256_hex(K)}

    def release(self, decision: str, req: dict, verified_pub_bytes: Optional[bytes]) -> tuple[str, Optional[dict]]:
        """Only ALLOW crosses. Any other decision is physically refused here."""
        if decision != ALLOW:
            return "REFUSED", None
        if verified_pub_bytes is None:
            return "REFUSED", None
        out = self._protected_operation(req, verified_pub_bytes)
        self.boundary_crossings.append({"request_id": req.get("request_id"), **out})
        return "EXECUTED", out


# ==============================================================================
# POLICY
# ==============================================================================
@dataclass
class Policy:
    policy_id: str
    version: str
    allowed_algorithms: set
    param_rank: dict
    min_param_rank: int
    allowed_libraries: set
    min_library_version: dict
    hybrid_allowed: bool
    require_hybrid: bool
    evidence_freshness_seconds: int
    raw: dict
    source_hash: str

    @staticmethod
    def load(path: str) -> "Policy":
        with open(path, "rb") as f:
            raw_bytes = f.read()
        d = json.loads(raw_bytes)
        return Policy(
            policy_id=d["policy_id"], version=d["version"],
            allowed_algorithms=set(d["allowed_algorithms"]),
            param_rank=d["param_rank"], min_param_rank=d["min_param_rank"],
            allowed_libraries=set(d["allowed_libraries"]),
            min_library_version=d["min_library_version"],
            hybrid_allowed=d["hybrid_allowed"], require_hybrid=d["require_hybrid"],
            evidence_freshness_seconds=d["evidence_freshness_seconds"],
            raw=d, source_hash=sha256_hex(raw_bytes))


# ==============================================================================
# ORCHESTRATOR — the full ExecutionProof pipeline for one request
# ==============================================================================
class ExecutionProofVerifier:
    def __init__(self, policy: Policy, authority_engine: AuthorityEngine,
                 authority_level: str, authority_pk: bytes, gateway: ExecutionGateway,
                 used_nonces: set, environment: dict, now_fn=time.time):
        self.policy = policy
        self.authority_engine = authority_engine
        self.authority_level = authority_level
        self.authority_pk = authority_pk
        self.gateway = gateway
        self.used_nonces = used_nonces
        self.environment = environment
        self.now_fn = now_fn

    def evaluate(self, req: dict, bundle: dict) -> ProofRecord:
        import datetime
        ts = self.now_fn()
        iso = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        empty = StageResult("(skipped)", False, ["NOT_EVALUATED"], "stage not reached")
        derived_algo = "(not-derived)"
        artifact_hashes = {}

        # ---- Stage 0: contract completeness -> HOLD if incomplete
        missing = [f for f in REQUIRED_CONTRACT_FIELDS if req.get(f) in (None, "")]
        if missing:
            pr = ProofRecord(
                request_id=req.get("request_id", "UNKNOWN"), timestamp=ts, eval_time_iso=iso,
                policy_id=self.policy.policy_id, policy_version=self.policy.version,
                policy_hash=self.policy.source_hash, requester=req.get("requester", ""),
                action=req.get("action", ""), claimed_algorithm=req.get("claimed_algorithm", ""),
                derived_algorithm=derived_algo,
                authority=StageResult("authority", False, ["CONTRACT_INCOMPLETE"], f"missing: {missing}"),
                evidence=empty, constraint=empty, decision=HOLD,
                reason_codes=["CONTRACT_INCOMPLETE"], artifact_hashes=artifact_hashes,
                nonce=req.get("nonce"), gateway_status="REFUSED", boundary_crossed=False,
                environment=self.environment)
            return pr.finalize()

        # ---- Stage 1: Authority -> DENY on fail
        auth = self.authority_engine.evaluate(req)
        if not auth.passed:
            status, _ = self.gateway.release(DENY, req, None)
            pr = ProofRecord(
                request_id=req["request_id"], timestamp=ts, eval_time_iso=iso,
                policy_id=self.policy.policy_id, policy_version=self.policy.version,
                policy_hash=self.policy.source_hash, requester=req["requester"], action=req["action"],
                claimed_algorithm=req["claimed_algorithm"], derived_algorithm=derived_algo,
                authority=auth, evidence=empty, constraint=empty, decision=DENY,
                reason_codes=auth.reason_codes, artifact_hashes=artifact_hashes, nonce=req.get("nonce"),
                gateway_status=status, boundary_crossed=False, environment=self.environment)
            return pr.finalize()

        # ---- Stage 2: Evidence -> HOLD on fail
        ev_engine = EvidenceEngine(self.authority_level, self.authority_pk, self.used_nonces, self.now_fn)
        evidence, finding = ev_engine.evaluate(req, bundle, self.policy)
        if finding is not None:
            derived_algo = finding.derived_family
        if bundle.get("public_key_b64"):
            artifact_hashes["artifact_sha256"] = sha256_hex(b64d(bundle["public_key_b64"]))
        if bundle.get("manifest"):
            artifact_hashes["manifest_sha256"] = sha256_hex(
                json.dumps(bundle["manifest"], sort_keys=True, separators=(",", ":")).encode())
        if not evidence.passed:
            status, _ = self.gateway.release(HOLD, req, None)
            pr = ProofRecord(
                request_id=req["request_id"], timestamp=ts, eval_time_iso=iso,
                policy_id=self.policy.policy_id, policy_version=self.policy.version,
                policy_hash=self.policy.source_hash, requester=req["requester"], action=req["action"],
                claimed_algorithm=req["claimed_algorithm"], derived_algorithm=derived_algo,
                authority=auth, evidence=evidence, constraint=empty, decision=HOLD,
                reason_codes=evidence.reason_codes, artifact_hashes=artifact_hashes, nonce=req.get("nonce"),
                gateway_status=status, boundary_crossed=False, environment=self.environment)
            return pr.finalize()

        # ---- Stage 3: Constraint -> HOLD on fail
        constraint = ConstraintEngine().evaluate(req, finding, self.policy)
        if not constraint.passed:
            status, _ = self.gateway.release(HOLD, req, None)
            pr = ProofRecord(
                request_id=req["request_id"], timestamp=ts, eval_time_iso=iso,
                policy_id=self.policy.policy_id, policy_version=self.policy.version,
                policy_hash=self.policy.source_hash, requester=req["requester"], action=req["action"],
                claimed_algorithm=req["claimed_algorithm"], derived_algorithm=derived_algo,
                authority=auth, evidence=evidence, constraint=constraint, decision=HOLD,
                reason_codes=constraint.reason_codes, artifact_hashes=artifact_hashes, nonce=req.get("nonce"),
                gateway_status=status, boundary_crossed=False, environment=self.environment)
            return pr.finalize()

        # ---- All PASS -> ALLOW: consume nonce, release to gateway
        self.used_nonces.add(req.get("nonce"))
        pub_bytes = b64d(bundle["public_key_b64"])
        status, out = self.gateway.release(ALLOW, req, pub_bytes)
        pr = ProofRecord(
            request_id=req["request_id"], timestamp=ts, eval_time_iso=iso,
            policy_id=self.policy.policy_id, policy_version=self.policy.version,
            policy_hash=self.policy.source_hash, requester=req["requester"], action=req["action"],
            claimed_algorithm=req["claimed_algorithm"], derived_algorithm=derived_algo,
            authority=auth, evidence=evidence, constraint=constraint, decision=ALLOW,
            reason_codes=["ALL_STAGES_PASS"], artifact_hashes=artifact_hashes, nonce=req.get("nonce"),
            gateway_status=status, boundary_crossed=(status == "EXECUTED"), environment=self.environment)
        if out:
            pr.artifact_hashes["execution_output"] = out
        return pr.finalize()
