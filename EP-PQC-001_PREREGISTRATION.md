# EP-PQC-001 — PREREGISTRATION

**Pre-Execution Post-Quantum Cryptographic Policy Verification**
Remnant Fieldworks Inc. — ExecutionProof™ experimental series
Status at authoring: **COMMITTED BEFORE EXECUTION.** Expected outcomes are sealed in `generator/answer_key.sealed.json` (hash pinned below) and were written before the verifier was run.

> Governing standard: Proof Before Power™ / Verification Before Execution™. Design before execution. Evidence before claims. Preserve failures. Do not move goalposts after results are known. Separate experimental policy from regulatory requirement; separate simulation from production; separate successful classification from successful execution enforcement.

---

## 1. Objective
Determine whether the ExecutionProof pipeline (Request Contract → Authority Engine → Evidence Engine → Constraint Engine → Control Engine → ProofRecord™ → Execution Gateway) can, **before a protected cryptographic operation is allowed to proceed**, correctly classify a proposed execution request as ALLOW / HOLD / DENY based on *independently verified* cryptographic evidence and a declared post-quantum policy — and **physically prevent** any non-ALLOW request from crossing the controlled execution boundary.

## 2. Research question
Can ExecutionProof reliably distinguish policy-compliant post-quantum cryptographic execution requests from unauthorized, unverifiable, incomplete, deprecated, substituted, stale, tampered, replayed, or policy-incompatible requests **before execution occurs**, where the compliance decision is derived from *independent inspection of real cryptographic artifacts* rather than from the requester's self-asserted labels?

## 3. Hypothesis (H1)
For every preregistered case, ExecutionProof produces the sealed expected decision, derived from the Authority/Evidence/Constraint invariants, **and** no case classified HOLD or DENY results in the protected operation executing (no boundary crossing).

## 4. Null hypothesis (H0)
ExecutionProof fails to reliably prevent at least one preregistered unauthorized, insufficiently evidenced, substituted, stale, tampered, replayed, or policy-incompatible cryptographic execution from reaching the protected execution boundary — i.e., at least one non-ALLOW case either is misclassified as ALLOW or produces a boundary crossing.

## 5. System boundary
- **In scope:** the ExecutionProof decision pipeline and a single instrumented Execution Gateway whose protected action is a real ML-KEM key encapsulation performed against the verified public key. The gateway maintains an objective ledger of *actual* protected-function invocations.
- **Out of scope:** quantum resistance of ExecutionProof itself; security proofs of ML-KEM/ML-DSA/SLH-DSA; any government certification; production readiness; HSM/TPM/KMS/TLS-handshake integration; network transport. These are explicitly NOT tested (see Claims Boundary).

## 6. Policy versions & hashes (frozen)
- `EP-PQC-POLICY-001-A.json` (A-2027.0, transitional, hybrid permitted, ML-KEM ≥ rank 3) — SHA-256 `a1642a7413bb6b2f99a64fcfc8781c1b5ee28ca9b5fbea58d8e5c05bab4b14e7`
- `EP-PQC-POLICY-001-B.json` (B-2030.0, rollover, PQC-only, ML-KEM-1024 only) — SHA-256 `99663b478448d29cc65925ed9a27dbea4897e1d577ba7a10e53ff2b693542bb8`

These are **experimental policy profiles**, NOT a claim about the regulatory requirements binding any organization. See `EXTERNAL_SOURCE_VERIFICATION.md`.

## 7. Software / environment
- Python 3.11.6
- `cryptography` 46.0.7 (classical RSA/EC parsing — independent artifact derivation)
- `kyber-py` 1.2.0 (ML-KEM-512/768/1024, FIPS 203) — real keygen/encaps/decaps
- `dilithium-py` (ML-DSA-44/65/87, FIPS 204) — real evidence-authority signatures
- Deterministic evaluation clock `T0 = 1760000000` (freshness tests reproducible).
- Key material is generated **once and frozen** (synthetic/test keys only); decision logic is deterministic.

## 8. Cryptographic libraries / algorithms under use
- Artifact-under-test = ML-KEM encapsulation (public) key; protected op = ML-KEM encapsulation.
- Evidence provenance = ML-DSA-65 signature by a pinned evidence authority.
- Legacy artifacts for adversarial cases = real RSA-2048 / ECDH-P256 keys.

## 9. Committed artifacts (frozen, hashed BEFORE verifier run)
- `impl/ep_pqc_core.py` — SHA-256 `506d8e0c830f6133bab821310571f87402fd82434fc0e6cc65aff3f483c20bdb`
- `generator/generate_cases.py` — SHA-256 `c54901f8435a4d1d5df06b2b7102a9fabc5169a6a818d0224c48f6e993db4abf`
- `generator/challenges.json` — SHA-256 `946eef7e0c1330694b4a44e5f7242d49cdffdfbe4b1b84c3f42ecbb283237430`
- `generator/answer_key.sealed.json` — SHA-256 `487dff42aa953b16ed70c74bd5e9a86b101700bc1b39d5abe9fdd9930ad75834`
- `evidence/authority_pubkey.json` — SHA-256 `55ac81d8970ccac5872b1301486a25811780606efdb4b4b86c0d58ad46ac1df9`
- `run_experiment.py` — SHA-256 `b9d17f66573d8cbbf210b6e3dcf6cd2b8321a28cfb2be82d440da14dd68ac2d0`

## 10. Test environment
Single-host CPU execution; no network; no GPU/HSM/TPM required. No external service is contacted at decision time.

## 11. Test cases and sealed expected outcomes
Expected decisions are committed in `answer_key.sealed.json` (hash above) and are reproduced here for the record. The verifier does not read that file.

| Case | Scenario | Expected | Primary reason |
|---|---|---|---|
| PQC-01 | Fully valid PQC request | ALLOW | ALL_STAGES_PASS |
| PQC-02 | Legacy-only (RSA-2048) under PQC-required policy | HOLD | CONSTRAINT_LEGACY_ALGORITHM |
| PQC-03 | Missing cryptographic evidence | HOLD | EVID_MISSING |
| PQC-04 | Falsified algorithm declaration (claims ML-KEM, artifact is RSA) | HOLD | EVID_ALGORITHM_CLAIM_MISMATCH |
| PQC-05 | Unauthorized requester | DENY | AUTH_REQUESTER_NOT_AUTHORIZED |
| PQC-06 | Tampered evidence (byte flipped post-issuance) | HOLD | EVID_HASH_MISMATCH |
| PQC-07 | Stale evidence (freshness violated) | HOLD | EVID_STALE |
| PQC-08 | Artifact mismatch (evidence for other key) | HOLD | EVID_ARTIFACT_BINDING_MISMATCH |
| PQC-09 | Approved hybrid transition (policy A) | ALLOW | ALL_STAGES_PASS |
| PQC-10 | Unauthorized hybrid under PQC-only policy B | HOLD | CONSTRAINT_HYBRID_NOT_PERMITTED |
| PQC-11a | Rollover part 1: ML-KEM-768 hybrid under A | ALLOW | ALL_STAGES_PASS |
| PQC-11b | Rollover part 2: same config under B (fresh nonce) | HOLD | CONSTRAINT_ALGORITHM_NOT_ALLOWED |
| PQC-12 | Replay (evidence bound to prior request/nonce) | HOLD | EVID_NONCE_BINDING_MISMATCH |
| PQC-13 | Untrusted provider/library | HOLD | CONSTRAINT_UNTRUSTED_PROVIDER |
| PQC-14 | Parameter downgrade (ML-KEM-512 under 768-floor) | HOLD | CONSTRAINT_PARAM_DOWNGRADE |
| PQC-15 | Library version below minimum | HOLD | CONSTRAINT_VERSION_BELOW_MINIMUM |
| PQC-16 | Algorithm substitution (claims 1024, artifact is 768) | HOLD | EVID_ALGORITHM_CLAIM_MISMATCH |
| NC-00-baseline | Unchanged baseline | ALLOW | ALL_STAGES_PASS |
| NC-01-authority | Change ONLY authority | DENY | AUTH_REQUESTER_NOT_AUTHORIZED |
| NC-02-provider | Change ONLY provider | HOLD | CONSTRAINT_UNTRUSTED_PROVIDER |
| NC-03-policyversion | Change ONLY policy version | HOLD | CONSTRAINT_ALGORITHM_NOT_ALLOWED |
| NC-04-freshness | Change ONLY freshness | HOLD | EVID_STALE |
| NC-05-algorithm | Change ONLY algorithm/param | HOLD | CONSTRAINT_PARAM_DOWNGRADE |
| NC-06-artifactbinding | Change ONLY artifact binding | HOLD | EVID_ARTIFACT_BINDING_MISMATCH |

## 12. PASS criterion
**PASS** iff ALL of the following hold:
1. Every case's final decision equals its sealed expected decision.
2. Every case's primary reason code equals its sealed expected reason.
3. **Safety invariant:** no case with expected decision HOLD or DENY produces a boundary crossing (no protected ML-KEM encapsulation executed). The only boundary crossings permitted are the ALLOW cases.
4. Negative controls change the decision **only** along the single mutated dimension.

## 13. FAIL criterion
**FAIL** if any adversarial/non-ALLOW case produces a boundary crossing (False ALLOW at the gateway), OR any case's decision is misclassified in a way that violates the safety invariant, OR a negative control changes the decision for the wrong dimension. A FAIL is preserved publicly (subject to RF publication policy) and is NOT reclassified as INCONCLUSIVE.

## 14. INCONCLUSIVE criterion
Infrastructure or design failure prevents a fair determination: dependency failure, corrupted fixture, environmental error, or a preregistration ambiguity discovered that prevents fair classification. INCONCLUSIVE is never used to hide an unfavorable but valid result.

## 15. Deviations policy
Any deviation from this preregistration is recorded in a POST_EXECUTION_RECORD with timestamp and rationale. Expected outcomes are never edited after execution. If a fix is warranted, a new experiment `EP-PQC-001R1` is created; the original result is preserved byte-for-byte.

## 16. Remediation policy
On FAIL: preserve EP-PQC-001 as FAIL; diagnose; create EP-PQC-001R1 with explicit failure diagnosis, the original failing case repeated, targeted regression cases, and new adversarial cases. Never overwrite the original.

## 17. Artifact-retention policy
All frozen inputs, raw decisions, ProofRecords, scorer output, and logs are retained under `/home/ubuntu/output/RF_EP_PQC_001/`. Private/secret keys are never published; only synthetic/test public keys and hashes appear in artifacts.

## 18. Pinned evidence authority
ML-DSA-65 evidence-authority public-key SHA-256: `4d6465249c07ee4ea60e7017b28f7dcc45e93495062b6e87b47fbd82ca1a0ba6` (also in `evidence/authority_pubkey.json`). The verifier trusts only this key for manifest provenance.

## 19. Blinding statement
Generator and verifier are separate programs. The verifier reads only `challenges.json` and has no access to `answer_key.sealed.json` at decision time (procedural separation). This is **not** third-party blinding — the same author wrote both — and that limitation is reported honestly. Expected outcomes were committed (sealed + hashed) before the verifier ran.
