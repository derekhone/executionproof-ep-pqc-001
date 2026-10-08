# Public abstract — EP-PQC-001

As organizations migrate to post-quantum cryptography (PQC), a practical risk is that a system will
*claim* to use an approved algorithm while actually presenting a stale, substituted, mis-bound, or
unauthorized artifact. EP-PQC-001 asks a narrow, testable question: **can a pre-execution
verification gateway physically prevent a cryptographic operation from crossing an execution boundary
when the system cannot independently prove that the operation satisfies a defined PQC policy?**

The experiment implements the design law *"if it cannot be verified, it cannot execute."* The gateway
does not trust labels. For every request it independently re-derives the true algorithm family from
the **raw key bytes** — DER parsing for classical RSA/ECDH, and exact FIPS-203 byte-lengths plus a
functional encapsulation probe for ML-KEM — recomputes artifact hashes, verifies a **real ML-DSA-65**
evidence-manifest signature, and enforces authority, freshness, request/artifact/nonce binding,
single-use nonces, and policy constraints under two **experimental** policy profiles (a transitional
profile and a PQC-only rollover profile). The protected operation (a real ML-KEM encapsulation)
executes **only** when every stage passes.

The work is **preregistered**: the hypotheses, case matrix, and scoring rules were written and
hash-sealed **before** execution, and every decision emits a hash-sealed ProofRecord that a
**standalone verifier** (independent of the enforcement engine) re-checks against the raw and scored
results.

**Findings, stated verbatim.** The root run (24 cases) is **PARTIAL / safety-PASS**: 23/24 decision
matches, 22/24 reason matches, **zero false ALLOWs**, and no safety-invariant violations. Two cases
deviated from their expected reason code, but both were **safe** — the operation was still blocked —
and both traced to our own **test-case design**, not to the enforcement engine. These deviations are
reported as-is and were not reclassified. A remediation run (R1, 26 cases) used the **byte-identical**
engine with only the test design corrected (plus an added nonce-replay pair) and produced a clean
**PASS** (26/26 decision, 26/26 reason, zero false ALLOWs).

**Scope and limits.** This is a bounded **software-only** simulation. It demonstrates software-only,
pre-execution verification of PQC-related artifacts under an experimental policy, and nothing beyond
that. It does **not** claim CNSA 2.0 compliance, NIST certification, quantum resistance of
ExecutionProof, production or defense readiness, or HSM/TPM/live-TLS validation; it does not prove the
security of ML-KEM or ML-DSA; and it has not undergone third-party validation (blinding is
procedural, single author). The contribution is a reproducible, preregistered demonstration that a
fail-closed verification gateway can be built and independently audited — and an honest account of
where the first attempt was only partially correct and how a test-design fix, not an engine change,
resolved it.
