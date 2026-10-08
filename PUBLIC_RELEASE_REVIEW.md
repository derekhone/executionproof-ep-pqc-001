# EP-PQC-001 — Public Release Review (REVIEW ONLY)

**Date:** 2026-10-08 · **Prepared for:** Derek Hone, Remnant Fieldworks Inc.
**Status:** ⛔ **NOT PUBLISHED.** No GitHub push, no GitHub release, no Zenodo upload, no DOI minted.
This document shows **exactly** what would be published and flags anything that should block release.

> Standing gate: nothing in this package goes public until a **separate written "PUBLISH GO"** from
> Derek. This review does not itself authorize any external action.

---

## 1. What this review covers

Derek authorized preparation of the **final public-release package for review only**. Every
release-candidate document was written and is staged under **`release/`** so it is clearly separated
from the frozen evidence. The frozen experiment (engine, preregistrations, policies, results, scored
outputs, ProofRecords) is **unchanged** — see §6.

## 2. Release-candidate files (staged in `release/`)

| Deliverable requested | File | Notes |
|---|---|---|
| Final README.md | `release/README.md` | Public landing page; verbatim PARTIAL/PASS; limitations; errata ref |
| CITATION.cff | `release/CITATION.cff` | No DOI; license = Apache-2.0 placeholder per recommendation |
| LICENSE recommendation | `release/LICENSE_RECOMMENDATION.md` | Apache-2.0 (code) + CC-BY-4.0 (docs/data); not finalized |
| Zenodo metadata | `release/.zenodo.json` | Valid JSON; open; no DOI; errata + limitations in notes |
| Repository description | `release/REPOSITORY_DESCRIPTION.txt` | Short + long About, name, topics |
| Release title + notes | `release/RELEASE_NOTES.md` | Title: `EP-PQC-001 v1.0.0 …`; tag `v1.0.0` |
| Public abstract | `release/PUBLIC_ABSTRACT.md` | Plain-language, bounded claims |
| Limitations section | in `release/README.md` + `release/PUBLIC_ABSTRACT.md` | Explicit non-claims list |
| Root PARTIAL + R1 PASS presentation | `release/README.md` §Results, `release/RELEASE_NOTES.md` | Verbatim, not softened |
| ERRATA.md reference | `release/README.md` §Errata → root `ERRATA.md` | PQC-17b typo disclosed |
| Reproduction instructions | `release/README.md` §Reproduce | verifier + manifest + re-run |
| Final HASHES.txt | root `HASHES.txt` | 90 files incl. `release/` |
| Final file manifest | §5 below + `HASHES.txt` | full tree |

## 3. Claim-boundary check (PASS)

Every release-candidate document keeps claims bounded to **software-only, pre-execution verification
of PQC-related artifacts under an experimental policy.** Each of the following is explicitly
**disclaimed** in README, abstract, release notes, and `.zenodo.json`:

- ❌ CNSA 2.0 compliance · ❌ NIST certification/validation · ❌ quantum resistance of ExecutionProof
- ❌ production readiness · ❌ defense readiness · ❌ HSM/TPM/live-TLS validation
- ❌ third-party validation (blinding is procedural, single author)
- ❌ proof of ML-KEM/ML-DSA security (uses, does not prove)

No "first / only / patented / unbreakable" language is present. Trademark handled: ExecutionProof™
noted as an RF mark; standards mentioned for context only, no endorsement implied.

## 4. Verdicts — preserved verbatim (not softened, not hidden)

- **EP-PQC-001 (root) — PARTIAL (safety-PASS).** 24 cases; decision 23/24; reason 22/24;
  **False_ALLOW = 0**; safety-invariant violations = none; boundary crossings = exactly the 4
  expected-ALLOW cases. The two deviations (**PQC-04**, **PQC-12**) are presented in full: both
  **SAFE** (operation still blocked), both traced to **test-case design, not the engine**. Not
  reclassified to "inconclusive"; goalposts not moved.
- **EP-PQC-001R1 — PASS.** 26 cases; decision 26/26; reason 26/26; **False_ALLOW = 0**. Re-used the
  **byte-identical** engine (`506d8e0c…`); only the test design was fixed; nonce-replay pair added.

The root→R1 story is told honestly: R1 is a **test-design** fix on an unchanged engine, so it does
not weaken enforcement.

## 5. Final file manifest (90 files)

Authoritative list is `HASHES.txt` (consolidated SHA-256, verifiable with
`sha256sum -c HASHES.txt` or `python3 make_hashes.py --check`). Top-level structure:

```
RF_EP_PQC_001/
├── README.md, INTEGRITY_AUDIT.md, ERRATA.md, DEPENDENCIES.md
├── requirements.txt, HASHES.txt, make_hashes.py, verify_proofrecords.py
├── run_experiment.py, score.py
├── EP-PQC-001_PREREGISTRATION.md, PREREGISTRATION_SHA256.txt
├── impl/ep_pqc_core.py                  (engine 506d8e0c…)
├── policy/EP-PQC-POLICY-001-A.json      (a1642a74…)  B.json (99663b47…)
├── generator/, evidence/, results/, proofrecords/ (24)
├── src/ pdf/ docx/                      (full A–S report)
├── R1/  (prereg fce80a02…, generator, results, proofrecords (26), runner, scorer)
└── release/  (README.md, CITATION.cff, LICENSE_RECOMMENDATION.md, .zenodo.json,
               REPOSITORY_DESCRIPTION.txt, RELEASE_NOTES.md, PUBLIC_ABSTRACT.md)
```

## 6. Integrity audit (re-run this review)

- **Standalone verifier** `python3 verify_proofrecords.py` → **PASS (exit 0)**; 24/24 + 26/26
  ProofRecords self-verify and reconcile with raw + scored results; boundary invariant holds for all 50.
- **Manifest** `sha256sum -c HASHES.txt` / `make_hashes.py --check` → **OK** (all 90 files match).
- **Frozen artifacts unchanged:** engine `506d8e0c830f…`; root prereg `931508ea1de6…`;
  R1 prereg `fce80a02f218…`; policy A `a1642a74…`; policy B `99663b47…`; all `results/` untouched.

## 7. Does anything block release?

**No technical or integrity issue blocks release.** The package is self-contained, reproducible,
independently verifiable, and honestly bounded. The disclosed PQC-17b erratum is **non-fatal** and
correctly documented (frozen artifact intentionally not modified to preserve the evidence chain).

The following are **decisions/confirmations Derek must make before a PUBLISH GO** — they are not
defects:

| Item | Needs | Severity |
|---|---|---|
| **License choice** | Confirm Apache-2.0 (code) + CC-BY-4.0 (docs/data), or alternative. Then add `LICENSE` + `NOTICE` and sync `CITATION.cff`/`.zenodo.json`. | Must set before publish (non-blocking for review) |
| **Repository URL** | `CITATION.cff` uses intended URL `github.com/derekhone/ep-pqc-001`; confirm exact owner/name (repo not yet created). | Confirm before publish |
| **File relocation on publish** | On publish, the `release/` candidates move to repo **root** (README.md, CITATION.cff, .zenodo.json, LICENSE) and `HASHES.txt` is regenerated once after the move. | Mechanical step at publish time |
| **DOI** | None minted by design; Zenodo deposit only after explicit GO. | Intentional hold |
| **Report cross-refs** | `src/EP-PQC-001_REPORT.md` is the internal A–S report; confirm it should ship as-is publicly (it already carries honesty bounds). | Confirm |

## 8. Recommendation

**Ready for your review.** If you approve, a future **PUBLISH GO** would trigger: (1) finalize license
+ NOTICE; (2) confirm repo name; (3) move `release/` files to root and regenerate `HASHES.txt`;
(4) push to GitHub; (5) create the `v1.0.0` release with `RELEASE_NOTES.md`; (6) **only then**, on a
further explicit instruction, create the Zenodo deposit and mint the DOI.

**Awaiting your separate written PUBLISH GO. No action will be taken until then.**
