# LICENSE recommendation — EP-PQC-001

**Status: RECOMMENDATION ONLY. No `LICENSE` file has been committed. Until one is, all rights are
reserved by Remnant Fieldworks Inc.** This document is for Derek's review; the actual license is not
finalized and nothing here grants any rights yet.

## Recommended dual license

This repository mixes **code** (the engine, verifier, generators, scorers) with **documentation and
data** (reports, preregistrations, policy JSON, results, ProofRecords). A single license rarely fits
both well, so the recommendation is:

| Component | Recommended license | Rationale |
|---|---|---|
| **Code** (`*.py`) | **Apache-2.0** | Permissive, patent-grant clause (useful given the ExecutionProof IP program), widely accepted for reproducible-research code, GitHub/Zenodo-friendly. |
| **Docs & data** (`*.md`, `*.json`, `*.pdf`, `*.docx`, results, ProofRecords) | **CC-BY-4.0** | Standard for research artifacts; requires attribution while allowing reuse and redistribution. |

This split is the common pattern for preregistered, reproducible scientific software and keeps the
patent-relevant code under a license with an explicit patent grant while letting the evidence and
write-ups circulate under a citation-friendly data license.

### Alternative single-license options (if a split is undesirable)

- **MIT** (code) — simplest permissive option, but **no patent grant**. Given the ExecutionProof
  patent/governance families, Apache-2.0 is preferred over MIT.
- **Apache-2.0 for everything** — acceptable and simplest to administer; slightly unusual for prose
  but legally fine.
- **All-rights-reserved / proprietary** — if Derek wants to publish for review without granting reuse
  rights. In that case, publish with **no** open-source `LICENSE` and an explicit "all rights
  reserved, for review only" notice. (This is the current default until a license is chosen.)

## Trademark note (independent of the copyright license)

**ExecutionProof™** is a trademark of Remnant Fieldworks Inc. An open-source copyright license does
**not** grant trademark rights. Recommend adding a short `NOTICE` line: *"ExecutionProof is a
trademark of Remnant Fieldworks Inc. The license covers copyright in the code and documents; it does
not grant any right to use the ExecutionProof name or marks."*

## To finalize (on Derek's instruction only)

1. Choose: **Apache-2.0 (code) + CC-BY-4.0 (docs/data)** [recommended], or a single license, or
   all-rights-reserved.
2. Add a `LICENSE` file (and, for the dual option, a `LICENSE-docs` or a `## License` note in README
   mapping each path to its license).
3. Set the `license` field in `CITATION.cff` and `.zenodo.json` to match (both currently say
   `Apache-2.0` as a placeholder aligned with the recommendation — update if the choice differs).
4. Add the `NOTICE` trademark line.

No `LICENSE` file is added in this review package by design — the choice is Derek's.
