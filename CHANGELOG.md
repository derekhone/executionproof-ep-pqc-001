# Changelog

All notable changes to the EP-PQC-001 public package are documented here.
This project archives a frozen research experiment; scientific artifacts are
immutable once released. Versions that follow a release are limited to
documentation and packaging corrections and never alter any scientific artifact.

DOI reference (Zenodo):

- **Concept DOI** (always resolves to the latest version): `10.5281/zenodo.23248211`
- **v1.0.1 version DOI** (current): `10.5281/zenodo.23248351`
- **v1.0.0 version DOI** (original, preserved): `10.5281/zenodo.23248212`

---

## [1.0.1] — 2026-10-08

**Documentation-only correction. No scientific artifact changed.**

### Fixed
- Corrected the DOI terminology throughout the public package so that the Zenodo
  **concept DOI** is unambiguously distinguished from each **version DOI**. The
  v1.0.0 documentation (`README.md`, `CITATION.cff`) incorrectly labeled the
  v1.0.0 *version* DOI `10.5281/zenodo.23248212` as the "concept DOI". The concept
  DOI is `10.5281/zenodo.23248211`; it always resolves to the latest version.

### Changed
- `README.md` — DOI citation block now lists the concept DOI, the v1.0.1 version
  DOI (current), and the v1.0.0 version DOI (preserved), with an explanatory
  paragraph on the difference; GitHub links reflect the latest release (v1.0.1)
  while preserving the v1.0.0 reference.
- `CITATION.cff` — `version` bumped to `1.0.1`; the top-level `doi` field holds the
  **concept DOI**; the `identifiers` list enumerates all three DOIs with
  descriptions.
- `RELEASE_NOTES.md` — retitled to v1.0.1 with a documentation-only-correction
  banner and a citation line listing all three DOIs.
- `.zenodo.json` — `version` set to `1.0.1`; added a `related_identifiers` entry
  (`isNewVersionOf` → `10.5281/zenodo.23248212`); notes updated to explain the
  correction.
- Added this `CHANGELOG.md`.
- Regenerated `HASHES.txt` and the public archive to reflect the corrected
  documentation files (packaging only).

### Unchanged (byte-identical to v1.0.0)
- The enforcement engine (`impl/ep_pqc_core.py`).
- All preregistrations (`EP-PQC-001_PREREGISTRATION.md`,
  `R1/EP-PQC-001R1_PREREGISTRATION.md`).
- All policy profiles (`policy/EP-PQC-POLICY-001-A.json`,
  `policy/EP-PQC-POLICY-001-B.json`).
- All ProofRecords, raw results, and scored results.
- Both verdicts: EP-PQC-001 root run = **PARTIAL / safety-PASS**;
  EP-PQC-001R1 = **PASS**.
- The disclosed PQC-17b erratum (`ERRATA.md`) and the sealed ProofRecord it
  describes — intentionally not modified, because editing a sealed ProofRecord
  would change its `record_hash` and break the evidence chain.
- All stated limitations and prohibited claims.

---

## [1.0.0] — 2026-10-08

Initial public release of **EP-PQC-001**, a software-only ExecutionProof™
experiment testing whether a pre-execution gateway can physically block a
cryptographic operation when the system cannot independently prove that the
operation satisfies a defined post-quantum cryptography (PQC) policy.

- Root run EP-PQC-001 (24 cases): **PARTIAL / safety-PASS** — decision 23/24,
  reason 22/24, zero false ALLOW, no safety-invariant violations.
- Remediation run EP-PQC-001R1 (26 cases), byte-identical engine with only the
  test design corrected: clean **PASS** (26/26 decision, 26/26 reason, zero
  false ALLOW).
- Published to GitHub (tag `v1.0.0`) and Zenodo (version DOI
  `10.5281/zenodo.23248212`).
