# EP-PQC-001 — Dependency & Environment Record

This file closes the **ML-DSA dependency-record reproducibility gap**: the frozen
ProofRecords and `results/raw_decisions.json` recorded the ML-DSA library version as
`"dilithium_py": "n/a"`, which is not a reproducible pin. This document resolves that
value to the exact installed release and explains the root cause, **without altering any
frozen artifact** (doing so would change their record hashes).

## Resolved versions (authoritative)

| Role | Import name | Distribution | **Pinned version** | Source of truth |
|---|---|---|---|---|
| ML-KEM / FIPS 203 | `kyber_py` | `kyber-py` | **1.2.0** | `importlib.metadata.version("kyber-py")` |
| ML-DSA / FIPS 204 | `dilithium_py` | `dilithium-py` | **1.4.0** | `importlib.metadata.version("dilithium-py")` |
| Classical RSA/ECDH | `cryptography` | `cryptography` | **46.0.7** | `cryptography.__version__` |

Runtime: **Python 3.11.6** on **Linux-6.17.0-1019-aws-x86_64-with-glibc2.36**.

Machine-pinned equivalent: see [`requirements.txt`](requirements.txt).

## Root cause of the `"n/a"` ML-DSA record

The run scripts captured the environment with:

```python
"dilithium_py": getattr(dilithium_py, "__version__", "n/a")
```

The `dilithium_py` package **does not expose a `__version__` module attribute**
(`hasattr(dilithium_py, "__version__") == False`), so the `getattr` fallback wrote
`"n/a"`. This is a *recording* gap only — the correct library was installed and used;
its version was simply not retrievable via that attribute. The authoritative version is
obtainable via distribution metadata:

```python
import importlib.metadata as m
m.version("dilithium-py")   # -> '1.4.0'
```

> Note: `kyber_py` likewise lacks `__version__`, but the run scripts used
> `getattr(kyber_py, "__version__", "1.2.0")`, so its fallback happened to equal the
> installed version (1.2.0). It is pinned here from metadata for the same rigor.

## Why the frozen artifacts are NOT edited

The ProofRecords embed the environment dict inside the hashed record body, so changing
`"n/a"` → `"1.4.0"` inside any frozen record would change its `record_hash` and break the
chain with `results/raw_decisions.json`. Under the RF rule *preserve FAILs / never massage
sealed outputs*, the frozen value stays verbatim and this document supplies the resolved,
reproducible pin alongside it. Future runs that import updated run scripts should source the
version from `importlib.metadata` so the pin is captured in-record.

## Independent verification

```bash
python3 -m pip install -r requirements.txt
python3 -c "import importlib.metadata as m; \
print('kyber-py', m.version('kyber-py')); \
print('dilithium-py', m.version('dilithium-py')); \
import cryptography; print('cryptography', cryptography.__version__)"
```

Expected:
```
kyber-py 1.2.0
dilithium-py 1.4.0
cryptography 46.0.7
```
