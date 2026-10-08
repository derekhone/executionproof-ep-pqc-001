#!/usr/bin/env python3
"""
EP-PQC-001 — consolidated HASHES.txt generator (reproducible).

Walks the whole package and writes one SHA-256 per file, sorted by relative
path, to HASHES.txt. Excludes HASHES.txt itself and caches/VCS dirs so the
manifest is self-consistent and regenerable. READ-ONLY except for HASHES.txt.

    python3 make_hashes.py            # (re)write HASHES.txt
    python3 make_hashes.py --check    # verify current files against HASHES.txt
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "HASHES.txt")
EXCLUDE_DIRS = {".git", "__pycache__", ".ipynb_checkpoints"}
EXCLUDE_FILES = {"HASHES.txt"}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files():
    for root, dirs, files in os.walk(HERE):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
        for fn in sorted(files):
            if fn in EXCLUDE_FILES:
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, HERE)
            yield rel, full


def build():
    return [(rel, sha256_file(full)) for rel, full in iter_files()]


def write_manifest():
    entries = build()
    lines = [f"{digest}  {rel}" for rel, digest in entries]
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("# EP-PQC-001 — consolidated SHA-256 manifest\n")
        fh.write(f"# {len(entries)} files. Excludes HASHES.txt itself.\n")
        fh.write("# Verify: python3 make_hashes.py --check   (or: sha256sum -c HASHES.txt)\n")
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(entries)} files)")


def check():
    if not os.path.isfile(OUT):
        print("HASHES.txt not found; run without --check first")
        return 1
    expected = {}
    with open(OUT, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            digest, rel = line.split("  ", 1)
            expected[rel] = digest
    current = dict(build())
    ok = True
    for rel, digest in expected.items():
        if rel not in current:
            ok = False
            print(f"[FAIL] missing on disk: {rel}")
        elif current[rel] != digest:
            ok = False
            print(f"[FAIL] hash changed: {rel}")
    for rel in current:
        if rel not in expected:
            ok = False
            print(f"[FAIL] new/untracked file not in manifest: {rel}")
    print("OK: all files match HASHES.txt" if ok else "FAIL: manifest mismatch")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check())
    write_manifest()
