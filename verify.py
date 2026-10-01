#!/usr/bin/env python3
"""
Check captures made by capture.py.

    python verify.py archive/2026-10-02/061312Z     # one capture
    python verify.py archive                        # every capture

For each capture it:
  • recomputes the SHA-256 of every file and compares it with manifest.json;
  • checks each RFC 3161 timestamp token against manifest.json and the
    Time-Stamp Authority's certificate chain (with OpenSSL);
  • prints the time each authority signed.

Needs Python 3.11+ and the `openssl` command. Nothing here talks to the
capture tool's own clock — the times shown come from the authorities' signatures.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from capture import parse_tsr_text, run, sha256_file, token_certs, verify_token


def check(folder: Path, tmp: Path) -> bool:
    mpath = folder / "manifest.json"
    manifest = json.loads(mpath.read_text())
    ok = True
    print(f"\n{folder}")
    print(f"  captured (runner clock): {manifest.get('capture_started_utc')}")

    bad = []
    for name, meta in manifest.get("files", {}).items():
        p = folder / name
        if not p.exists():
            bad.append(f"{name} is missing")
        elif sha256_file(p) != meta["sha256"]:
            bad.append(f"{name} has been changed")
    if bad:
        ok = False
        for b in bad:
            print(f"  ✗ {b}")
    else:
        print(f"  ✓ all {len(manifest.get('files', {}))} files match manifest.json")

    tokens = sorted((folder / "timestamps").glob("*.tsr"))
    if not tokens:
        print("  ✗ no timestamp tokens")
        return False
    good = 0
    for tsr in tokens:
        name = tsr.stem
        certs = tsr.with_name(f"{name}-certs.pem")
        if not certs.exists():
            token_certs(tsr, certs)
        info = parse_tsr_text(run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"]).stdout)
        valid, msg = verify_token(mpath, tsr, certs, tmp)
        if valid:
            good += 1
            print(f"  ✓ {name:<9} signed {info['time_utc']}  by {info['tsa_name']}")
        else:
            print(f"  ✗ {name:<9} signature check failed: {msg}")
    print(f"  page HTTP {manifest.get('page', {}).get('http_status')}, "
          f"PDF linked on page: {'yes' if manifest.get('pdf_link', {}).get('found') else 'NO'}, "
          f"PDF HTTP {manifest.get('pdf', {}).get('http_status')}")
    wb = folder / "wayback.json"
    if wb.exists():
        for j in json.loads(wb.read_text()):
            if j.get("snapshot_url"):
                print(f"  ↗ Wayback: {j['snapshot_url']}")
    return ok and good > 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    folders = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        folders += [p] if (p / "manifest.json").exists() else sorted(m.parent for m in p.rglob("manifest.json"))
    if not folders:
        print("No captures found.")
        return 1
    with tempfile.TemporaryDirectory() as td:
        results = [check(f, Path(td)) for f in folders]
    passed = sum(results)
    print(f"\n{passed}/{len(results)} captures verified.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
