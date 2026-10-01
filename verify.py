#!/usr/bin/env python3
"""
Check the records made by capture.py.

    python verify.py archive                        # every record, plus a summary
    python verify.py archive --details              # ... and one line per record
    python verify.py archive/2026-10-02/080312Z     # one record, in detail

For each record it:
  • recomputes the SHA-256 of every file and compares it with manifest.json;
  • checks each RFC 3161 timestamp token against manifest.json and the
    Time-Stamp Authority's certificate chain (with OpenSSL), and reads the time
    each authority signed;
  • checks that the record names the record just before it and that record's
    exact SHA-256 (the chain), so a deleted, inserted or edited record shows up;
  • lists gaps between records longer than --gap minutes (default 20) and any alerts.

Needs Python 3.11+ and the `openssl` command. The times shown come from the
authorities' signatures, not from the capture tool's own clock.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from capture import ca_bundle, parse_tsr_text, run, sha256_file, token_certs, verify_token


def check_record(folder: Path, tmp: Path) -> dict:
    mpath = folder / "manifest.json"
    r = {"folder": folder, "manifest_sha256": sha256_file(mpath), "problems": [], "signed": []}
    try:
        m = json.loads(mpath.read_text())
    except ValueError:
        r["problems"].append("manifest.json is damaged")
        return r
    r["m"] = m
    for name, meta in m.get("files", {}).items():
        p = folder / name
        if not p.exists():
            r["problems"].append(f"{name} is missing")
        elif sha256_file(p) != meta["sha256"]:
            r["problems"].append(f"{name} has been changed")
    for tsr in sorted((folder / "timestamps").glob("*.tsr")):
        certs = tsr.with_name(f"{tsr.stem}-certs.pem")
        try:
            if not certs.exists():
                token_certs(tsr, certs)
            info = parse_tsr_text(run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"]).stdout)
            valid, msg = verify_token(mpath, tsr, certs, tmp)
        except Exception as e:
            valid, msg, info = False, str(e), {}
        if valid:
            r["signed"].append((tsr.stem, info.get("time_utc"), info.get("tsa_name")))
        else:
            r["problems"].append(f"{tsr.stem} timestamp does not match: {msg}")
    if not r["signed"]:
        r["problems"].append("no valid timestamp")
    return r


def when(m: dict) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(m["capture_started_utc"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError):
        return None


def line(r: dict) -> str:
    m = r.get("m", {})
    kind = m.get("type", "capture")
    sig = "  ".join(f"{n} {t[11:19] if t else '?'}" for n, t, _ in r["signed"])
    flag = "✗" if r["problems"] else "✓"
    extra = f"   ALERT: {'; '.join(m['alerts'])}" if m.get("alerts") else ""
    return f"  {flag} {m.get('capture_started_utc', '?'):<24} {kind:<7} signed {sig}{extra}"


def detail(r: dict, archive_root: Path | None) -> None:
    m = r.get("m", {})
    print(f"\n{r['folder']}")
    print(f"  type: {m.get('type', 'capture')}   started (runner clock): {m.get('capture_started_utc')}")
    if not any(p.endswith(("missing", "changed")) for p in r["problems"]):
        print(f"  ✓ all {len(m.get('files', {}))} files match manifest.json")
    for n, t, who in r["signed"]:
        print(f"  ✓ {n:<9} signed {t}  by {who}")
    for p in r["problems"]:
        print(f"  ✗ {p}")
    link = m.get("pdf_link", {}).get("found") or m.get("pdf_link_in_page_source", {}).get("found")
    print(f"  page HTTP {m.get('page', {}).get('http_status')}, PDF linked on page: {'yes' if link else 'NO'}, "
          f"PDF HTTP {m.get('pdf', {}).get('http_status')}"
          f"{', PDF CHANGED' if m.get('pdf_changed_since_previous_run') else ''}")
    if m.get("alerts"):
        print(f"  ⚠ alerts: {'; '.join(m['alerts'])}")
    prev = m.get("previous_record")
    if prev:
        print(f"  previous record: {prev.get('folder')}  ({prev.get('manifest_sha256', '')[:16]}…)")
    wb = r["folder"] / "wayback.json"
    if wb.exists():
        for j in json.loads(wb.read_text()):
            if j.get("snapshot_url"):
                print(f"  ↗ Wayback: {j['snapshot_url']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", type=Path, help="the archive folder, or one record folder")
    ap.add_argument("--details", action="store_true", help="print one line per record")
    ap.add_argument("--gap", type=float, default=20, help="report gaps longer than this many minutes")
    args = ap.parse_args()

    single = (args.path / "manifest.json").exists()
    folders = [args.path] if single else sorted(p.parent for p in args.path.rglob("manifest.json"))
    if not folders:
        print("No records found.")
        return 1

    with tempfile.TemporaryDirectory() as td:
        ca_bundle(Path(td))  # build the trusted-roots file once, before the parallel checks
        with ThreadPoolExecutor(max_workers=8) as pool:
            records = list(pool.map(lambda f: check_record(f, Path(td)), folders))

    if single:
        detail(records[0], None)
        return 0 if not records[0]["problems"] else 1

    root = args.path
    rel = {r["folder"].relative_to(root).as_posix(): r for r in records}
    names = list(rel)

    # chain: every record must name the record just before it, with that record's exact SHA-256
    breaks = []
    for i, name in enumerate(names):
        m = rel[name].get("m", {})
        if "previous_record" not in m:          # made by tool version 1, before the chain existed
            continue
        prev = m["previous_record"]
        if i == 0 or "previous_record" not in rel[names[i - 1]].get("m", {"previous_record": None}):
            if prev and prev.get("folder") not in rel:
                breaks.append(f"{name}: names {prev.get('folder')} as the previous record, which is not in the archive")
            continue
        if not prev:
            breaks.append(f"{name}: names no previous record, but {names[i - 1]} comes before it")
        elif prev.get("folder") != names[i - 1]:
            breaks.append(f"{name}: names {prev.get('folder')} as the previous record, "
                          f"but the record before it is {names[i - 1]}")
        elif prev.get("manifest_sha256") != rel[names[i - 1]]["manifest_sha256"]:
            breaks.append(f"{names[i - 1]}: its manifest.json was changed after {name} recorded it")

    times = [(n, when(rel[n].get("m", {}))) for n in names]
    times = [(n, t) for n, t in times if t]
    gaps = [(a, b, (tb - ta).total_seconds() / 60) for (a, ta), (b, tb) in zip(times, times[1:])
            if (tb - ta).total_seconds() / 60 > args.gap]
    bad = [r for r in records if r["problems"]]
    alerts = [r for r in records if r.get("m", {}).get("alerts")]
    kinds = [r.get("m", {}).get("type", "capture") for r in records]

    if args.details:
        print("Records:")
        for r in records:
            print(line(r))
    elif bad or alerts:
        print("Records with problems or alerts:")
        for r in records:
            if r["problems"] or r.get("m", {}).get("alerts"):
                print(line(r))
                for p in r["problems"]:
                    print(f"      ✗ {p}")

    first, last = (times[0][1], times[-1][1]) if times else (None, None)
    print("\nSummary")
    older = kinds.count("capture")
    older_txt = f", {older:,} older captures" if older else ""
    print(f"  records:     {len(records):,}  ({kinds.count('check'):,} checks, "
          f"{kinds.count('full'):,} full captures{older_txt})")
    if first:
        print(f"  period:      {first:%Y-%m-%d %H:%M} → {last:%Y-%m-%d %H:%M} UTC")
    files_bad = any("changed" in p or "missing" in p for r in bad for p in r["problems"])
    print("  files:       " + ("✗ some files were changed or are missing (see above)" if files_bad
                              else "✓ all match their fingerprints"))
    signed = sum(len(r["signed"]) for r in records)
    nots = sum(1 for r in records if not r["signed"])
    print(f"  timestamps:  {signed:,} signatures verified" + (f", ✗ {nots} records without a valid one" if nots else " ✓"))
    if breaks:
        print(f"  chain:       ✗ {len(breaks)} break(s)")
        for b in breaks:
            print(f"      ✗ {b}")
    else:
        print("  chain:       ✓ unbroken — no record has been removed, added or edited")
    if gaps:
        longest = max(gaps, key=lambda g: g[2])
        print(f"  gaps > {args.gap:g} min: {len(gaps)}  (longest {longest[2]:.0f} min, {longest[0]} → {longest[1]})")
        for a, b, mins in gaps[:20]:
            print(f"      {mins:5.0f} min  {a} → {b}")
        if len(gaps) > 20:
            print(f"      … and {len(gaps) - 20} more")
    else:
        print(f"  gaps > {args.gap:g} min: none")
    print(f"  alerts:      {len(alerts)}" + ("" if alerts else "  ✓"))

    ok = not bad and not breaks
    print(f"\n{'All records verified.' if ok else 'Verification found problems (see above).'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
