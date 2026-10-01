#!/usr/bin/env python3
"""
Proof-of-publication capture.

Every run:
  1. opens the page in a real Chrome browser and saves a full-page screenshot,
     a complete MHTML archive (HTML + images + CSS in one file) and the DOM;
  2. checks that the configured PDF is linked from the page and saves a
     screenshot with that link outlined;
  3. downloads the PDF through the same browser session;
  4. writes manifest.json with the SHA-256 of every file, the HTTP headers,
     server IP and TLS certificate details;
  5. gets manifest.json timestamped by independent RFC 3161 Time-Stamp
     Authorities (so the time cannot be back-dated by anyone, including you);
  6. asks the Internet Archive's Wayback Machine to make its own independent
     capture of the page and the PDF;
  7. asks archive.ph (archive.today) for a second independent copy of the page
     (archive.ph cannot save PDFs).

Settings live in config.toml. Run `python capture.py --help` for options.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

TOOL_VERSION = "1.0"
ROOT = Path(__file__).resolve().parent
UTC = dt.timezone.utc
TOOL_UA = f"proof-capture/{TOOL_VERSION} (+https://github.com)"
WAYBACK = os.environ.get("WAYBACK_BASE", "https://web.archive.org")


# ───────────────────────── small helpers ─────────────────────────

def log(msg: str = "") -> None:
    print(msg, flush=True)


def utcnow() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {(r.stderr or r.stdout).strip()[:400]}")
    return r


def http(url: str, data: bytes | None = None, headers: dict | None = None,
         timeout: int = 30, method: str | None = None):
    """Plain HTTP(S) request. Returns (status, headers, body, final_url); never raises on 4xx/5xx."""
    req = urllib.request.Request(url, data=data, headers={"User-Agent": TOOL_UA, **(headers or {})},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read() or b"", url


def set_output(**kv) -> None:
    """Pass values to later steps of the GitHub Actions workflow."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            for k, v in kv.items():
                f.write(f"{k}={v}\n")


def step_summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(md + "\n")


def norm_url(u: str) -> str:
    """Normalise a URL for comparison: lower-case scheme/host, decoded path, no #fragment."""
    p = urllib.parse.urlsplit(u.strip())
    netloc = p.netloc.lower()
    for default in (":443", ":80"):
        if netloc.endswith(default):
            netloc = netloc[: -len(default)]
    return urllib.parse.urlunsplit((p.scheme.lower(), netloc,
                                    urllib.parse.unquote(p.path or "/"),
                                    urllib.parse.unquote_plus(p.query), ""))


def resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)})
    except OSError as e:
        return [f"DNS error: {e}"]


def parse_time(value: str, tz: ZoneInfo) -> dt.datetime:
    t = dt.datetime.fromisoformat(value.strip())
    return t if t.tzinfo else t.replace(tzinfo=tz)


def load_config(path: Path) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    tgt = cfg.get("target", {})
    for key in ("page_url", "pdf_url"):
        if not str(tgt.get(key, "")).startswith(("http://", "https://")):
            sys.exit(f"config.toml: target.{key} must be a full http(s) URL")
    if "example.com" in tgt["page_url"]:
        log("WARNING: config.toml still has the example URL — edit target.page_url and target.pdf_url.")
    return cfg


# ───────────────────────── trusted timestamps ─────────────────────────

def ca_bundle(tmpdir: Path) -> Path:
    """Root certificates used to check timestamp tokens: tsa-certs/*.pem + the system trust store."""
    parts = []
    for p in sorted((ROOT / "tsa-certs").glob("*.pem")):
        parts.append(p.read_text())
    candidates = [ssl.get_default_verify_paths().cafile, "/etc/ssl/certs/ca-certificates.crt",
                  "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt"]
    try:
        import certifi  # optional
        candidates.append(certifi.where())
    except ImportError:
        pass
    for c in candidates:
        if c and Path(c).is_file():
            parts.append(Path(c).read_text())
            break
    out = tmpdir / "ca-bundle.pem"
    out.write_text("\n".join(parts))
    return out


def token_certs(tsr: Path, out_pem: Path) -> Path:
    """Extract the certificates the TSA embedded in its token (needed as 'untrusted' intermediates)."""
    with tempfile.TemporaryDirectory() as td:
        tok = Path(td) / "token.der"
        run(["openssl", "ts", "-reply", "-in", str(tsr), "-token_out", "-out", str(tok)])
        run(["openssl", "pkcs7", "-inform", "DER", "-in", str(tok), "-print_certs", "-out", str(out_pem)])
    return out_pem


def parse_tsr_text(text: str) -> dict:
    def grab(label):
        m = re.search(rf"^{label}:\s*(.+)$", text, re.M)
        return m.group(1).strip() if m else None
    raw = grab("Time stamp")
    when = None
    if raw:
        s = re.sub(r"\s+", " ", raw.replace(" GMT", "").replace(" UTC", ""))
        for fmt in ("%b %d %H:%M:%S.%f %Y", "%b %d %H:%M:%S %Y"):
            try:
                when = iso(dt.datetime.strptime(s, fmt).replace(tzinfo=UTC))
                break
            except ValueError:
                pass
    return {"status": grab("Status"), "time_raw": raw, "time_utc": when,
            "serial": grab("Serial number"), "tsa_name": grab("TSA"),
            "policy": grab("Policy OID"), "hash_algorithm": grab("Hash Algorithm")}


def verify_token(data_file: Path, tsr: Path, certs_pem: Path, tmpdir: Path) -> tuple[bool, str]:
    cmd = ["openssl", "ts", "-verify", "-data", str(data_file), "-in", str(tsr),
           "-CAfile", str(ca_bundle(tmpdir))]
    if certs_pem.exists() and "BEGIN CERTIFICATE" in certs_pem.read_text():
        cmd += ["-untrusted", str(certs_pem)]
    r = run(cmd, check=False)
    msg = (r.stdout + r.stderr).strip()
    if "Verification: OK" in msg:
        return True, "Verification: OK"
    lines = [l for l in msg.splitlines() if not l.startswith("Warning:")]
    return False, " | ".join(lines)[-400:] or "verification failed"


def ensure_tsa_roots(tsas: list[dict]) -> None:
    """Download each TSA's root certificate once into tsa-certs/ so verification is self-contained."""
    d = ROOT / "tsa-certs"
    d.mkdir(exist_ok=True)
    for t in tsas:
        url = t.get("root_url")
        dest = d / f"{t['name']}-root.pem"
        if not url or dest.exists():
            continue
        try:
            status, _, body, _ = http(url, timeout=20)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            if b"-----BEGIN CERTIFICATE-----" in body:
                dest.write_bytes(body)
            else:  # DER → PEM
                with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
                    f.write(body)
                run(["openssl", "x509", "-inform", "DER", "-in", f.name, "-out", str(dest)])
                os.unlink(f.name)
            log(f"  saved root certificate for {t['name']} → tsa-certs/{dest.name}")
        except Exception as e:
            log(f"  could not fetch root certificate for {t['name']}: {e}")


def timestamp_manifest(manifest: Path, tsas: list[dict], out: Path, errors: list) -> list[dict]:
    tdir = out / "timestamps"
    tdir.mkdir(exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for t in tsas:
            name = t["name"]
            tsq, tsr, certs = tdir / f"{name}.tsq", tdir / f"{name}.tsr", tdir / f"{name}-certs.pem"
            res = {"tsa": name, "url": t["url"], "ok": False}
            try:
                run(["openssl", "ts", "-query", "-data", str(manifest), "-sha256", "-cert", "-out", str(tsq)])
                last = None
                for attempt in range(3):
                    status, headers, body, _ = http(
                        t["url"], data=tsq.read_bytes(), method="POST", timeout=30,
                        headers={"Content-Type": "application/timestamp-query",
                                 "Accept": "application/timestamp-reply"})
                    if status == 200 and body:
                        break
                    last = f"HTTP {status}"
                    time.sleep(3 * (attempt + 1))
                else:
                    raise RuntimeError(f"TSA did not answer ({last})")
                tsr.write_bytes(body)
                info = parse_tsr_text(run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"]).stdout)
                res.update(info)
                if not (info["status"] or "").lower().startswith("granted"):
                    raise RuntimeError(f"TSA refused: {info['status']}")
                token_certs(tsr, certs)
                ok, msg = verify_token(manifest, tsr, certs, tmp)
                res.update(ok=True, verified_at_capture=ok, verify_message=msg)
                log(f"  {name}: {info['time_utc']}  (signature check: {'OK' if ok else msg})")
            except Exception as e:
                res["error"] = str(e)
                errors.append(f"timestamp {name}: {e}")
                log(f"  {name}: FAILED — {e}")
                if not res.get("time_utc"):  # no usable token: don't leave half-files behind
                    for p in (tsq, tsr, certs):
                        p.unlink(missing_ok=True)
            results.append(res)
    (tdir / "summary.json").write_text(json.dumps(results, indent=2))
    return results


# ───────────────────────── Wayback Machine ─────────────────────────

def wayback_due(state: Path, every_minutes: int, now: dt.datetime) -> bool:
    if every_minutes <= 0:
        return False
    try:
        last = dt.datetime.fromisoformat(state.read_text().strip())
    except (OSError, ValueError):
        return True
    # a little slack because GitHub's scheduler starts runs a few minutes late
    return now - last >= dt.timedelta(minutes=every_minutes) - dt.timedelta(minutes=3)


def wayback_capture(urls: list[str], budget_s: int = 120) -> list[dict]:
    key, secret = os.environ.get("IA_ACCESS_KEY"), os.environ.get("IA_SECRET_KEY")
    auth = {"Authorization": f"LOW {key}:{secret}"} if key and secret else {}
    jobs = []
    for url in urls:
        job = {"url": url, "mode": "api-key" if auth else "anonymous", "submitted_utc": iso(utcnow())}
        try:
            if auth:
                data = urllib.parse.urlencode({"url": url, "capture_all": "1"}).encode()
                status, h, body, final = http(f"{WAYBACK}/save", data=data, method="POST", timeout=60,
                                              headers={**auth, "Accept": "application/json"})
                j = json.loads(body or b"{}")
                if not j.get("job_id"):
                    raise RuntimeError(j.get("message") or f"HTTP {status}")
                job["job_id"] = j["job_id"]
            else:
                safe_url = urllib.parse.quote(url, safe=":/?&=%#+@!$,;~*'()[]")
                status, h, body, final = http(f"{WAYBACK}/save/{safe_url}", timeout=90)
                for cand in (h.get("Content-Location"), h.get("Location"), final):
                    m = re.search(r"/web/(\d{14})/", cand or "")
                    if m:
                        job["timestamp"] = m.group(1)
                        break
                else:
                    m = re.search(r'watchJob\(\s*"([^"]+)"', body.decode("utf-8", "replace"))
                    if not m:
                        raise RuntimeError(f"Save Page Now gave no job id (HTTP {status})")
                    job["job_id"] = m.group(1)
        except Exception as e:
            job["error"] = str(e)
        jobs.append(job)

    deadline = time.time() + budget_s
    while time.time() < deadline:
        pending = [j for j in jobs if j.get("job_id") and "timestamp" not in j and "error" not in j]
        if not pending:
            break
        time.sleep(6)
        for j in pending:
            try:
                status, _, body, _ = http(f"{WAYBACK}/save/status/{j['job_id']}", timeout=30,
                                          headers={**auth, "Accept": "application/json"})
                s = json.loads(body or b"{}")
                if s.get("status") == "success":
                    j["timestamp"] = s["timestamp"]
                    j["original_url"] = s.get("original_url", j["url"])
                elif s.get("status") == "error":
                    j["error"] = s.get("message") or s.get("status_ext") or "error"
            except Exception as e:
                j["last_poll_error"] = str(e)

    for j in jobs:
        if "timestamp" in j:
            j["snapshot_url"] = f"https://web.archive.org/web/{j['timestamp']}/{j.get('original_url', j['url'])}"
        elif "error" not in j:
            j["error"] = "still processing when the run ended (it may still appear in the Wayback Machine)"
    return jobs


# ───────────────────────── archive.ph (archive.today) ─────────────────────────
# archive.today has no official API: this does what its home-page form does, with
# plain HTTP requests (none of archive.today's own scripts are run). It saves web
# pages only, not PDFs, and it often answers automated requests with a captcha;
# when that happens the capture simply records it and moves on.

AT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
AT_BLOCKED = re.compile(r"g-recaptcha|h-captcha|hcaptcha|cf-chl|challenge-platform|One more step", re.I)


def _at_blocked(status: int, text: str) -> bool:
    return status == 429 or bool(AT_BLOCKED.search(text[:200000]))


def archive_today_capture(url: str, base: str, budget_s: int = 120) -> dict:
    base = base.rstrip("/")
    job = {"url": url, "service": base, "submitted_utc": iso(utcnow())}
    hdr = {"User-Agent": AT_UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
           "Accept-Language": "en-US,en;q=0.9"}
    captcha = "archive.ph asked for a captcha (it often does this to automated requests), so no copy this time"
    try:
        status, h, body, final = http(base + "/", headers=hdr, timeout=40)
        text = body.decode("utf-8", "replace")
        if _at_blocked(status, text):
            raise RuntimeError(captcha)
        if status >= 400:
            raise RuntimeError(f"archive.ph home page answered HTTP {status}")
        m = (re.search(r'name="submitid"[^>]*?value="([^"]+)"', text)
             or re.search(r'value="([^"]+)"[^>]*?name="submitid"', text))
        form = {"url": url, "anyway": "1", **({"submitid": m.group(1)} if m else {})}
        status, h, body, final = http(
            base + "/submit/", data=urllib.parse.urlencode(form).encode(), method="POST", timeout=120,
            headers={**hdr, "Content-Type": "application/x-www-form-urlencoded", "Referer": base + "/"})
        text = body.decode("utf-8", "replace")
        if _at_blocked(status, text):
            raise RuntimeError(captcha)

        target = None
        refresh = h.get("Refresh") or h.get("refresh") or ""
        meta = re.search(r'http-equiv="refresh"[^>]*content="[^"]*url=([^"]+)"', text, re.I)
        wip = re.search(re.escape(base) + r"/wip/[A-Za-z0-9]+", text)
        for cand in (refresh, meta.group(1) if meta else "", final, wip.group(0) if wip else ""):
            mm = re.search(r"(https?://[^\s;\"']+)", cand or "")
            if mm and mm.group(1).startswith(base) and not re.search(r"/(submit/?)?(\?.*)?$", mm.group(1)):
                target = mm.group(1)
                break
        if not target:
            raise RuntimeError(f"archive.ph gave no snapshot link (HTTP {status})")
        snap = target.replace("/wip/", "/")
        job["snapshot_url"] = snap

        # wait until archive.ph has finished building the copy
        deadline = time.time() + budget_s
        while True:
            s, _, b, f = http(snap, headers=hdr, timeout=40)
            if s == 200 and "/wip/" not in f and not _at_blocked(s, b.decode("utf-8", "replace")):
                job["ready"] = True
                job["ready_utc"] = iso(utcnow())
                break
            if time.time() >= deadline:
                job["ready"] = False
                job["note"] = "still being built when the run ended; the link should work a few minutes later"
                break
            time.sleep(8)
    except urllib.error.URLError as e:
        job["error"] = f"archive.ph could not be reached ({e.reason})"
    except Exception as e:
        job["error"] = str(e)
    return job


# ───────────────────────── the browser part ─────────────────────────

LINKS_JS = """() => Array.from(document.querySelectorAll('a[href]')).map((a, i) => {
  const r = a.getBoundingClientRect(), cs = getComputedStyle(a);
  return {index: i, href: a.href, text: (a.innerText || a.textContent || a.title || '').trim().slice(0, 300),
          x: Math.round(r.x + scrollX), y: Math.round(r.y + scrollY), width: Math.round(r.width), height: Math.round(r.height),
          visible: r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'};
})"""

SCROLL_JS = """async () => {
  const step = Math.max(window.innerHeight * 0.8, 400);
  for (let y = 0; y < document.documentElement.scrollHeight && y < 60000; y += step) {
    window.scrollTo(0, y); await new Promise(r => setTimeout(r, 150));
  }
  window.scrollTo(0, 0); await new Promise(r => setTimeout(r, 300));
}"""

OUTLINE_JS = """([i, label]) => {
  const a = document.querySelectorAll('a[href]')[i];
  if (!a) return false;
  a.scrollIntoView({block: 'center', inline: 'center'});
  a.style.setProperty('outline', '4px solid #e00', 'important');
  a.style.setProperty('outline-offset', '3px', 'important');
  const bar = document.createElement('div');
  bar.textContent = label;
  bar.setAttribute('style', 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;padding:6px 10px;' +
    'background:#111;color:#fff;font:12px/1.4 monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis');
  document.body.appendChild(bar);
  return true;
}"""


def tls_info(d):
    if not d:
        return d
    for k in ("validFrom", "validTo"):
        if isinstance(d.get(k), (int, float)):
            d[k + "_utc"] = iso(dt.datetime.fromtimestamp(d[k], UTC))
    return d


def launch(pw):
    errs = []
    for opts in ({"channel": "chrome"}, {}):
        try:
            return pw.chromium.launch(headless=True, **opts), opts.get("channel", "chromium")
        except Exception as e:
            errs.append(str(e).splitlines()[0])
    raise RuntimeError("could not start a browser: " + " | ".join(errs))


def capture_browser(cfg: dict, out: Path, errors: list) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    page_url, pdf_url = cfg["target"]["page_url"], cfg["target"]["pdf_url"]
    b = cfg.get("browser", {})
    info: dict = {"page": {"url": page_url}, "pdf": {"url": pdf_url}, "pdf_link": {"found": False}}

    with sync_playwright() as pw:
        browser, engine = launch(pw)
        version = browser.version
        ua = b.get("user_agent") or (
            f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version} Safari/537.36")
        info["browser"] = {"engine": engine, "version": version, "user_agent": ua,
                           "viewport": [b.get("viewport_width", 1440), b.get("viewport_height", 900)]}
        context = browser.new_context(
            user_agent=ua, locale=b.get("locale", "en-US"), timezone_id="UTC",
            viewport={"width": b.get("viewport_width", 1440), "height": b.get("viewport_height", 900)},
            device_scale_factor=1, accept_downloads=False)
        page = context.new_page()

        # ── load the page ──
        t0 = utcnow()
        try:
            resp = page.goto(page_url, wait_until="load", timeout=int(b.get("timeout_seconds", 60)) * 1000)
        except Exception as e:
            info["page"].update(loaded=False, error=str(e).splitlines()[0], requested_utc=iso(t0))
            errors.append(f"page did not load: {str(e).splitlines()[0]}")
            resp = None
        if resp is not None:
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PWTimeout:
                pass
            chain, r = [], resp.request.redirected_from
            while r:
                chain.insert(0, r.url)
                r = r.redirected_from
            info["page"].update(
                loaded=True, requested_utc=iso(t0), final_url=page.url, redirects=chain,
                http_status=resp.status, http_status_text=resp.status_text,
                headers=resp.all_headers(), server_address=resp.server_addr(),
                tls=tls_info(resp.security_details()), dns=resolve(urllib.parse.urlsplit(page.url).hostname or ""))
            if resp.status >= 400:
                errors.append(f"page answered HTTP {resp.status}")

            clicked = []
            for sel in b.get("dismiss_selectors", []):
                try:
                    page.locator(sel).first.click(timeout=3000)
                    clicked.append(sel)
                    page.wait_for_timeout(500)
                except Exception:
                    pass
            info["page"]["clicked_before_capture"] = clicked
            try:
                page.evaluate(SCROLL_JS)  # trigger lazy-loaded images
            except Exception:
                pass
            page.wait_for_timeout(int(float(b.get("settle_seconds", 3)) * 1000))
            info["page"]["title"] = page.title()
            info["page"]["rendered_utc"] = iso(utcnow())

            # ── evidence files (untouched page) ──
            try:
                page.screenshot(path=str(out / "page.png"), full_page=True, timeout=120000)
            except Exception as e:
                errors.append(f"full-page screenshot failed: {e}")
            try:
                cdp = context.new_cdp_session(page)
                mhtml = cdp.send("Page.captureSnapshot", {"format": "mhtml"})["data"]
                (out / "page.mhtml").write_text(mhtml, encoding="utf-8", newline="")
            except Exception as e:
                errors.append(f"MHTML archive failed: {e}")
            try:
                (out / "page.html").write_text(page.content(), encoding="utf-8")
            except Exception as e:
                errors.append(f"DOM save failed: {e}")

            # ── is the PDF linked from the page? ──
            try:
                links = page.evaluate(LINKS_JS)
            except Exception:
                links = []
            want = norm_url(pdf_url)
            matches = [l for l in links if norm_url(l["href"]) == want]
            info["pdf_link"] = {"found": bool(matches), "links_on_page": len(links),
                                "matches": matches[:5],
                                "other_pdf_links": [l["href"] for l in links
                                                    if ".pdf" in l["href"].lower()
                                                    and norm_url(l["href"]) != want][:20]}
            if matches:
                m = next((l for l in matches if l["visible"]), matches[0])
                try:
                    label = (f"{page.url}  ·  {iso(utcnow())}  ·  red outline and this bar added by "
                             f"proof-capture after the evidence files were saved")
                    if page.evaluate(OUTLINE_JS, [m["index"], label]):
                        page.wait_for_timeout(400)
                        page.screenshot(path=str(out / "link-in-context.png"))
                        info["pdf_link"]["highlighted"] = m
                except Exception as e:
                    errors.append(f"link screenshot failed: {e}")
            else:
                errors.append("the PDF link was NOT found on the page")

        # ── download the PDF through the same browser session ──
        t1 = utcnow()
        try:
            r = context.request.get(pdf_url, timeout=int(b.get("timeout_seconds", 60)) * 2000,
                                    max_redirects=10,
                                    headers={"Referer": page_url if page.url.startswith("about:") else page.url})
            body = r.body()
            headers = r.headers
            is_pdf = body[:5] == b"%PDF-"
            fname = "document.pdf" if is_pdf else "pdf-response.bin"
            (out / fname).write_bytes(body)
            cd = headers.get("content-disposition", "")
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd, re.I)
            info["pdf"].update(
                requested_utc=iso(t1), received_utc=iso(utcnow()), http_status=r.status,
                final_url=r.url, headers=headers, bytes=len(body), is_pdf=is_pdf, saved_as=fname,
                original_filename=urllib.parse.unquote(m.group(1)) if m else
                urllib.parse.unquote(Path(urllib.parse.urlsplit(r.url).path).name),
                dns=resolve(urllib.parse.urlsplit(r.url).hostname or ""))
            if r.status >= 400:
                errors.append(f"PDF answered HTTP {r.status}")
            elif not is_pdf:
                errors.append("the PDF URL did not return a PDF file")
        except Exception as e:
            info["pdf"].update(requested_utc=iso(t1), error=str(e).splitlines()[0])
            errors.append(f"PDF download failed: {str(e).splitlines()[0]}")

        context.close()
        browser.close()
    return info


# ───────────────────────── main ─────────────────────────

LOG_FIELDS = ["capture_utc", "capture_local", "folder", "page_http", "pdf_linked", "pdf_http",
              "pdf_sha256", "screenshot_sha256", "manifest_sha256", "timestamps", "wayback", "archive_ph",
              "problems"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=ROOT / "config.toml")
    ap.add_argument("--ignore-window", action="store_true", help="capture now even outside the time window")
    ap.add_argument("--archive", type=Path, default=ROOT / "archive", help="where captures are written")
    args = ap.parse_args()

    cfg = load_config(args.config)
    win = cfg.get("window", {})
    tz = ZoneInfo(win.get("timezone", "UTC"))
    start, end = parse_time(win["start"], tz), parse_time(win["end"], tz)
    now = utcnow()

    if not args.ignore_window:
        if now < start:
            log(f"Window has not started yet (starts {start.isoformat()}). Nothing to do.")
            set_output(status="not_started")
            return 0
        if now >= end:
            log(f"Window ended at {end.isoformat()}. Turning the schedule off.")
            set_output(status="ended")
            return 0

    stamp = now.strftime("%H%M%SZ")
    out = args.archive / now.strftime("%Y-%m-%d") / stamp
    out.mkdir(parents=True, exist_ok=False)
    rel = out.relative_to(args.archive.parent) if args.archive.parent in out.parents else out
    log(f"Capture {iso(now)}  →  {rel}")
    errors: list[str] = []

    # 1–3. browser capture
    try:
        info = capture_browser(cfg, out, errors)
    except Exception as e:
        traceback.print_exc()
        errors.append(f"browser capture crashed: {e}")
        info = {"page": {"url": cfg["target"]["page_url"]}, "pdf": {"url": cfg["target"]["pdf_url"]},
                "pdf_link": {"found": False}}
    finished = utcnow()

    # 4. manifest
    files = {}
    for p in sorted(out.rglob("*")):
        if p.is_file():
            files[str(p.relative_to(out))] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    gh = {k: os.environ.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                                         "GITHUB_SHA", "GITHUB_EVENT_NAME", "RUNNER_NAME")}
    run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{gh['GITHUB_REPOSITORY']}"
               f"/actions/runs/{gh['GITHUB_RUN_ID']}") if gh["GITHUB_RUN_ID"] else None
    manifest = {
        "about": "Evidence that the page and the linked PDF were publicly served at the time below. "
                 "The SHA-256 of this file is signed by independent RFC 3161 Time-Stamp Authorities "
                 "(see timestamps/). Check with: python verify.py <this folder>",
        "tool": f"proof-capture {TOOL_VERSION}",
        "capture_started_utc": iso(now),
        "capture_finished_utc": iso(finished),
        "capture_started_local": now.astimezone(tz).isoformat(timespec="seconds"),
        "window": {"start": start.isoformat(), "end": end.isoformat(), "ignored": args.ignore_window},
        "target": cfg["target"],
        **info,
        "files": files,
        "notes": {
            "page.png": "full-page screenshot of the page as loaded",
            "page.mhtml": "complete archive of the page (open in Chrome/Edge)",
            "page.html": "page HTML (DOM) after scripts ran",
            "link-in-context.png": "the PDF link on the page; the red outline was added by this tool AFTER the other files were saved",
            "document.pdf": "the PDF exactly as the server sent it",
        },
        "problems": errors,
        "runner": {"github": gh, "run_url": run_url, "os": platform.platform(), "python": platform.python_version()},
    }
    mpath = out / "manifest.json"
    mpath.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, default=str))
    (out / "SHA256SUMS").write_text(
        "".join(f"{v['sha256']}  {k}\n" for k, v in {**files, "manifest.json": {"sha256": sha256_file(mpath)}}.items()))
    manifest_hash = sha256_file(mpath)

    log(f"  page:   HTTP {info['page'].get('http_status', '—')}  {info['page'].get('title', '')!r}")
    log(f"  link:   {'found on page' if info['pdf_link'].get('found') else 'NOT FOUND on page'}")
    log(f"  pdf:    HTTP {info['pdf'].get('http_status', '—')}  {info['pdf'].get('bytes', 0):,} bytes")
    for name, v in files.items():
        log(f"  sha256  {v['sha256']}  {name}")
    log(f"  sha256  {manifest_hash}  manifest.json")

    # 5. trusted timestamps
    log("Timestamping manifest.json")
    tsas = cfg.get("tsa", [])
    ensure_tsa_roots(tsas)
    ts = timestamp_manifest(mpath, tsas, out, errors)
    if not any(t["ok"] for t in ts):
        errors.append("NO timestamp authority answered — this capture has no trusted time")

    # 6. Wayback Machine (independent third-party copy)
    wb_cfg = cfg.get("wayback", {})
    state = args.archive / ".wayback-last"
    wb = []
    if wayback_due(state, int(wb_cfg.get("every_minutes", 60)), now):
        log("Asking the Wayback Machine to capture the page and the PDF")
        wb = wayback_capture([cfg["target"]["page_url"], cfg["target"]["pdf_url"]],
                             int(wb_cfg.get("wait_seconds", 120)))
        (out / "wayback.json").write_text(json.dumps(wb, indent=2))
        for j in wb:
            log(f"  {j.get('snapshot_url') or 'failed: ' + j.get('error', '?')}")
        if any("snapshot_url" in j for j in wb):
            state.write_text(iso(now))

    # 7. archive.ph — a second independent copy of the page (archive.ph can't save PDFs)
    at_cfg = cfg.get("archive_today", {})
    at = []
    if at_cfg.get("enabled", True):
        log("Asking archive.ph to capture the page")
        at = [archive_today_capture(cfg["target"]["page_url"], at_cfg.get("url", "https://archive.ph"),
                                    int(at_cfg.get("wait_seconds", 120)))]
        (out / "archive-today.json").write_text(json.dumps(at, indent=2))
        for j in at:
            if "error" in j:
                log(f"  failed: {j['error']}")
            else:
                log(f"  {j['snapshot_url']}{'' if j.get('ready') else '  (still being built)'}")

    archive_problems = ([f"wayback {j['url']}: {j['error']}" for j in wb if "error" in j]
                        + [f"archive.ph: {j['error']}" for j in at if "error" in j])

    # log.csv — one line per capture
    logf = args.archive / "log.csv"
    if logf.exists():  # add any new columns to an older log
        with open(logf, newline="") as f:
            rows = list(csv.DictReader(f))
            old_fields = rows and list(rows[0].keys()) or None
        if old_fields is not None and old_fields != LOG_FIELDS:
            with open(logf, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=LOG_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
    new = not logf.exists()
    with open(logf, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if new:
            w.writeheader()
        w.writerow({
            "capture_utc": iso(now), "capture_local": now.astimezone(tz).isoformat(timespec="seconds"),
            "folder": str(out.relative_to(args.archive)),
            "page_http": info["page"].get("http_status", "error"),
            "pdf_linked": "yes" if info["pdf_link"].get("found") else "NO",
            "pdf_http": info["pdf"].get("http_status", "error"),
            "pdf_sha256": files.get("document.pdf", {}).get("sha256", ""),
            "screenshot_sha256": files.get("page.png", {}).get("sha256", ""),
            "manifest_sha256": manifest_hash,
            "timestamps": " ".join(f"{t['tsa']}={t.get('time_utc')}" for t in ts if t["ok"]) or "NONE",
            "wayback": " ".join(j["snapshot_url"] for j in wb if "snapshot_url" in j),
            "archive_ph": " ".join(j["snapshot_url"] for j in at if "snapshot_url" in j),
            "problems": "; ".join(errors + archive_problems),
        })

    ok_ts = [t for t in ts if t["ok"]]
    step_summary(
        f"### Capture {iso(now)}\n\n"
        f"| | |\n|---|---|\n"
        f"| Page | HTTP {info['page'].get('http_status', '—')} — {info['page'].get('title', '')} |\n"
        f"| PDF linked on page | {'yes' if info['pdf_link'].get('found') else '**NO**'} |\n"
        f"| PDF | HTTP {info['pdf'].get('http_status', '—')}, {info['pdf'].get('bytes', 0):,} bytes |\n"
        f"| manifest.json SHA-256 | `{manifest_hash}` |\n"
        + "".join(f"| Timestamp ({t['tsa']}) | {t.get('time_utc')} |\n" for t in ok_ts)
        + "".join(f"| Wayback ({'PDF' if j['url'] == cfg['target']['pdf_url'] else 'page'}) | "
                  f"{j.get('snapshot_url') or 'failed: ' + j.get('error', '?')} |\n" for j in wb)
        + "".join(f"| archive.ph (page) | "
                  f"{j.get('snapshot_url') or 'failed: ' + j.get('error', '?')} |\n" for j in at)
        + (f"\n**Problems:** {'; '.join(errors + archive_problems)}\n" if errors or archive_problems else ""))

    if errors or archive_problems:
        log("Problems: " + "; ".join(errors + archive_problems))
    set_output(status="captured", folder=str(rel), stamp=iso(now))
    return 0


if __name__ == "__main__":
    sys.exit(main())
