#!/usr/bin/env python3
"""
Proof-of-publication capture.

Runs every 10 minutes (see .github/workflows/capture.yml). Every run:
  1. QUICK CHECK: downloads the page's HTML exactly as the server sends it and
     the PDF, checks that the PDF is linked on the page, and fingerprints both;
  2. FULL CAPTURE, at the first run of every 6-hour block, on every manual run,
     and whenever something looks different (page down, link missing, PDF
     changed, page text changed): opens the page in a real Chrome browser and
     saves a full-page screenshot, a complete MHTML copy, the rendered page and
     a screenshot of the PDF link outlined;
  3. writes manifest.json with the SHA-256 of every file, the HTTP headers and
     server details, and the SHA-256 of the PREVIOUS run's manifest, so all
     runs form one unbroken chain (a missing or edited record breaks it);
  4. gets manifest.json timestamped by independent RFC 3161 Time-Stamp
     Authorities (so the time cannot be back-dated by anyone, including you);
  5. about once an hour, asks the Internet Archive's Wayback Machine to make
     its own independent copy of the page and the PDF (a copy that fails, e.g.
     because the Wayback Machine is busy, is tried again on the next run);
  6. marks the GitHub run as failed (GitHub then emails you) when the page goes
     down, the PDF link disappears, or the PDF goes missing or changes; while a
     problem lasts, it reminds you once per 6-hour block, not every 10 minutes.

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
from html.parser import HTMLParser
from pathlib import Path
from zoneinfo import ZoneInfo

TOOL_VERSION = "2.0"
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
    url = urllib.parse.quote(url.strip(), safe=":/?#[]@!$&'()*+,;=%~")  # spaces etc.; keeps %XX as is
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
    """Normalise a URL for comparison: http = https, www. ignored, decoded path, no #fragment."""
    p = urllib.parse.urlsplit(u.strip())
    netloc = p.netloc.lower()
    for default in (":443", ":80"):
        if netloc.endswith(default):
            netloc = netloc[: -len(default)]
    netloc = netloc.removeprefix("www.")  # example.com and www.example.com count as the same site
    return urllib.parse.urlunsplit(("https" if p.scheme.lower() in ("http", "https") else p.scheme.lower(), netloc,
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
    out = tmpdir / "ca-bundle.pem"
    if out.exists():
        return out
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
    tmp = out.with_name(f"ca-bundle.{os.getpid()}.{id(parts)}.tmp")
    tmp.write_text("\n".join(parts))
    os.replace(tmp, out)  # atomic, so a parallel reader never sees half a file
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

def wayback_due(last_utc: str | None, every_minutes: int, now: dt.datetime) -> bool:
    if every_minutes <= 0:
        return False
    try:
        last = dt.datetime.fromisoformat(last_utc.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return True
    # a little slack because GitHub's scheduler starts runs a few minutes late
    return now - last >= dt.timedelta(minutes=every_minutes) - dt.timedelta(minutes=3)


class WaybackBusy(RuntimeError):
    pass


def _wayback_submit(url: str, auth: dict) -> dict:
    """Ask Save Page Now for a capture; returns {"job_id"} or {"timestamp"}."""
    if auth:
        data = urllib.parse.urlencode({"url": url, "capture_all": "1"}).encode()
        status, h, body, final = http(f"{WAYBACK}/save", data=data, method="POST", timeout=60,
                                      headers={**auth, "Accept": "application/json"})
        if status == 429:
            raise WaybackBusy("HTTP 429")
        try:
            j = json.loads(body or b"{}")
        except ValueError:
            j = {}
        if not j.get("job_id"):
            msg = j.get("message") or f"HTTP {status}"
            if "limit" in msg.lower() or "too many" in msg.lower():
                raise WaybackBusy(msg)
            raise RuntimeError(msg)
        return {"job_id": j["job_id"]}
    safe_url = urllib.parse.quote(url, safe=":/?&=%#+@!$,;~*'()[]")
    status, h, body, final = http(f"{WAYBACK}/save/{safe_url}", timeout=90)
    if status == 429:
        raise WaybackBusy("HTTP 429")
    for cand in (h.get("Content-Location"), h.get("Location"), final):
        m = re.search(r"/web/(\d{14})/", cand or "")
        if m:
            return {"timestamp": m.group(1)}
    m = re.search(r'watchJob\(\s*"([^"]+)"', body.decode("utf-8", "replace"))
    if not m:
        raise RuntimeError(f"Save Page Now gave no job id (HTTP {status})")
    return {"job_id": m.group(1)}


def wayback_capture(urls: list[str], budget_s: int = 120, pause_s: float = 15) -> list[dict]:
    """Submit each URL with a pause in between; if the Wayback Machine says it is busy
    (HTTP 429, too many requests), wait and try once more. Then wait for the copies."""
    key, secret = os.environ.get("IA_ACCESS_KEY"), os.environ.get("IA_SECRET_KEY")
    auth = {"Authorization": f"LOW {key}:{secret}"} if key and secret else {}
    jobs = []
    for i, url in enumerate(urls):
        if i:
            time.sleep(pause_s)  # back-to-back requests are what usually triggers HTTP 429
        job = {"url": url, "mode": "api-key" if auth else "anonymous", "submitted_utc": iso(utcnow())}
        for attempt in (1, 2):
            try:
                job.update(_wayback_submit(url, auth))
                job.pop("error", None)
                break
            except WaybackBusy as e:
                job["error"] = (f"the Wayback Machine was busy ({e}, too many requests); "
                                f"it will be tried again on the next run")
                if attempt == 1:
                    time.sleep(pause_s * 2)
                    job["retried_utc"] = iso(utcnow())
            except Exception as e:
                job["error"] = str(e)
                break
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


# ───────────────────────── quick check (every run) ─────────────────────────
# The page's HTML exactly as the server sends it, and the PDF. No browser, so it
# takes seconds; a full browser capture follows when needed (see main()).

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")


class _LinksAndText(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.text, self.base, self._skip = [], [], None, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"].strip())
        elif tag == "base" and a.get("href") and not self.base:
            self.base = a["href"].strip()

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)


def _short(e: Exception) -> str:
    if isinstance(e, urllib.error.URLError) and not isinstance(e, urllib.error.HTTPError):
        return f"could not connect ({e.reason})"
    return (str(e).splitlines() or [type(e).__name__])[0][:300]


def _header(headers: dict, name: str) -> str:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), "")


def quick_check(cfg: dict, out: Path, errors: list) -> dict:
    page_url, pdf_url = cfg["target"]["page_url"], cfg["target"]["pdf_url"]
    timeout = int(cfg.get("browser", {}).get("timeout_seconds", 60))
    hdr = {"User-Agent": BROWSER_UA, "Accept-Language": "en-US,en;q=0.9",
           "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    info: dict = {"page": {"url": page_url, "method": "plain HTTP request"},
                  "pdf": {"url": pdf_url}, "pdf_link": {"found": False, "method": "page source"}}

    t0 = utcnow()
    try:
        status, headers, body, final = http(page_url, headers=hdr, timeout=timeout)
        (out / "page-source.html").write_bytes(body)
        m = re.search(r"charset=([\w-]+)", _header(headers, "Content-Type"), re.I)
        text = body.decode(m.group(1) if m else "utf-8", "replace")
        parser = _LinksAndText()
        parser.feed(text)
        base = urllib.parse.urljoin(final, parser.base) if parser.base else final
        links = [urllib.parse.urljoin(base, h) for h in parser.links]
        want = norm_url(pdf_url)
        found = [l for l in links if norm_url(l) == want]
        visible = re.sub(r"\s+", " ", " ".join(parser.text)).strip()
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        info["page"].update(
            loaded=True, requested_utc=iso(t0), received_utc=iso(utcnow()), http_status=status,
            final_url=final, headers=headers, bytes=len(body),
            title=re.sub(r"\s+", " ", title.group(1)).strip() if title else "",
            text_sha256=hashlib.sha256(visible.encode()).hexdigest(),
            dns=resolve(urllib.parse.urlsplit(final).hostname or ""))
        info["pdf_link"].update(found=bool(found), links_on_page=len(links), matches=found[:5])
        if status >= 400:
            errors.append(f"page answered HTTP {status}")
    except Exception as e:
        info["page"].update(loaded=False, requested_utc=iso(t0), error=_short(e))
        errors.append(f"page did not load: {_short(e)}")

    t1 = utcnow()
    try:
        status, headers, body, final = http(
            pdf_url, timeout=timeout * 2,
            headers={**hdr, "Accept": "application/pdf,*/*;q=0.8", "Referer": page_url})
        is_pdf = body[:5] == b"%PDF-"
        fname = "document.pdf" if is_pdf else "pdf-response.bin"
        (out / fname).write_bytes(body)
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', _header(headers, "Content-Disposition"), re.I)
        info["pdf"].update(
            requested_utc=iso(t1), received_utc=iso(utcnow()), http_status=status, final_url=final,
            headers=headers, bytes=len(body), is_pdf=is_pdf, saved_as=fname,
            sha256=hashlib.sha256(body).hexdigest(),
            original_filename=urllib.parse.unquote(m.group(1) if m else
                                                   Path(urllib.parse.urlsplit(final).path).name),
            dns=resolve(urllib.parse.urlsplit(final).hostname or ""))
        if status >= 400:
            errors.append(f"PDF answered HTTP {status}")
        elif not is_pdf:
            errors.append("the PDF link did not return a PDF file")
    except Exception as e:
        info["pdf"].update(requested_utc=iso(t1), error=_short(e))
        errors.append(f"PDF download failed: {_short(e)}")
    return info


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
    info: dict = {"page": {"url": page_url, "method": "Chrome browser"},
                  "pdf_link": {"found": False, "method": "rendered page"}}

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
                errors.append("the PDF link was NOT found on the page (checked in the browser too)")

        context.close()
        browser.close()
    return info


# ───────────────────────── main ─────────────────────────

LOG_FIELDS = ["capture_utc", "capture_local", "type", "folder", "page_http", "pdf_linked", "pdf_http",
              "pdf_sha256", "pdf_changed", "page_text_changed", "screenshot_sha256", "manifest_sha256",
              "previous_manifest_sha256", "timestamps", "wayback", "alerts", "problems"]

NOTES = {
    "page-source.html": "the page's HTML exactly as the server sent it, before any scripts ran",
    "document.pdf": "the PDF exactly as the server sent it",
    "pdf-response.bin": "what the PDF link returned (it was not a PDF file)",
    "page.png": "full-page screenshot of the page as loaded in Chrome",
    "page.mhtml": "complete copy of the page as loaded in Chrome (open in Chrome or Edge)",
    "page.html": "the page's HTML after its scripts ran in Chrome",
    "link-in-context.png": "the PDF link on the page; the red outline and caption bar were added by "
                           "this tool AFTER the other files were saved",
}


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def minutes_since(value: str | None, now: dt.datetime) -> float:
    try:
        return (now - dt.datetime.fromisoformat(value.replace("Z", "+00:00"))).total_seconds() / 60
    except (AttributeError, ValueError):
        return float("inf")


def block_of(t: dt.datetime, hours: int) -> str:
    return f"{t:%Y-%m-%d}/{t.hour // hours}"


def write_log(logf: Path, row: dict) -> None:
    if logf.exists():  # add any new columns to an older log
        with open(logf, newline="") as f:
            rows = list(csv.DictReader(f))
            old = rows[0].keys() if rows else None
        if old is not None and list(old) != LOG_FIELDS:
            with open(logf, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=LOG_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
    new = not logf.exists()
    with open(logf, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=ROOT / "config.toml")
    ap.add_argument("--ignore-window", action="store_true", help="run now even outside the time window")
    ap.add_argument("--full", action="store_true", help="always do a full browser capture")
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

    full_every = int(cfg.get("checks", {}).get("full_capture_every_hours", 6))
    if full_every not in (1, 2, 3, 4, 6, 8, 12, 24):
        full_every = 6
    args.archive.mkdir(parents=True, exist_ok=True)
    state_path = args.archive / ".state.json"
    state = load_state(state_path)

    out = args.archive / now.strftime("%Y-%m-%d") / now.strftime("%H%M%SZ")
    out.mkdir(parents=True, exist_ok=False)
    folder = out.relative_to(args.archive).as_posix()
    rel = out.relative_to(args.archive.parent) if args.archive.parent in out.parents else out
    log(f"Run {iso(now)}  →  {rel}")
    errors: list[str] = []

    # 1. quick check
    info = quick_check(cfg, out, errors)
    page_ok = info["page"].get("loaded") and info["page"].get("http_status", 999) < 400
    pdf = info["pdf"]
    pdf_ok = pdf.get("is_pdf") and pdf.get("http_status", 999) < 400
    prev_pdf, pdf_sha = state.get("pdf_sha256"), pdf.get("sha256") if pdf_ok else None
    pdf_changed = bool(prev_pdf and pdf_sha and pdf_sha != prev_pdf)
    prev_text, text_sha = state.get("page_text_sha256"), info["page"].get("text_sha256") if page_ok else None
    text_changed = bool(prev_text and text_sha and text_sha != prev_text)
    log(f"  quick check: page HTTP {info['page'].get('http_status', '—')}, "
        f"PDF link {'found' if info['pdf_link']['found'] else 'NOT found'} in page source, "
        f"PDF HTTP {pdf.get('http_status', '—')}"
        f"{', PDF CHANGED' if pdf_changed else ''}{', page text changed' if text_changed else ''}")

    # 2. full capture when it's due or something looks different
    reasons = []
    if args.full:
        reasons.append("manual run")
    new_block = state.get("last_full_block") != block_of(now, full_every)
    if new_block:
        reasons.append(f"first run in this {full_every}-hour block")
    if not page_ok:
        reasons.append("page problem")
    elif not info["pdf_link"]["found"]:
        reasons.append("PDF link not found in page source")
    if not pdf_ok:
        reasons.append("PDF problem")
    if pdf_changed:
        reasons.append("PDF changed")
    if text_changed and minutes_since(state.get("last_text_full_utc"), now) >= 60:
        reasons.append("page text changed")
    if state.get("last_alerts") and page_ok and pdf_ok and info["pdf_link"]["found"]:
        reasons.append("back to normal after a problem")
    full = bool(reasons)

    if full:
        log(f"Full browser capture ({'; '.join(reasons)})")
        quick = info
        try:
            b = capture_browser(cfg, out, errors)
        except Exception as e:
            traceback.print_exc()
            errors.append(f"browser capture crashed: {e}")
            b = {"page": {"url": cfg["target"]["page_url"], "loaded": False, "error": str(e)},
                 "pdf_link": {"found": False}}
        info = {"page": b["page"], "page_source": quick["page"], "pdf_link": b["pdf_link"],
                "pdf_link_in_page_source": quick["pdf_link"], "pdf": quick["pdf"], "browser": b.get("browser")}
        # the page is up / the link is there if EITHER the plain request or the browser saw it
        page_ok = page_ok or (b["page"].get("loaded") and b["page"].get("http_status", 999) < 400)
        link_found = quick["pdf_link"]["found"] or b["pdf_link"].get("found", False)
    else:
        link_found = info["pdf_link"]["found"]
    finished = utcnow()

    alerts = []
    if not page_ok:
        alerts.append("page down or not loading")
    elif not link_found:
        alerts.append("PDF link missing from the page")
    if not pdf_ok:
        alerts.append("PDF missing or not loading")
    if pdf_changed:
        alerts.append("PDF changed since the previous run")

    errors[:] = list(dict.fromkeys(errors))  # the quick check and the browser may report the same thing

    # 3. manifest, chained to the previous run
    files = {}
    for p in sorted(out.rglob("*")):
        if p.is_file():
            files[p.relative_to(out).as_posix()] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    gh = {k: os.environ.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                                         "GITHUB_SHA", "GITHUB_EVENT_NAME", "RUNNER_NAME")}
    run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{gh['GITHUB_REPOSITORY']}"
               f"/actions/runs/{gh['GITHUB_RUN_ID']}") if gh["GITHUB_RUN_ID"] else None
    previous = state.get("chain_head")
    manifest = {
        "about": "Evidence that the page and the linked PDF were publicly served at the time below. "
                 "previous_record names the previous run and the SHA-256 of its manifest.json, so all runs "
                 "form one unbroken chain. The SHA-256 of this file is signed by independent RFC 3161 "
                 "Time-Stamp Authorities (see timestamps/). Check everything with: python verify.py archive",
        "tool": f"proof-capture {TOOL_VERSION}",
        "type": "full" if full else "check",
        "full_capture_reasons": reasons,
        "previous_record": previous,
        "capture_started_utc": iso(now),
        "capture_finished_utc": iso(finished),
        "capture_started_local": now.astimezone(tz).isoformat(timespec="seconds"),
        "window": {"start": start.isoformat(), "end": end.isoformat(), "ignored": args.ignore_window},
        "target": cfg["target"],
        **info,
        "pdf_changed_since_previous_run": pdf_changed,
        "page_text_changed_since_previous_run": text_changed,
        "alerts": alerts,
        "files": files,
        "notes": {k: v for k, v in NOTES.items() if k in files},
        "problems": errors,
        "runner": {"github": gh, "run_url": run_url, "os": platform.platform(), "python": platform.python_version()},
    }
    mpath = out / "manifest.json"
    mpath.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, default=str))
    manifest_hash = sha256_file(mpath)
    (out / "SHA256SUMS").write_text("".join(f"{v['sha256']}  {k}\n" for k, v in files.items())
                                    + f"{manifest_hash}  manifest.json\n")
    for name, v in files.items():
        log(f"  sha256  {v['sha256']}  {name}")
    log(f"  sha256  {manifest_hash}  manifest.json")
    if previous:
        log(f"  chained to {previous.get('folder')} ({previous.get('manifest_sha256', '')[:16]}…)")

    # 4. trusted timestamps
    log("Timestamping manifest.json")
    tsas = cfg.get("tsa", [])
    ensure_tsa_roots(tsas)
    ts = timestamp_manifest(mpath, tsas, out, errors)
    if not any(t["ok"] for t in ts):
        errors.append("NO timestamp authority answered — this run has no trusted time")

    # 5. Wayback Machine (independent third-party copy)
    wb_cfg = cfg.get("wayback", {})
    wb_last = state.setdefault("wayback", {})  # last successful Wayback copy, per link
    due = [u for u in (cfg["target"]["page_url"], cfg["target"]["pdf_url"])
           if wayback_due(wb_last.get(u) or state.get("wayback_last_utc"),
                          int(wb_cfg.get("every_minutes", 60)), now)]
    wb = []
    if due:
        log("Asking the Wayback Machine to capture " +
            " and ".join("the PDF" if u == cfg["target"]["pdf_url"] else "the page" for u in due))
        wb = wayback_capture(due, int(wb_cfg.get("wait_seconds", 120)))
        (out / "wayback.json").write_text(json.dumps(wb, indent=2))
        for j in wb:
            log(f"  {j.get('snapshot_url') or 'failed: ' + j.get('error', '?')}")
    wb_problems = [f"wayback {j['url']}: {j['error']}" for j in wb if "error" in j]

    # 6. remember where we are
    state["chain_head"] = {"folder": folder, "manifest_sha256": manifest_hash, "capture_utc": iso(now)}
    if pdf_sha:
        state["pdf_sha256"] = pdf_sha
    if text_sha:
        state["page_text_sha256"] = text_sha
    if full and (out / "page.png").exists():
        state["last_full_block"] = block_of(now, full_every)
        state["last_full_utc"] = iso(now)
        if "page text changed" in reasons:
            state["last_text_full_utc"] = iso(now)
    legacy = state.pop("wayback_last_utc", None)  # older versions kept one time for both links
    for u in (cfg["target"]["page_url"], cfg["target"]["pdf_url"]):
        if legacy and u not in wb_last and u not in due:
            wb_last[u] = legacy
    for j in wb:
        if "snapshot_url" in j:
            wb_last[j["url"]] = iso(now)
    # email (via a failed run) when a problem starts or changes, and as a reminder
    # once per block while it lasts, rather than every 10 minutes
    notify = bool(alerts) and (sorted(alerts) != sorted(state.get("last_alerts") or []) or new_block)
    state["last_alerts"] = alerts
    state_path.write_text(json.dumps(state, indent=2))

    ok_ts = [t for t in ts if t["ok"]]
    write_log(args.archive / "log.csv", {
        "capture_utc": iso(now), "capture_local": now.astimezone(tz).isoformat(timespec="seconds"),
        "type": "full" if full else "check", "folder": folder,
        "page_http": info["page"].get("http_status", "error"),
        "pdf_linked": "yes" if link_found else "NO",
        "pdf_http": pdf.get("http_status", "error"),
        "pdf_sha256": pdf.get("sha256", ""),
        "pdf_changed": "YES" if pdf_changed else "",
        "page_text_changed": "yes" if text_changed else "",
        "screenshot_sha256": files.get("page.png", {}).get("sha256", ""),
        "manifest_sha256": manifest_hash,
        "previous_manifest_sha256": (previous or {}).get("manifest_sha256", ""),
        "timestamps": " ".join(f"{t['tsa']}={t.get('time_utc')}" for t in ok_ts) or "NONE",
        "wayback": " ".join(j["snapshot_url"] for j in wb if "snapshot_url" in j),
        "alerts": "; ".join(alerts),
        "problems": "; ".join(errors + wb_problems),
    })

    problems = errors + wb_problems
    step_summary(
        f"### {'Full capture' if full else 'Check'} {iso(now)}\n\n"
        + (f"**⚠ ALERT: {'; '.join(alerts)}**\n\n" if alerts else "")
        + "| | |\n|---|---|\n"
        f"| Page | HTTP {info['page'].get('http_status', '—')} — {info['page'].get('title', '')} |\n"
        f"| PDF linked on page | {'yes' if link_found else '**NO**'} |\n"
        f"| PDF | HTTP {pdf.get('http_status', '—')}, {pdf.get('bytes', 0):,} bytes"
        f"{' — **changed**' if pdf_changed else ''} |\n"
        + (f"| Full capture because | {'; '.join(reasons)} |\n" if full else "")
        + f"| manifest.json SHA-256 | `{manifest_hash}` |\n"
        f"| Previous record | {(previous or {}).get('folder', '— (first record)')} |\n"
        + "".join(f"| Timestamp ({t['tsa']}) | {t.get('time_utc')} |\n" for t in ok_ts)
        + "".join(f"| Wayback ({'PDF' if j['url'] == cfg['target']['pdf_url'] else 'page'}) | "
                  f"{j.get('snapshot_url') or 'failed: ' + j.get('error', '?')} |\n" for j in wb)
        + (f"\n**Problems:** {'; '.join(problems)}\n" if problems else ""))

    if problems:
        log("Problems: " + "; ".join(problems))
    if alerts:
        log("ALERT: " + "; ".join(alerts) + ("" if notify else "  (ongoing — already reported)"))
    set_output(status="captured", folder=str(rel), stamp=iso(now), type="full" if full else "check",
               alert="true" if notify else "false", alert_reason="; ".join(alerts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
