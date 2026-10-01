# proof-capture

Four times a day (every 6 hours) during a time window you choose, GitHub opens your web page in Chrome, saves a full-page screenshot and a complete copy of the page, checks that your PDF is linked on it, downloads that PDF, and has the whole capture signed by two independent timestamp authorities. Each time it also asks the Wayback Machine to make its own copy. Each capture is committed to this repository, and the schedule switches itself off when the window ends.

## Setup (about 10 minutes)

1. **Create a private repository** on GitHub, for example `proof-capture`. Leave it empty: no README and no licence.
2. **Edit `config.toml`** before uploading:
   - `page_url`: the page you want to prove was live.
   - `pdf_url`: the PDF link on that page. Right-click the link, choose **Copy link address**, and paste it.
   - `start` and `end`: the capture window, in Romanian time (`timezone = "Europe/Bucharest"`).
3. **Upload the files.** The simplest way is git:
   ```bash
   cd proof-capture
   git init -b main && git add . && git commit -m "Set up proof capture"
   git remote add origin https://github.com/<your-username>/proof-capture.git
   git push -u origin main
   ```
   Uploading through the GitHub website works too, but the `.github` folder is hidden on a Mac (press **Cmd + Shift + .** in Finder to show it). Make sure `.github/workflows/capture.yml` ends up in the repository.
4. **Do a test run.** Open the **Actions** tab and enable workflows if GitHub asks. Choose **Capture page + PDF** → **Run workflow**, tick *Capture now, even outside the window*, and run it. About a minute later a new folder appears under `archive/`. The run's **Summary** page shows the page status, whether the PDF link was found, the timestamps and any problems.

That's all. Captures start at `start`, run 4 times a day, and stop at `end`.

**Capture times** (set in `.github/workflows/capture.yml`, which GitHub reads in UTC): 00:07, 06:07, 12:07 and 18:07 UTC. In Romania that's 03:07, 09:07, 15:07 and 21:07 in summer time, and 02:07, 08:07, 14:07 and 20:07 from 25 October 2026. To pick other times, change the hours in the `cron` line, for example `"7 6,10,14,18 * * *"` for four daytime captures. You can also capture at any moment with **Actions → Capture page + PDF → Run workflow**.

**Optional: more reliable Wayback captures.** Anonymous Wayback requests are rate-limited. A free archive.org account helps: get keys from <https://archive.org/account/s3.php>, then add them under **Settings → Secrets and variables → Actions** as `IA_ACCESS_KEY` and `IA_SECRET_KEY`.

## What each capture contains

`archive/YYYY-MM-DD/HHMMSSZ/` (the folder name is the UTC time):

| File | What it is |
|---|---|
| `page.png` | Full-page screenshot of the page as loaded |
| `page.mhtml` | Complete copy of the page (HTML, images and CSS in one file). Opens in Chrome or Edge. |
| `page.html` | The page's HTML after its scripts ran |
| `link-in-context.png` | The PDF link on the page, outlined in red, with the URL and time in a caption bar. The outline and caption are added *after* the other files are saved. |
| `document.pdf` | The PDF exactly as the server sent it |
| `manifest.json` | SHA-256 of every file above, HTTP status and headers (including the server's own `Date`), server IP, DNS, TLS certificate, redirects, browser version, and the GitHub run link |
| `SHA256SUMS` | The same hashes in the standard `sha256sum -c` format |
| `timestamps/` | RFC 3161 tokens from DigiCert and FreeTSA over `manifest.json` (`.tsr`), plus the request and certificates |
| `wayback.json` | Wayback Machine snapshot links |

`archive/log.csv` has one line per capture, so you can see every capture time and any gaps at a glance.

## Checking a capture

Anyone with Python 3.11+ and `openssl` can check a capture:

```bash
python verify.py archive                       # every capture
python verify.py archive/2026-10-02/060312Z    # just one
```

It recomputes every file hash and checks each timestamp signature against the authority's certificate. If even one byte of a file or the manifest had changed, the check fails. You can also check with OpenSSL directly:

```bash
openssl ts -verify -data manifest.json -in timestamps/freetsa.tsr \
  -CAfile ../../../tsa-certs/freetsa-root.pem -untrusted timestamps/freetsa-certs.pem
```

## What this proves, and its limits

- **Timestamp tokens** prove that these exact files existed *no later than* the signed time. Two separate companies sign each capture, so neither GitHub's clock nor yours is being trusted.
- **Wayback Machine snapshots** are copies the Internet Archive made itself, from its own servers. They are the strongest independent evidence that the site really served the content.
- **GitHub Actions logs** print every hash for every run, which gives you another third-party record. GitHub keeps logs for 90 days by default. You can raise this under **Settings → Actions → General**, or download the logs you need.
- **Coverage:** each capture proves the page was live at that moment. With 4 captures a day, it can't show what happened in the 6 hours between them. If you need to prove the page was up at a specific time, add that hour to the schedule or run a capture by hand.
- **Timing:** GitHub often starts scheduled runs a few minutes late and occasionally skips one when it's busy. With 4 captures a day, a skipped run means a 12-hour gap, so check `log.csv` now and then and run one by hand if you see a gap. Each capture records its real time.
- **If the site goes down** or the PDF link disappears, the run still commits a capture that records the failure (HTTP status, "link NOT found"). That is evidence too.
- **Cost:** free. On a private repository, the free GitHub plan includes 2,000 Actions minutes a month. Each run bills about 1–2 minutes, so 4 a day comes to roughly 120–250 minutes a month, well inside the free amount. If you ever go over with no card on file, GitHub stops the runs rather than charging you.
- **Storage:** a typical page plus PDF is about 1–3 MB per capture, so roughly 4–12 MB a day, or 120–360 MB a month. Git stores an unchanged PDF only once. GitHub prefers repositories under about 1 GB, so a few months fit comfortably.
- This is technical evidence, not legal advice. If you need it for a court or a regulator, ask a lawyer whether you also need a certified capture, for example a *proces-verbal de constatare* from a bailiff (*executor judecătoresc*) in Romania.

## Changing things later

- **Extend or shorten the window:** edit `start` and `end` in `config.toml`. If the schedule has already switched itself off, turn it back on under **Actions → Capture page + PDF → ⋯ → Enable workflow**.
- **Stop early:** **Actions → Capture page + PDF → ⋯ → Disable workflow**.
- **Close a cookie banner before the screenshot:** add its button's CSS selector to `dismiss_selectors`.
