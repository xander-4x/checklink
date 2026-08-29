# check-url (antifish)

A command-line tool that checks a suspicious link before you click it. Built
for the "fake video call, your app is out of date, update via this link"
pattern — a widespread social-engineering technique (documented by Microsoft
and Apple) where a look-alike download link installs a backdoor instead of
the real app.

It never executes the target. Most checks only look at headers, TLS
metadata, and the domain name; if the response looks like a downloadable
file, the body is read into memory (capped at 50MB) just long enough to
hash it — never written to disk, never run.

## Usage

```sh
./check-url https://url-to-check.com
```

Flags go before the URL (standard Go `flag` parsing). `-set-key` and
`-delete-key` are the exception — they manage the OS keychain and don't
take a URL at all:

```sh
./check-url [flags] <url>
./check-url -set-key VT_API_KEY
```

| Flag         | Default | Description                                                                 |
|--------------|---------|-------------------------------------------------------------------------------|
| `-json`      | off     | Machine-readable JSON output instead of the text report                     |
| `-no-color`  | off     | Disable ANSI color on the verdict line                                      |
| `-timeout`   | `15s`   | Per-check network timeout (must be positive)                                |
| `-vt-submit` | off     | Submit URLs VirusTotal hasn't seen before for fresh analysis (uses API quota) |
| `-vt-submit-file` | off | Upload a downloaded file to VirusTotal if its hash has no cached report (uses more quota, makes the file visible to other VT users) |
| `-set-key NAME` | — | Prompt for a secret's value (hidden input) and save it to the OS keychain, then exit. See [Optional API keys](#optional-api-keys) |
| `-delete-key NAME` | — | Remove a secret previously saved with `-set-key`, then exit |

Color is also disabled automatically when stdout isn't a terminal, or when
`NO_COLOR` is set in the environment.

## Example

```
$ ./check-url http://teams.microsoft.com.security-update-portal.net

Checking: http://teams.microsoft.com.security-update-portal.net

Where the link actually goes
  could not check — this domain does not exist (teams.microsoft.com.security-update-portal.net)

Connection security
  skipped — domain does not exist (see above)

Domain name analysis
  [LOW] unusually deep subdomain chain (5 labels): teams.microsoft.com.security-update-portal.net
  [HIGH] brand name "microsoft" appears as a subdomain, but the real registrable domain is "security-update-portal.net" — classic brand-in-subdomain spoofing
  [HIGH] brand name "teams" appears as a subdomain, but the real registrable domain is "security-update-portal.net" — classic brand-in-subdomain spoofing

Google Safe Browsing
  skipped — GOOGLE_SAFE_BROWSING_API_KEY not set

VirusTotal
  skipped — VT_API_KEY not set

DANGEROUS — do not open this link

Why:
  [HIGH] brand name "microsoft" appears as a subdomain, but the real registrable domain is "security-update-portal.net" — classic brand-in-subdomain spoofing
  [HIGH] brand name "teams" appears as a subdomain, but the real registrable domain is "security-update-portal.net" — classic brand-in-subdomain spoofing

This is an automatic signal, not a guarantee - be wary of urgent messages and
social engineering techniques
```

The report body stays in the terminal's default color; only the verdict line
is colored — green (`LOOKS SAFE`), yellow (`CAUTION`), red (`DANGEROUS`), or
cyan (`UNKNOWN`, when the domain doesn't resolve at all and nothing could
actually be checked).

## What it checks

Before any of the checks below run, a Google Drive / Dropbox / OneDrive
**share page** link is rewritten to its direct-download form (see
[Cloud-storage share links](#cloud-storage-share-links)), so the checks
below run against the real file, not the viewer/preview page in front of
it.

- **Where the link actually goes** — follows redirects (without downloading
  the response body), flags a redirect that lands on a different registrable
  domain than the one you gave it, flags plain HTTP (and, more severely, an
  HTTPS link that redirects down to plain HTTP — a possible TLS-stripping
  downgrade), and flags a response that serves an executable (`.exe`,
  `.msi`, `.dmg`, `.ps1`, `.apk`, …) — the classic "update" payload.
- **Connection security** — TLS certificate issuer and age; a certificate
  issued in the last few days is a common trait of freshly stood-up phishing
  infrastructure.
- **Domain name analysis** — raw IP as host, punycode/IDN labels, known URL
  shorteners, typosquats of common brands (Levenshtein distance), and brand
  names used as a fake subdomain (`teams.microsoft.com.evil.net`) — the
  single most common trick behind the "fake Teams update" pattern.
- **Google Safe Browsing** *(optional)* — checks the URL against Google's
  threat-list API.
- **VirusTotal (URL)** *(optional)* — looks up any cached verdict from ~70-90
  antivirus engines; use `-vt-submit` to request a fresh scan for URLs VT
  hasn't seen before. Only escalates to `DANGEROUS` at 3+ engines agreeing —
  on any popular, entirely legitimate site it's routine for a single
  low-quality vendor to false-positive out of ~90 engines, so 1-2 flags
  shows as `CAUTION` ("could be an isolated false positive") instead.
- **Downloaded file** *(optional VirusTotal step)* — if the response looks
  like a file (by extension, `Content-Disposition`, or a binary
  `Content-Type`), downloads it (capped at 50MB), computes its SHA-256, and
  checks that hash against VirusTotal's file database. This catches
  malware regardless of what the file is named — the URL/extension checks
  above can be fooled by a misleading filename, a hash can't. Skipped
  automatically for anything that doesn't look like a file (e.g. a normal
  webpage). Use `-vt-submit-file` to upload files VT hasn't seen before
  (only files ≤32MB — VirusTotal's direct-upload limit).

## Cloud-storage share links

Attackers increasingly host payloads on Google Drive, Dropbox, or OneDrive
specifically because the domain is trusted — it sails through typosquat and
reputation checks that would flag a throwaway domain. The catch is that the
link actually sent to a victim is a **share/preview page** (HTML), not the
file itself, so a checker that only follows redirects and reads headers
never reaches the real bytes.

`check-url` detects the common share-link shapes and rewrites them to the
direct-download form before running any checks:

| Provider | Share link | Rewritten to |
|---|---|---|
| Google Drive | `drive.google.com/file/d/{id}/view`, `/open?id={id}` | `drive.google.com/uc?export=download&id={id}` |
| Dropbox | `dropbox.com/s/...?dl=0` (or `dl` missing) | same URL with `dl=1` |
| OneDrive | `onedrive.live.com/...` | same URL with `download=1` |
| OneDrive (short link) | `1drv.ms/...` | resolved to its `onedrive.live.com` destination, then `download=1` |

```
$ ./check-url https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/view?usp=sharing

Checking: https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/view?usp=sharing
Resolved cloud-storage share link to: https://drive.google.com/uc?export=download&id=1AbCdEfGhIjKlMnOpQrStUvWxYz

...
Downloaded file
  [INFO] invoice.pdf (482113 bytes) SHA-256: 9a81dffe...
...
```

This is a best-effort convenience, not a guarantee: SharePoint document
links, `wetransfer.com`, and similar aren't covered, and if a provider
changes its share-link format this can silently stop matching. When the
link doesn't match a known pattern, it's checked as-is — nothing breaks,
you just lose the auto-resolve.

## Optional API keys

The Safe Browsing, VirusTotal (URL), and VirusTotal parts of the file check
are all skipped unless a key is available for them. There are three ways to
provide one, checked in this order:

**1. OS keychain (recommended)** — encrypted at rest, tied to your login,
never sits on disk as plaintext. Set one interactively (input is hidden,
not echoed to the terminal):

```sh
./check-url -set-key VT_API_KEY                    # https://www.virustotal.com/gui/my-apikey
./check-url -set-key GOOGLE_SAFE_BROWSING_API_KEY   # https://console.cloud.google.com — enable "Safe Browsing API"
```

Remove one with `-delete-key VT_API_KEY`. Backed by Keychain on macOS,
Credential Manager on Windows, and Secret Service (gnome-keyring/KWallet)
on Linux — a headless Linux box without a keyring daemon running won't have
this available, so fall back to option 2 or 3 there.

**2. A real environment variable** — always wins over both the keychain and
`.env`, useful for CI or a one-off override:

```sh
export VT_API_KEY=...
```

**3. A `.env` file** (`KEY=value` per line) in the current directory —
`check-url` loads it on startup automatically. There's a `.gitignore` entry
for `.env` already, but it's still plaintext on disk; prefer the keychain
where you can.

```sh
# .env
VT_API_KEY=your-key-here
```

`VT_API_KEY` covers both the URL check and the file-hash check. Both
services have free tiers; VirusTotal's is rate-limited (4 requests/min,
500/day, shared across everyone using the same key — see the "one shared
key" note below), which is why `-vt-submit`/`-vt-submit-file` are opt-in
rather than automatic.

> **Rolling this out to a team:** VirusTotal's free-tier quota is per API
> key, not per person. If everyone shares one key in a company-wide config,
> 4 requests/minute disappears fast with more than a couple of concurrent
> users. Either have each person use their own free key, get a paid VT plan
> if this becomes real infrastructure, or put a small caching proxy in
> front of a single key.
>
> `-vt-submit-file` uploads the actual file bytes to VirusTotal, which
> makes that file (and its contents) visible to other VT users — don't use
> it on files that might contain secrets or internal data.

## Exit codes

Useful for scripting or wiring into other tooling:

| Code | Meaning                                                        |
|------|-----------------------------------------------------------------|
| `0`  | `LOOKS SAFE`                                                     |
| `1`  | `CAUTION`, or `UNKNOWN` (domain doesn't resolve, nothing checked) |
| `2`  | `DANGEROUS`                                                      |

## JSON output

`-json` prints the verdict plus the full per-check detail:

```sh
./check-url -json https://example.com
```

`resolved_url` is present only when the input matched a cloud-storage share
link and was rewritten (see [Cloud-storage share links](#cloud-storage-share-links)).

```json
{
  "url": "https://example.com",
  "verdict": "LOOKS SAFE",
  "checks": [
    { "checker": "redirect-chain", "findings": [ { "checker": "redirect-chain", "severity": "INFO", "message": "Content-Type: text/html" } ] },
    { "checker": "tls-cert", "findings": [ ... ] },
    { "checker": "heuristics" },
    { "checker": "google-safe-browsing", "skipped": "GOOGLE_SAFE_BROWSING_API_KEY not set" },
    { "checker": "virustotal", "skipped": "VT_API_KEY not set" },
    { "checker": "file-hash", "skipped": "response doesn't look like a downloadable file, nothing to hash" }
  ]
}
```

## Build

```sh
go build -o check-url .
```

Cross-compile for colleagues on other platforms:

```sh
GOOS=windows GOARCH=amd64 go build -o check-url.exe .
GOOS=darwin  GOARCH=arm64 go build -o check-url-mac .
```

## Limitations

This is a heuristic signal, not a guarantee:

- Typosquat detection only catches domains that are *visually close* to a
  known brand (small edit distance) — a domain like `teams-msupdate.com`
  won't trip it even though it's clearly impersonating Teams. Safe Browsing
  / VirusTotal cover a much wider net when API keys are configured.
- The known-brand list (`heuristics.go`) is a short, hand-picked set geared
  toward the "fake meeting app" pattern — extend it for your organization's
  actual attack surface.
- The file-hash check only catches malware VirusTotal's engines already
  recognize (or that you explicitly submit with `-vt-submit-file`); a truly
  novel, targeted payload can still come back clean. It's a strong signal
  when it fires, not proof of safety when it doesn't. Files over 50MB
  aren't hashed at all — download and scan those with your local antivirus.
- Nothing here replaces judgment during a live social-engineering attempt:
  urgency, an unfamiliar caller, and pressure not to look "difficult" are
  the actual attack, independent of what any tool reports.
