# Hunting Bad Guys

```text
    __  ____  ___   _____________   ________
   / / / / / / / | / /_  __/  _/ | / / ____/
  / /_/ / / / /  |/ / / /  / //  |/ / / __
 / __  / /_/ / /|  / / / _/ // /|  / /_/ /
/_/ /_/\____/_/ |_/ /_/ /___/_/ |_/\____/
    ____  ___    ____     ________  ____  _______
   / __ )/   |  / __ \   / ____/ / / /\ \/ / ___/
  / __  / /| | / / / /  / / __/ / / /  \  /\__ \
 / /_/ / ___ |/ /_/ /  / /_/ / /_/ /   / /___/ /
/_____/_/  |_/_____/   \____/\____/   /_//____/
```

Self-hosted threat intelligence platform for investigating suspicious domains and IP addresses.
Paste a list of targets and get DNS, WHOIS, HTTP redirect chains, TLS details,
certificate transparency, root-file fingerprints, screenshots, GeoIP, BGP/ASN
data, extracted IOCs, static file analysis (APK, IPA, PE, ELF, PDF, scripts),
disassembly, network-traffic capture and Tor-routed host probes, all queryable
with a small query language and organised into cases, reports and alerts.

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-informational)](pyproject.toml)

## Contents

- [Features](#features)
- [Quick start (Docker)](#quick-start-docker)
- [Configuration](#configuration)
- [Single sign-on](#single-sign-on)
- [Branding and themes](#branding-and-themes)
- [Deploying on a VPS](#deploying-on-a-vps)
- [Local development](#local-development)
- [Updating](#updating)
- [Integrations (OpenCTI, MISP, SIEM, scripts)](#integrations-opencti-misp-siem-scripts)
- [Query language](#query-language)
- [Security](#security)
- [Versioning and changelog](#versioning-and-changelog)
- [Disclaimer](#disclaimer)
- [License](#license)

## Features

| Area | What you get |
|---|---|
| Domain scan | DNS (A/AAAA/MX/TXT/NS/CNAME/SOA), WHOIS, HTTP chain with per-hop headers and TLS, certificate transparency, root files with SHA-1 and MinHash, crawled files, screenshot with perceptual hash, GeoIP per address |
| IP scan | ASN and prefix (RDAP, BGPView, Hurricane Electric), GeoIP, optional Tor-routed service and OS probe (nmap with `--reason`) |
| Extraction | EFI: 65 IOC patterns (credentials, wallets, messaging handles, paste sites, tunnels). EFA: static analysis of APK, IPA, PE, ELF, PDF, Office, scripts; radare2 and Ghidra decompilation; Detect-It-Easy; JADX |
| Dynamic | Network-traffic capture in a sandboxed browser where cross-origin requests are recorded and blocked |
| Workflow | Folders, cases, team-shared CTI reports with markdown and STIX export, relationship graph, dashboard, alert rules with email notifications, public blog |
| Feeds | Public result feed with pHash similarity search, authenticated team feed, optional nightly import of OpenPhish, URLhaus, ThreatFox, PhishStats, ransomware.live and more |
| Access | Local accounts with invite codes, OpenID Connect single sign-on, admin console with logs, account management (create, rename, reset passwords, roles), changelog and system info |

## Quick start (Docker)

Requirements: Docker Engine 24+ with the Compose plugin, 4 GB RAM (8 GB recommended
for binary analysis), outbound internet access.

```bash
git clone https://github.com/indestiny0xff/HuntingBadGuys-PUBLIC.git
cd HuntingBadGuys
cp .env.example .env
```

Edit `.env` and set the values marked `CHANGE_ME` (secret key, admin password,
database password). For a local install keep `SITE_ADDRESS=http://localhost`;
for a server set it to your domain and `ACME_EMAIL` for Let's Encrypt. Then:

```bash
docker compose up -d
docker compose logs -f app   # first start downloads the GeoIP database
```

Open `http://localhost` (or your domain) and sign in with the bootstrap admin.
Its username is `HUNTER_ADMIN_USER` (default `admin`); unless you set
`HUNTER_ADMIN_PASSWORD`, a random password was generated on first start:

```bash
docker compose logs app | grep -A 3 "Initial admin password"
# or
docker compose exec app cat /data/initial-admin-password.txt
```

Change it right away in the Accounts tab of the admin console at `/admin`;
the saved copy is deleted when you do.

The first build compiles the Ghidra decompiler plugin and takes 10 to 20 minutes;
later builds use the cache.

The proxy publishes ports 80 and 443 by default, which Let's Encrypt needs on
a server. On a workstation those ports are often taken, so pick uncommon ones
in `.env`: `HTTP_PORT=8457`, `HTTPS_PORT=8458`, keep
`SITE_ADDRESS=http://localhost` and set `HUNTER_PUBLIC_URL=http://localhost:8457`;
the site is then served on `http://localhost:8457`. Any free port works.

Behind a corporate proxy, set `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in
`.env` before building. The same values are used for the image build (apt,
curl, uv) and by the running containers (scans, GeoIP download, SSO discovery,
Let's Encrypt). Keep `localhost,127.0.0.1,app,db` in `NO_PROXY`. Tor and the
nmap host probes cannot use an HTTP proxy, so set `HUNTER_TOR_ENABLED=false`
and `HUNTER_HIG_ENABLED=false` if the proxy is the only route out.

Windows (PowerShell) and macOS use the same commands; `cp` is `Copy-Item` on
PowerShell:

```powershell
Copy-Item .env.example .env
docker compose up -d
```

## Configuration

Everything is configured through `.env`. The complete, commented list lives in
[`.env.example`](.env.example). The most important variables:

| Variable | Purpose |
|---|---|
| `SITE_ADDRESS`, `ACME_EMAIL` | Address served by Caddy. A domain enables automatic HTTPS |
| `HUNTER_PUBLIC_URL` | Public base URL used in links, emails and the SSO redirect |
| `HUNTER_JWT_SECRET` | Signs session cookies. Required in production |
| `HUNTER_ADMIN_USER`, `HUNTER_ADMIN_PASSWORD` | Bootstrap admin account; empty password = random, shown once in the log |
| `HUNTER_INVITE_CODE` | Required for self-registration; empty disables it |
| `HUNTER_ACCESS_REQUEST_EMAIL` | Inbox for the "request access" form (needs SMTP) |
| `HUNTER_OIDC_*` | Single sign-on, see below |
| `POSTGRES_PASSWORD` | Database password (the DSN is built automatically) |
| `HUNTER_SMTP_*` | Outbound email for alerts and access requests |
| `HUNTER_ALLOW_PRIVATE_TARGETS` | Keep `false`; `true` disables the SSRF guard |
| `HUNTER_HIG_ENABLED`, `HUNTER_TOR_ENABLED` | Host probes and Tor inside the container |
| `HUNTER_FEED_INGEST` | Nightly import of public threat feeds |
| `APP_CPUS`, `APP_MEMORY` | Container resource limits |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Outbound proxy for the build and the containers (optional) |

Generate secrets with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"      # HUNTER_JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(32))"  # HUNTER_INVITE_CODE
```

## Single sign-on

Any OpenID Connect provider works (Google, Microsoft Entra ID, Okta, Keycloak,
Authentik, Zitadel). Register a confidential web client with the redirect URI
`https://your-domain/auth/sso/callback`, then set:

```ini
HUNTER_OIDC_ISSUER=https://accounts.google.com
HUNTER_OIDC_CLIENT_ID=...
HUNTER_OIDC_CLIENT_SECRET=...
HUNTER_OIDC_ALLOWED_DOMAINS=example.com     # optional
HUNTER_OIDC_ONLY=false                      # true hides the password form
```

A "Sign in with SSO" button appears on the login pages. Accounts are created on
first login (`HUNTER_OIDC_AUTO_CREATE`), keyed by the provider's stable subject
claim; usernames derive from `preferred_username` or the email local part. Grant
admin rights by listing the resulting username in `HUNTER_ADMIN_USERNAMES`.

## Branding and themes

```ini
HUNTER_APP_NAME=Acme Threat Lab   # page titles, headers, emails, reports
HUNTER_THEME=blue                 # purple (default), red, green, blue, black
```

Both apply everywhere without rebuilding the image; restart the `app` service
after changing them.

## Deploying on a VPS

A 4 vCPU / 8 GB VPS running Ubuntu 24.04 or Debian 12 is a good baseline. Point
your domain's A record at the server, then as root:

```bash
curl -fsSL https://raw.githubusercontent.com/indestiny0xff/HuntingBadGuys-PUBLIC/main/scripts/vps_setup.sh | bash
cd /opt/huntingbadguys
cp .env.example .env && nano .env     # SITE_ADDRESS=hunt.example.com, ACME_EMAIL, secrets
docker compose up -d
```

The setup script installs Docker, opens ports 22/80/443 with UFW, enables
fail2ban and unattended security upgrades, and clones the repository. Caddy
obtains and renews the certificate. Harden SSH (key-only authentication, no
root login) before exposing the server.

Operations:

```bash
docker compose logs -f app              # logs
bash scripts/backup.sh                  # database + data volume to backups/
bash scripts/restore.sh backups/<file>  # restore a dump
docker compose pull && docker compose build --pull && docker compose up -d   # upgrade
```

## Local development

The project uses [uv](https://docs.astral.sh/uv/) for dependencies and
[ruff](https://docs.astral.sh/ruff/) for linting and formatting. Python 3.12+.

Linux and macOS:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync                              # creates .venv with locked dependencies
uv run playwright install chromium   # browser for screenshots
cp .env.example .env                 # set HUNTER_PRODUCTION=false for local use
uv run uvicorn app.main:app --reload
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
uv sync
uv run playwright install chromium
Copy-Item .env.example .env
uv run uvicorn app.main:app --reload
```

Without a database (`HUNTER_DB_DSN` empty) results live in memory and are lost
on restart, which is fine for development. To use PostgreSQL locally, start
only the database: `docker compose up -d db` and set
`HUNTER_DB_DSN=postgresql://hunter:<password>@localhost:5432/hunter`.

Binary analysis tools (radare2, JADX, Detect-It-Easy, nmap, Tor) are only
installed in the Docker image; the corresponding features report "not
available" when running outside it.

Checks:

```bash
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pytest -q           # tests (no network access needed)
uv run pre-commit install  # optional: run lint, format and secret scanning on commit
```

A `Makefile` wraps these for Linux and macOS (`make install`, `make dev`,
`make check`, `make up`).

## Updating

Dependencies are pinned for reproducible builds: Python packages in `uv.lock`
and the analysis tools as build arguments in the `Dockerfile`. To move every
pin to the latest release:

```bash
uv run python scripts/update_deps.py --check   # show what is outdated
uv run python scripts/update_deps.py           # apply
uv run pytest -q
docker compose build --pull && docker compose up -d
```

The script keeps the Playwright Python package and the Playwright base image on
the same version, and updates radare2, JADX, Detect-It-Easy and the Temurin JRE.
Commit the changed `pyproject.toml`, `uv.lock`, `Dockerfile` and `.env.example`.

## Threat feed ingestion

The public feed can be filled automatically from public phishing and ransomware
sources (OpenPhish, URLhaus, ThreatFox, PhishStats, PhishHunt, ransomware.live,
ransomlook, ransomwatch). `scripts/ingest_feeds.py` pulls the feeds, creates
one folder per source and one case per group, and submits every target as a
public scan through the API. Two ways to run it:

Built in (recommended): set in `.env` and restart the app container. The
entrypoint then runs the import every night at 00:00 UTC using the bootstrap
admin account.

```ini
HUNTER_FEED_INGEST=true
HUNTER_FEED_INGEST_FEEDS=openphish urlhaus threatfox        # any subset of the sources above
HUNTER_FEED_EXCLUDE_USERNAMES=admin                         # keep bulk scans out of the Intel feed
```

Host cron (if you prefer your own schedule). The script talks to the API, so it
needs an account; `ingest` here is a dedicated account created in the admin
console:

```bash
crontab -e
# every day at 02:00, log to backups/ingest.log
0 2 * * * cd /opt/huntingbadguys && docker compose exec -T app python scripts/ingest_feeds.py -u ingest -p 'CHANGE_ME' --base-url http://127.0.0.1:8000 --feeds openphish urlhaus threatfox >> backups/ingest.log 2>&1
```

Useful flags: `--test-feeds` checks connectivity without scanning, `--dry-run`
prints what would be submitted, `--phishunt-key KEY` enables the PhishHunt feed.
A full run can take hours because every target is scanned.

## Using the API

Every feature is available as a versioned JSON API under `/api/v1`, authenticated
with per-user API keys. Create a key in the app (user menu, **API** button): it is
shown once, stored hashed, and can be revoked at any time. Administrators can
revoke any account's keys from the admin console. Send it as a bearer token or
in `X-API-Key`:

```bash
BASE=https://hunt.example.com
KEY=hbg_...

# scan domains and IPs (hostnames in IP mode are resolved first)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \\
  -d '{"targets":["example.com","phish.site/login"],"screenshot":true}' $BASE/api/v1/analyse/domain
curl -s -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \\
  -d '{"targets":["1.1.1.1","example.com"]}' $BASE/api/v1/analyse/ip

# query your results with the query language
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \\
  -d '{"query":"final_status == 200 AND dns.A exists"}' $BASE/api/v1/query

# who am I
curl -s -H "Authorization: Bearer $KEY" $BASE/api/v1/auth/me
```

Python:

```python
import httpx

api = httpx.Client(
    base_url="https://hunt.example.com/api/v1",
    headers={"Authorization": "Bearer hbg_..."},
    timeout=300,
)
results = api.post("/analyse/domain", json={"targets": ["example.com"]}).json()
print(results[0]["final_status"], results[0]["dns"]["A"])
```

Main endpoints (prefix `/api/v1`; the web app uses the same paths without the
prefix and a session cookie):

| Endpoint | Purpose |
|---|---|
| `GET /auth/me` | The authenticated account |
| `GET/POST/DELETE /auth/api-keys` | Manage your API keys (the secret is returned once on creation) |
| `POST /auth/login`, `POST /auth/logout`, `POST /auth/password` | Session management for the web app |
| `POST /analyse/domain`, `POST /analyse/ip` | Run scans (`is_private`, `case_id`, per-module toggles in the body) |
| `POST /analyse/ip/hig`, `GET /analyse/ip/hig?target=` | Start and poll a host probe |
| `POST /query` | Query language over your results (`ids`, `case_id` optional) |
| `GET /store`, `PATCH /store/{id}`, `DELETE /store/{id}` | List, update (privacy, case) and delete results |
| `GET/POST/DELETE /folders`, `GET/POST/PATCH/DELETE /cases` | Organisation |
| `GET /cases/{id}/graph`, `GET /cases/{id}/report`, `PUT /cases/{id}/report` | Graph data and team-shared reports |
| `GET /cases/{id}/export?format=json\|csv\|stix\|misp` | Indicator export for OpenCTI, MISP, SIEM |
| `POST /results/{id}/efi`, `POST /results/{id}/efa`, `POST /results/{id}/nt` | IOC extraction, file analysis, traffic capture |
| `GET/POST/DELETE /alerts`, `POST /alerts/{id}/test`, `GET /notifications` | Alert rules |
| `GET /public/results`, `GET /public/results/{id}`, `POST /public/query` | Public feed (no login) |
| `GET /feed/results`, `GET /feed/results/{id}`, `POST /feed/query` | Team feed (login) |
| `GET /api/blog/posts`, `POST /api/blog/posts` | Blog |
| `GET /admin/api/users`, `POST /admin/api/users`, `PATCH /admin/api/users/{id}` | Account management (admin) |
| `DELETE /admin/api/users/{id}/api-keys` | Revoke all keys of an account (admin) |

The complete, always-current reference is built into the application: any
signed-in user can open `/api/docs` (interactive Swagger UI generated from the
code, also linked from the API keys panel and the admin console) and
`/api/openapi.json` for the OpenAPI schema, which includes the security
schemes for client generators. Request and response shapes are the pydantic
models in `app/models.py`. Rate limits apply per client IP (120 requests per
minute, 20 per minute on `/auth/*`).

## Integrations (OpenCTI, MISP, SIEM, scripts)

Every case can be exported as a flat indicator set. One endpoint, four formats:

```text
GET /api/v1/cases/{case_id}/export?format=json   # domains, ips, urls, hashes, emails, dns, certificates, results
GET /api/v1/cases/{case_id}/export?format=csv    # type,value,sources
GET /api/v1/cases/{case_id}/export?format=stix   # STIX 2.1 bundle: indicators + report (stable ids)
GET /api/v1/cases/{case_id}/export?format=misp   # MISP event JSON with typed attributes
```

Find the case id first:

```bash
BASE=https://hunt.example.com; KEY=hbg_...
curl -s -H "Authorization: Bearer $KEY" $BASE/api/v1/cases | jq -r '.[] | "\(.id)  \(.name)"'
CASE=<id>
```

Pull specific things with jq:

```bash
EXPORT="$BASE/api/v1/cases/$CASE/export"
# every IP of the case (A/AAAA records, IP scans, resolved hostnames)
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq -r '.ips[].value'
# every domain, every URL, every file hash
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq -r '.domains[].value, .urls[].value, .hashes[].value'
# DNS records per domain
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq '.dns'
# certificates seen in CT logs (common name, issuer, SANs)
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq '.certificates[] | {common_name, issuer, san}'
# open ports found by host probes
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq '.results[] | select(.kind=="ip") | {target, ports: [.hig.ports[]? | {port, service, reason}]}'
# IOCs extracted from page content (EFI): Telegram handles, wallets, webhooks, API keys
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq '.results[] | select(.efi) | {target, efi}'
```

OpenCTI (STIX 2.1 bundle through pycti):

```python
import httpx
from pycti import OpenCTIApiClient

hbg = httpx.Client(
    base_url="https://hunt.example.com/api/v1", headers={"Authorization": "Bearer hbg_..."}
)
bundle = hbg.get(f"/cases/{case_id}/export", params={"format": "stix"}).text

octi = OpenCTIApiClient("https://opencti.example.com", "OPENCTI_TOKEN")
octi.stix2.import_bundle_from_json(bundle, update=True)
```

Indicator ids are derived from the indicator value, so re-importing an updated
case updates the existing objects instead of creating duplicates. The bundle
also carries a `report` object linking every indicator to the case.

MISP (event through PyMISP, or the REST API):

```python
from pymisp import PyMISP

event = hbg.get(f"/cases/{case_id}/export", params={"format": "misp"}).json()
misp = PyMISP("https://misp.example.com", "MISP_KEY", ssl=True)
misp.add_event(event["Event"])
```

```bash
curl -s -H "Authorization: Bearer $KEY" "$EXPORT?format=misp" \
  | curl -s -X POST https://misp.example.com/events/add \
      -H "Authorization: MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" -d @-
```

SIEM, spreadsheets, blocklists:

```bash
curl -s -H "Authorization: Bearer $KEY" "$EXPORT?format=csv" > case.csv
curl -s -H "Authorization: Bearer $KEY" $EXPORT | jq -r '.domains[].value' > blocklist.txt
```

Automating the loop: scan with `POST /api/v1/analyse/domain` (`case_id` in the
body), run `POST /api/v1/results/{id}/efi` and `/efa` for extraction, then
export. Alert rules (`/api/v1/alerts`) can email when a case changes, and the
nightly feed import keeps the public cases fresh.

## Query language

Results can be filtered with dot-notation fields and the operators `==`, `!=`,
`contains`, `startswith`, `endswith`, `~=` (regex), `in`, `exists`,
`not exists`, combined with `AND`, `OR`, `NOT` and parentheses. Lists match if
any item matches.

```text
dns.A == "1.2.3.4"
final_headers.server contains "nginx" AND final_status == 200
bgp.asn.asn == "AS15169"
certs.san ~= "^login\\."
efi.telegram exists AND NOT screenshot exists
hig.ports.port == 3389
```

The App page has a built-in field reference and query examples.

## Security

See [SECURITY.md](SECURITY.md) for the reporting process and deployment notes.
In short: the service fetches hostile content by design, so it blocks private
addresses on every outbound request, caps downloads and archive entries,
isolates results per user, rate-limits, rejects cross-site writes, hashes
passwords with bcrypt, signs HttpOnly cookies, ships a strict Content Security
Policy and runs as an unprivileged container user with all capabilities dropped.

## Versioning and changelog

Releases follow [Semantic Versioning](https://semver.org/). The version is
declared once in `pyproject.toml`, exposed at `/health`, shown in the admin
console and tagged as `vX.Y.Z` in git. Full history: [CHANGELOG.md](CHANGELOG.md),
also available in the admin console.

### 1.0.0 (2026-10-17)

- First public release: one-command Docker Compose deployment with automatic HTTPS.
- OpenID Connect single sign-on, bootstrap admin, configurable branding and themes.
- Security hardening: SSRF guard on every outbound request, validated inputs,
  non-root container, per-IP lockouts, origin checks, ReDoS and zip-bomb limits.
- Modular codebase (`app/routes/*`), `uv` and `ruff` tooling, CI, dependency
  update script, admin changelog.

## Disclaimer

This software is intended for defensive security research, threat intelligence
and incident response on systems and infrastructure you are authorised to
investigate. It actively contacts the targets you submit (DNS, HTTP requests,
file downloads, port and service probes). You are solely responsible for how
you use it and for complying with the laws and agreements that apply to you.
The authors and contributors accept no liability for any misuse, damage or
legal consequences arising from the use of this project. It is provided "as
is", without warranty of any kind (see the license).

## License

[MIT](LICENSE)
