# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). This file is also shown in the
admin console under the Changelog tab.

## [Unreleased]

### Added

- Outbound proxy support: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `.env`
  are passed to the image build and to the `app` and `caddy` containers for
  hosts that reach the internet through a corporate proxy.
- Case report (RPT and blog): a "Network Traffic (NT)" section per target with
  the live capture (fetch, XHR, other requests, WebSockets) and the static
  per-file extraction (calls, forms, API bases, GraphQL endpoints, beacons).

### Fixed

- Blog publishing failed with "Invalid string length" on cases with analysed
  files: the report embedded every byte of every hex dump as HTML spans, which
  produced reports of several hundred MB. The hex view now previews the first
  8 KB per file (interactive spans only for dumps up to 1 KB); the full bytes
  are embedded compactly with "Show all rows", "Download hex dump" and
  "Download raw bytes" buttons. The publish dialog reports a clear error when
  the payload exceeds the 16 MB proxy limit.
- CI format check: ruff 0.17 formats Python code blocks in Markdown, so the two
  `httpx.Client` examples in the README are now written the way it expects.

## [1.0.0] - 2026-10-17

First public release.

### Added

- One-command deployment: `docker compose up -d` starts Caddy (automatic HTTPS),
  the application and PostgreSQL. Every setting is an environment variable
  documented in `.env.example`.
- Single sign-on through OpenID Connect (Google, Microsoft Entra ID, Okta,
  Keycloak, Authentik, Zitadel), with PKCE, nonce and ID-token validation,
  optional domain allow-list and SSO-only mode.
- Branding: `HUNTER_APP_NAME` renames the product on every page, email and
  report; `HUNTER_THEME` selects the purple, red, green, blue or black palette.
- Bootstrap admin account created from `HUNTER_ADMIN_USER` /
  `HUNTER_ADMIN_PASSWORD` on first start; with an empty password a random one
  is generated, printed once in the log and kept on the data volume until it is
  changed through the admin console (`POST /auth/password`).
- Case indicator export (`/cases/{id}/export`) as JSON, CSV, STIX 2.1 bundle
  or MISP event for OpenCTI, MISP and SIEM integrations.
- Per-user API keys (created in the app, shown once, stored hashed, revocable)
  accepted as `Authorization: Bearer` or `X-API-Key`; versioned `/api/v1`
  surface with an OpenAPI reference at `/api/docs` for signed-in users.
- Admin console: account management (create accounts, rename, set passwords,
  grant or revoke the admin role, delete), Changelog and System tabs, version badge.
- `scripts/update_deps.py` bumps Python packages and the pinned tool versions
  (Playwright, radare2, JADX, Detect-It-Easy, Temurin) in one go.
- `scripts/vps_setup.sh` prepares an Ubuntu or Debian VPS (Docker, firewall,
  fail2ban); `scripts/backup.sh` and `scripts/restore.sh` for the database.
- Host probes record why a port is reported (nmap `--reason`) and the UI shows it.
- Continuous integration (lint, format check, tests, Docker build), pre-commit
  hooks with secret scanning, `uv.lock` for reproducible installs.

### Changed

- The application module was split into focused routers (`app/routes/*`) with
  shared state, browser management and security helpers in their own modules.
- Dependency management moved from `requirements.txt` to `pyproject.toml` with
  `uv`; linting and formatting use `ruff`.
- The container runs as a non-root user with all capabilities dropped; the
  database network is internal; only the proxy publishes ports.
- Session tokens are issued with PyJWT and carry `iat` and `jti` claims.
- The public results API caps full-document pages at 500 items (the compact card
  projection is still available in bulk).
- Email templates, sitemap, canonical URLs and robots.txt use the configured
  public URL and application name instead of a hard-coded domain.

### Security

- Server-side request forgery: every outbound fetch now resolves the host first
  and refuses private, loopback and link-local addresses, including redirect
  hops, re-fetched files and screenshot targets.
- Host probe targets must be valid IP addresses (no argument injection into the
  scanner command line).
- Login lockout is keyed by username and client IP with exponential back-off,
  so an attacker cannot lock other users out.
- Cross-site writes are rejected when the Origin or Referer header does not
  match the site; the session cookie stays `SameSite=Lax`, `HttpOnly` and
  `Secure` in production.
- Forwarded headers are only trusted from the configured proxy networks; the
  rate limiter no longer reads `X-Forwarded-For` itself.
- Regex queries are length-capped and nested quantifiers are rejected (ReDoS).
- Zip entries from APK and IPA files are size-limited before inflation.
- Blog links may only point to http(s), mailto or relative targets.
- Access-request emails HTML-escape user input; pending requests are capped.
- Startup no longer logs the invite code or SMTP settings.
- Unvalidated `dict` request bodies were replaced by typed models.
- Removed the account-restore-on-register behaviour that allowed anyone with
  the invite code to take over a deleted user's data.

### Removed

- Next.js remnants, Supabase schema, Railway/Render configuration, the legacy
  `saved` page, the demo page and mock backend, the unused FlareSolverr stub
  and host-specific deployment scripts.

[Unreleased]: https://github.com/indestiny0xff/HuntingBadGuys-PUBLIC/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/indestiny0xff/HuntingBadGuys-PUBLIC/releases/tag/v1.0.0
