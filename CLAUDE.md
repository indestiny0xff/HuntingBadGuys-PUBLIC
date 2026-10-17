# Hunting Bad Guys - notes for AI assistants

## What this is

A FastAPI threat intelligence platform that scans suspicious domains and IPs (DNS, WHOIS,
HTTP chain, certificates, root files, screenshots, GeoIP, BGP, IOC extraction,
static file analysis, disassembly, Tor-routed host probes) and stores results
per user with cases, reports, alerts, a public feed and a blog. Single
`docker compose up -d` deployment: Caddy + app + PostgreSQL.

## Layout

- `app/main.py` app factory + lifespan (hydrates stores from PostgreSQL,
  bootstraps the admin, launches the shared browser).
- `app/routes/` one router per area: pages, public (feeds), blog, analysis,
  store (results/folders/cases/reports), alerts, admin, extraction (EFI/EFA/NT),
  graph. Add new endpoints here, not in `main.py`.
- `app/state.py` in-memory per-user dicts; every write is mirrored through
  `app/db.py`. Tests import `_stores` etc. from `app.main` (re-exported).
- `app/security.py` SSRF guard (`is_safe_url`, `ssrf_request_hook`), log
  sanitiser, regex guard. Any new outbound HTTP must use the hook or check the
  URL first.
- `app/auth.py` local accounts + sessions (PyJWT HS256 cookie `_s`);
  `app/sso.py` OIDC code flow with PKCE.
- `app/routes/pages.py` serves `static/*.html` through `render_page`, which
  fills `{{APP_NAME}}`, `{{BRAND_A}}`, `{{BRAND_B}}`, `{{PUBLIC_URL}}`,
  `{{YEAR}}` and injects `/branding.css` (theme palette). Never hard-code the
  product name or domain in templates.
- `app/config.py` all settings; every new option needs a line in `.env.example`.

## Conventions

- Tooling: `uv` (lock file committed), `ruff` (lint + format), `pytest`
  (`asyncio_mode=auto`, no real network). Run `uv run ruff check . && uv run pytest -q`.
- No emoji in user-facing text or docs. Plain ASCII punctuation in the README.
- Secrets only via `HUNTER_*` environment variables; nothing operator-specific
  in the repository. `scripts/` is gitignored except the allow-listed files.
- Version lives in `pyproject.toml`; update `CHANGELOG.md` with every change.
- Tool pins (Playwright, radare2, JADX, Detect-It-Easy, Temurin) are Dockerfile
  `ARG`s updated by `scripts/update_deps.py`; keep the Playwright pin identical
  in `pyproject.toml`, `Dockerfile` and `.env.example`.
