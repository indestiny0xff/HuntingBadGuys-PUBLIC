# Contributing

Thanks for helping improve Hunting Bad Guys.

## Workflow

1. Fork and create a branch from `main`.
2. `uv sync && uv run pre-commit install`.
3. Make the change with tests (`tests/`, no network access in tests: mock
   `httpx`, `dnspython` and Playwright as the existing tests do).
4. `uv run ruff check . && uv run ruff format . && uv run pytest -q`.
5. Add a line under `[Unreleased]` in `CHANGELOG.md`.
6. Open a pull request describing the change and how you tested it.

## Code layout

```
app/
  main.py        application factory and lifespan
  config.py      settings (HUNTER_* environment variables)
  auth.py        local accounts, sessions, admin dependency
  sso.py         OpenID Connect flow
  middleware.py  rate limiting, origin checks, security headers
  security.py    SSRF guard, log sanitising, regex guard
  state.py       per-user in-memory stores (write-through to PostgreSQL)
  browser.py     shared Playwright browser
  db.py          asyncpg persistence
  models.py      pydantic models
  routes/        one router per feature area
  services/      DNS, WHOIS, HTTP, files, screenshots, BGP, GeoIP, EFA/EFI, ...
  query/         query language (tokenizer, parser, evaluator)
static/          single-file pages (served through app/routes/pages.py)
tests/           pytest suite
```

## Releases

1. Bump `version` in `pyproject.toml` and `APP_VERSION` in `.env.example`.
2. Move the `[Unreleased]` notes to a new section in `CHANGELOG.md` and add a
   short summary to the README.
3. Tag: `git tag vX.Y.Z && git push --tags`.
