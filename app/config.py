"""Application settings.

Every value can be set through an environment variable prefixed with ``HUNTER_``
(for example ``HUNTER_JWT_SECRET``) or through a ``.env`` file in the working
directory. See ``.env.example`` for the documented list.
"""

from __future__ import annotations

import secrets

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

THEMES = ("purple", "red", "green", "blue", "black")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HUNTER_", env_file=".env", extra="ignore")

    # ── Branding ───────────────────────────────────────────────────────────────
    app_name: str = "Hunting Bad Guys"
    theme: str = "purple"
    # Public base URL (scheme + host), used for canonical links, sitemap and SSO
    # redirects. Example: https://hunt.example.com
    public_url: str = "http://localhost:8000"

    # ── Runtime ────────────────────────────────────────────────────────────────
    production: bool = False
    port: int = 8000
    data_dir: str = "/data"
    log_level: str = "INFO"

    # ── Authentication ─────────────────────────────────────────────────────────
    # Required in production. A random secret is generated in development so the
    # app starts without configuration, but sessions then reset on each restart.
    jwt_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    session_hours: int = 24
    # Marks the session cookie Secure. Defaults to the value of `production`.
    secure_cookie: bool | None = None
    # Invite code required for self-registration. Empty disables registration.
    invite_code: str = ""
    # Comma-separated usernames that get admin rights.
    admin_usernames: str = ""
    # Bootstrap admin, created at startup when it does not exist. With an empty
    # password a random one is generated, printed once in the log and saved to
    # <data_dir>/initial-admin-password.txt until it is changed.
    admin_user: str = "admin"
    admin_password: str = ""
    # Where "request access" emails are sent. Empty disables the request form.
    access_request_email: str = ""
    # Usernames hidden from the Intel team feed (for example a bulk ingest account).
    feed_exclude_usernames: str = ""

    # ── Single sign-on (OpenID Connect) ────────────────────────────────────────
    # Works with any OIDC provider: Google, Microsoft Entra ID, Okta, Keycloak,
    # Authentik, Zitadel. Leave the issuer empty to disable SSO.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_button_label: str = "Sign in with SSO"
    # Comma-separated email domains allowed to sign in (empty allows every domain).
    oidc_allowed_domains: str = ""
    # Create a local account on first SSO login.
    oidc_auto_create: bool = True
    # When true, the password form is hidden and only SSO can be used.
    oidc_only: bool = False

    # ── Database (PostgreSQL) ──────────────────────────────────────────────────
    # Example: postgresql://hunter:secret@db:5432/hunter. Empty keeps results in
    # memory only (they are lost on restart).
    db_dsn: str = ""

    # ── Outbound email (SMTP) ──────────────────────────────────────────────────
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True

    # ── Scanning ───────────────────────────────────────────────────────────────
    timeout: int = 15
    screenshot_width: int = 1280
    screenshot_height: int = 800
    max_file_bytes: int = 1_048_576
    max_targets_per_request: int = 50
    # Allow scanning private / loopback / link-local addresses (SSRF guard off).
    allow_private_targets: bool = False
    # "|"-separated User-Agent pool used when "random UA" is enabled on a scan.
    user_agents: str = ""
    # SOCKS proxy for .onion targets and the "random exit IP" option.
    tor_proxy: str = "socks5://127.0.0.1:9050"
    # Host Intelligence Gathering (Tor-routed port/service probe for IP scans).
    hig_enabled: bool = True
    # Playwright stealth patches for screenshots.
    stealth_mode: bool = True
    # GeoIP database path (downloaded automatically when missing).
    geoip_db: str = ""
    geoip_download_url: str = (
        "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
    )
    # Root files probed on every domain scan.
    root_paths: list[str] = [
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/ads.txt",
        "/crossdomain.xml",
        "/.well-known/security.txt",
        "/gate.php",
        "/submit.php",
        "/result.php",
        "/login.php",
        "/wp-login.php",
        "/shell.php",
        "/phpinfo.php",
        "/log.txt",
        "/logs/log.txt",
        "/backup.zip",
        "/.env",
        "/config.php",
        "/config.json",
        "/config.yaml",
        "/wp-config.php",
        "/.git/HEAD",
        "/.git/config",
        "/.well-known/ai-plugin.json",
        "/.well-known/mcp.json",
        "/openapi.json",
        "/openapi.yaml",
        "/.well-known/openapi.json",
    ]

    # ── Threat feed ingestion (optional, runs nightly inside the container) ────
    feed_ingest: bool = False
    feed_ingest_feeds: str = "openphish urlhaus threatfox"

    # ── Derived helpers ────────────────────────────────────────────────────────
    @property
    def cookie_secure(self) -> bool:
        return self.production if self.secure_cookie is None else self.secure_cookie

    @property
    def sso_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def registration_enabled(self) -> bool:
        return bool(self.invite_code) and not self.oidc_only

    @property
    def admin_username_list(self) -> list[str]:
        return [u.strip() for u in self.admin_usernames.split(",") if u.strip()]

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if self.theme not in THEMES:
            raise ValueError(f"HUNTER_THEME must be one of {', '.join(THEMES)}")
        self.public_url = self.public_url.rstrip("/")
        if self.production and len(self.jwt_secret) < 32:
            raise ValueError("HUNTER_JWT_SECRET must be set (32+ characters) in production")
        if self.oidc_only and not self.sso_enabled:
            raise ValueError(
                "HUNTER_OIDC_ONLY requires HUNTER_OIDC_ISSUER and HUNTER_OIDC_CLIENT_ID"
            )
        return self


settings = Settings()
