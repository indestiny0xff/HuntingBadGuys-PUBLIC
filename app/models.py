"""Pydantic models for stored data and request bodies."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")


# ── DNS ──────────────────────────────────────────────────────────────────────


class SOARecord(BaseModel):
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


class MXRecord(BaseModel):
    priority: int
    exchange: str


class DNSRecords(BaseModel):
    A: list[str] = []
    AAAA: list[str] = []
    MX: list[MXRecord] = []
    TXT: list[str] = []
    NS: list[str] = []
    CNAME: list[str] = []
    SOA: SOARecord | None = None


# ── GeoIP ────────────────────────────────────────────────────────────────────


class GeoIPInfo(BaseModel):
    country_iso: str | None = None
    country_name: str | None = None
    city: str | None = None
    continent: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    postal_code: str | None = None


class GeoIPEntry(GeoIPInfo):
    """GeoIPInfo with the originating IP address attached (used in domain results)."""

    ip: str


# ── HTTP chain ────────────────────────────────────────────────────────────────


class RedirectHop(BaseModel):
    url: str
    status_code: int
    response_headers: dict[str, str] = {}
    tls: dict[str, Any] | None = None


# ── Root files ────────────────────────────────────────────────────────────────


class RootFile(BaseModel):
    path: str
    url: str
    status_code: int
    content_type: str | None = None
    size: int | None = None
    sha1: str | None = None
    minhash: str | None = None
    minhash_bands: list[str] = []


# ── WHOIS ─────────────────────────────────────────────────────────────────────


class WhoisInfo(BaseModel):
    domain_name: str | None = None
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    status: list[str] = []
    nameservers: list[str] = []
    emails: list[str] = []
    raw: str | None = None


# ── Domain result ─────────────────────────────────────────────────────────────


class DomainResult(BaseModel):
    target: str
    scan_url: str | None = None
    kind: str = "domain"
    via_tor: bool = False  # scanned through Tor; later re-fetches must use it too
    case_id: str | None = None
    is_private: bool = False
    scanned_at: str | None = None
    final_status: int | None = None
    final_url: str | None = None
    final_headers: dict[str, str] = {}
    headers_hash: str | None = None  # SHA-256 of sorted final response headers
    dns: DNSRecords | None = None
    whois: WhoisInfo | None = None
    chain: list[RedirectHop] = []
    root_files: list[RootFile] = []
    crawled_files: list[RootFile] = []
    screenshot: str | None = None
    screenshot_phash: str | None = None
    nt: dict[str, Any] | None = None  # dynamic network traffic capture
    certs: list[dict[str, Any]] = []
    geo_ips: list[GeoIPEntry] = []  # GeoIP info per DNS A record
    errors: dict[str, str] = {}


# ── IP / BGP result ───────────────────────────────────────────────────────────


class ASNInfo(BaseModel):
    asn: str | None = None
    asn_cidr: str | None = None
    asn_country_code: str | None = None
    asn_date: str | None = None
    asn_description: str | None = None
    asn_registry: str | None = None


class PrefixInfo(BaseModel):
    prefix: str | None = None
    name: str | None = None
    description: str | None = None
    country_code: str | None = None
    asns: list[dict[str, Any]] = []


class BGPInfo(BaseModel):
    asn: ASNInfo | None = None
    prefix: PrefixInfo | None = None
    he_url: str | None = None  # bgp.he.net deep link (DNS records tab)
    he_dns_records: list[dict[str, Any]] = []
    he_search_results: list[dict[str, Any]] = []


# ── Host Intelligence Gathering (HIG) ─────────────────────────────────────────


class HIGScript(BaseModel):
    id: str
    output: str


class HIGPort(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str | None = None
    reason: str | None = None  # nmap --reason (e.g. syn-ack, conn-refused)
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: list[str] = []
    scripts: list[HIGScript] = []


class HIGInfo(BaseModel):
    ip: str | None = None
    state: str | None = None
    hostnames: list[str] = []
    os_matches: list[dict[str, Any]] = []
    ports: list[HIGPort] = []
    scripts: list[HIGScript] = []
    all_ports: bool = False
    via_tor: bool = False
    scanned_at: str | None = None
    error: str | None = None


class IPResult(BaseModel):
    target: str
    kind: str = "ip"
    resolved_from: str | None = None  # hostname the user typed, when a name was resolved
    case_id: str | None = None
    is_private: bool = False
    scanned_at: str | None = None
    bgp: BGPInfo | None = None
    geo: GeoIPInfo | None = None
    hig: HIGInfo | None = None
    errors: dict[str, str] = {}


# ── Users ─────────────────────────────────────────────────────────────────────


class UserCreate(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError("Username must be 3-32 chars: letters, digits, _ or -")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password must be at most 128 characters")
        return v


class UserRegister(UserCreate):
    invite_code: str = Field(max_length=256)


class LoginRequest(BaseModel):
    """Login never enforces the registration policy: an account created with a
    different policy (bootstrap, import) must still be able to sign in."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return UserCreate.validate_password(v)


class AccessRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=254)
    reason: str = Field(default="", max_length=1000)


class UserInDB(BaseModel):
    id: str
    username: str
    hashed_password: str | None = None  # None for SSO-only accounts
    created_at: str
    email: str | None = None
    auth_provider: str = "local"  # "local" or "oidc"
    sso_subject: str | None = None
    is_admin: bool = False  # stored role; HUNTER_ADMIN_USERNAMES adds env-defined admins


class ApiKey(BaseModel):
    id: str
    user_id: str
    name: str
    key_hash: str
    prefix: str  # first characters of the key, for display
    created_at: str
    last_used_at: str | None = None


class ApiKeyCreate(BaseModel):
    name: str = Field(default="API key", max_length=80)


class ApiKeyPublic(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None = None


class AdminUserCreate(UserCreate):
    """Account created by an administrator (no invite code)."""

    is_admin: bool = False


class AdminUserUpdate(BaseModel):
    """Partial update of an account by an administrator."""

    username: str | None = None
    password: str | None = None
    is_admin: bool | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        return None if v is None else UserCreate.validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        return None if v is None else UserCreate.validate_password(v)


class UserPublic(BaseModel):
    id: str
    username: str
    created_at: str
    is_admin: bool = False
    auth_provider: str = "local"


# ── Folders ──────────────────────────────────────────────────────────────────


class Folder(BaseModel):
    id: str
    name: str
    created_at: str


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


# ── Cases ────────────────────────────────────────────────────────────────────


class Case(BaseModel):
    id: str
    name: str
    description: str = ""
    folder_id: str | None = None
    created_at: str
    notes_md: str = ""  # CTI report (markdown)
    report_title: str = ""
    report_updated_at: str | None = None


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    folder_id: str | None = None


class CasePatch(BaseModel):
    """Partial update; only provided fields change."""

    folder_id: str | None = None
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    notes_md: str | None = None
    report_title: str | None = Field(default=None, max_length=200)


class ReportUpdate(BaseModel):
    notes_md: str | None = None
    report_title: str | None = Field(default=None, max_length=200)


class ResultPatch(BaseModel):
    is_private: bool | None = None
    case_id: str | None = None


# ── Blog ─────────────────────────────────────────────────────────────────────


class BlogPostCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    slug: str = Field(default="", max_length=120)
    body_md: str = ""
    summary: str = Field(default="", max_length=1000)
    tags: list[str] = []
    case_id: str | None = None
    is_published: bool = True
    stix: dict | None = None  # STIX 2.1 bundle (downloadable on the blog)
    report_html: str = ""  # full HTML investigation report (downloadable)
    graph_svg: str = ""  # SVG case graph (downloadable)
    graph_png: str = ""  # legacy data: URL of the graph PNG


# ── Alert rules ──────────────────────────────────────────────────────────────


class AlertRule(BaseModel):
    id: str
    email: str
    query: str
    targets: list[str] = []
    case_id: str | None = None
    case_name: str | None = None
    label: str = ""
    frequency_minutes: int = 60
    scheduled_time: str | None = None  # "HH:MM" UTC, fires daily when set
    created_at: str
    next_run: str
    seen_ids: list[str] = []  # deprecated, kept for migration only
    seen_hashes: dict[str, Any] = {}  # _id -> {_overall, section...}


class AlertRuleCreate(BaseModel):
    email: str = Field(default="", max_length=254)  # empty: cache only, no email
    case_id: str | None = None
    label: str = Field(default="", max_length=120)
    query: str = Field(default="", max_length=2000)
    frequency_minutes: int = Field(default=60, ge=5, le=10080)
    scheduled_time: str | None = Field(default=None, max_length=5)


class AlertNotification(BaseModel):
    id: str
    alert_id: str
    case_id: str | None = None
    case_name: str | None = None
    triggered_at: str
    result_count: int
    results: list[dict] = []


# ── Request models ────────────────────────────────────────────────────────────


class DomainRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    is_private: bool = False
    screenshot: bool = True
    root_files: bool = True
    crawled_files: bool = True
    whois: bool = True
    certs: bool = True
    random_ua: bool = False
    random_ip: bool = False  # route traffic through Tor
    case_id: str | None = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        if any(len(t) > 2048 for t in cleaned):
            raise ValueError("A target exceeds 2048 characters")
        return cleaned


class IPRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    is_private: bool = False
    random_ip: bool = False
    case_id: str | None = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        if any(len(t) > 64 for t in cleaned):
            raise ValueError("A target exceeds 64 characters")
        return cleaned


class HIGRequest(BaseModel):
    """Run the host intelligence scan for a single IP."""

    target: str
    id: str | None = None  # existing result id to update in place
    all_ports: bool = False
    via_tor: bool = True

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("target must be a valid IP address")
        return v


class QueryRequest(BaseModel):
    query: str = Field(max_length=2000)
    ids: list[str] | None = None
    case_id: str | None = None
