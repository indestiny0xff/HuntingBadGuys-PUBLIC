"""EFI — Extracted File Info: regex-based IOC extraction from text."""

from __future__ import annotations

import re

_MAX_VALUES = 50

# Severity exported for frontend: 5=critical, 4=high, 3=medium, 2=low, 1=info
SCORES: dict[str, int] = {
    # Critical — live credentials / active tokens
    "telegram_bot_token": 5,
    "discord_webhook": 5,
    "slack_webhook": 5,
    "slack_token": 5,
    "api_key_openai": 5,
    "api_key_anthropic": 5,
    "api_key_aws_key": 5,
    "api_key_aws_secret": 5,
    "api_key_github": 5,
    "api_key_stripe": 5,
    "private_key_header": 5,
    # High — active C2 channels, dead drops, exfil infra
    "jwt": 4,
    "telegram": 4,
    "discord": 4,
    "onion": 4,
    "pastebin": 4,
    "google_drive": 4,
    "signal": 4,
    "matrix": 4,
    "whatsapp": 4,
    "github_raw": 4,
    "github_gist": 4,
    "wire": 4,
    "keybase": 4,
    "ngrok": 4,
    # Medium — crypto wallets, secondary credential patterns
    "crypto_btc": 3,
    "crypto_eth": 3,
    "crypto_xmr": 3,
    "crypto_trc20": 3,
    "crypto_ltc": 3,
    "github": 3,
    "notion": 3,
    "dropbox_link": 3,
    "api_key_google": 3,
    "api_key_twilio": 3,
    "api_key_mailgun": 3,
    "api_key_sendgrid": 3,
    "api_key_paypal": 3,
    "api_key_generic": 3,
    "iban": 3,
    # Low — social profiles, contact info
    "emails": 2,
    "phones": 2,
    "instagram": 2,
    "facebook": 2,
    "twitter": 2,
    "youtube": 2,
    "tiktok": 2,
    "snapchat": 2,
    "linkedin": 2,
    "steam": 2,
    "skype": 2,
    "wechat": 2,
    "line": 2,
    "viber": 2,
    "kik": 2,
    "icq": 2,
    "zalo": 2,
    "vk": 2,
    "reddit": 2,
    "twitch": 2,
    "twitch_clip": 2,
    "onlyfans": 2,
    "rumble": 2,
    "tinder": 2,
    "bumble": 2,
    "badoo": 2,
    "meetic": 2,
}

_PATS: dict[str, str] = {
    # ── Contact ──────────────────────────────────────────────────────────────
    # Require a plausible TLD and skip single-label domains (no dot in local part edge cases)
    "emails": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}",
    # Require at least 10 digits total (country code + 9 more) to rule out
    # port numbers, version strings, CSS values, etc.
    "phones": r"(?<![0-9A-Za-z+])\+[1-9](?:[\s.\-()\[\]]*\d){9,14}(?![0-9A-Za-z])",
    # ── Social / messaging ────────────────────────────────────────────────────
    "telegram": r"(?:t\.me|telegram\.(?:me|dog))/[a-zA-Z0-9_]{5,32}",
    # Filter Instagram reserved paths: explore, accounts, p (posts), reel, stories, etc.
    "instagram": (
        r"instagram\.com/"
        r"(?!(?:explore|accounts|p|reel|reels|stories|tv|ar|about|help|legal|privacy"
        r"|directory|challenge|oauth|api|support|direct|_u|_n|login|logout|signup|contact)(?:[/?#]|$))"
        r"[a-zA-Z0-9_.]{2,30}(?=[/?#\s]|$)"
    ),
    # Filter Facebook reserved paths
    "facebook": (
        r"facebook\.com/"
        r"(?:profile\.php\?id=\d{5,}"
        r"|(?!(?:login|sharer|share|dialog|groups|events|pages|marketplace|help"
        r"|settings|privacy|about|home|watch|gaming|ads|business|games|fundraisers"
        r"|notifications|friends|memories|saved|bookmarks|logout|signup)(?:[/?#]|$))"
        r"[a-zA-Z0-9.]{5,50})(?=[/?#\s]|$)"
    ),
    "steam": r"steamcommunity\.com/(?:id|profiles)/[a-zA-Z0-9_\-]{3,64}",
    # Filter Twitter/X reserved paths
    "twitter": (
        r"(?:twitter\.com|x\.com)/"
        r"(?!(?:i|intent|home|explore|settings|search|messages|notifications"
        r"|login|logout|signup|tos|privacy|about|who_to_follow|compose|share|hashtag"
        r"|following|followers|lists|bookmarks|verified|help|en)(?:[/?#]|$))"
        r"[a-zA-Z0-9_]{1,15}(?=[/?#\s]|$)"
    ),
    "discord": r"discord(?:\.gg|app\.com/invite|\.com/invite)/[a-zA-Z0-9\-]{6,20}",
    "youtube": r"youtube\.com/(?:channel/|c/|@)[a-zA-Z0-9_\-]{2,50}",
    "tiktok": r"tiktok\.com/@[a-zA-Z0-9_.]{2,24}",
    "snapchat": r"snapchat\.com/add/[a-zA-Z0-9._\-]{3,15}",
    "linkedin": r"linkedin\.com/in/[a-zA-Z0-9_\-]{3,100}",
    # GitHub profile/repo — filter reserved paths
    "github": (
        r"github\.com/"
        r"(?!(?:login|join|signup|explore|trending|issues|pulls|marketplace|topics"
        r"|collections|events|sponsors|about|pricing|features|security|enterprise"
        r"|team|contact|search|new|orgs|notifications|settings|dashboard|codespaces"
        r"|copilot|mobile|apps|cli|readme|wiki|releases|blob|tree|raw|commit|compare"
        r"|actions|packages|projects)(?:[/?#]|$))"
        r"[a-zA-Z0-9][a-zA-Z0-9_\-]{0,38}(?:/[a-zA-Z0-9_.\-]{1,100}(?:\.git)?)?"
    ),
    # Raw content delivery — primary C2 payload hosting vector on GitHub
    "github_raw": (
        r"raw\.githubusercontent\.com/"
        r"[a-zA-Z0-9_\-]{1,39}/[a-zA-Z0-9_.\-]{1,100}"
        r"/[a-zA-Z0-9_.\-/]+"
    ),
    # GitHub Gist — common dead-drop / exfil staging
    "github_gist": (
        r"gist\.github(?:usercontent)?\.com/"
        r"[a-zA-Z0-9_\-]{1,39}/[a-fA-F0-9]{20,40}"
    ),
    # ── Dating / romance scam ─────────────────────────────────────────────────
    "tinder": r"tinder\.com/(?:@|u/)[a-zA-Z0-9._\-]{3,50}",
    "bumble": r"bumble\.com/share/[a-zA-Z0-9_\-]{10,60}",
    "badoo": r"badoo\.com/(?:en/people/|profile/)[a-zA-Z0-9_\-]{3,50}",
    "meetic": r"meetic\.(?:com|fr|es|de|it)/(?:profil|profile)/[a-zA-Z0-9_\-]{3,50}",
    # ── Messaging / C2 channels ───────────────────────────────────────────────
    "whatsapp": r"(?:wa\.me|chat\.whatsapp\.com|api\.whatsapp\.com/send\?phone=)[/+\d?=a-zA-Z0-9_\-]{5,60}",
    # Signal — invite link (with hash fragment) OR phone-link format (#p/+phone)
    "signal": (
        r"signal\.(?:me|group)"
        r"(?:/#(?:p/\+[0-9]{7,15}|[a-zA-Z0-9+/=_\-]{20,120})"
        r"|/call/#[a-zA-Z0-9+/=_\-]{20,120})"
    ),
    "skype": r"(?:skype:[a-zA-Z0-9._\-]{6,32}(?:\?(?:chat|call|add))?|join\.skype\.com/[a-zA-Z0-9]{10,24})",
    "wechat": r"(?:weixin\.qq\.com|wx\.qq\.com)/(?:r/)?[a-zA-Z0-9+/=_\-]{4,40}",
    "line": r"line\.me/(?:ti/p/[~]?[a-zA-Z0-9._\-]{3,50}|R/msg/[a-zA-Z0-9]{10,30}|ti/g2?/[a-zA-Z0-9]{10,30})",
    "viber": r"viber\.com/[a-zA-Z0-9._\-]{3,50}(?=[/?#\s]|$)",
    "kik": r"kik\.me/[a-zA-Z0-9_.]{2,25}",
    "icq": r"icq\.com/[a-zA-Z0-9_\-]{3,50}",
    "wire": r"(?:wire\.com|app\.wire\.com)/join/[a-zA-Z0-9_\-]{10,40}",
    "zalo": r"zalo\.me/[a-zA-Z0-9._\-]{5,30}",
    # ── Broader social / scam platforms ──────────────────────────────────────
    "vk": (
        r"vk\.com/"
        r"(?!(?:login|register|share|wall|photo|video|album|doc|event|app|feed"
        r"|im|settings|search|away|link|notifier|promo|help|about|faq|legal"
        r"|dev|community|support|stats)(?:[/?#]|$))"
        r"[a-zA-Z][a-zA-Z0-9_.]{2,49}(?=[/?#\s]|$)"
    ),
    "reddit": r"reddit\.com/(?:r|u)/[a-zA-Z0-9_]{3,50}(?:/comments/[a-zA-Z0-9]{5,10})?",
    # Filter Twitch reserved paths
    "twitch": (
        r"twitch\.tv/"
        r"(?!(?:directory|following|subscriptions|settings|p|login|signup|downloads"
        r"|store|schedule|bits|prime|turbo|communities|teams|search|popout|moderator"
        r"|friends|inventory|videos|clips|events|squad|drops|turbo|wallet|payments"
        r"|dashboard|broadcast|embed|help|jobs|legal|about|press|partners|developers"
        r"|channel|games)(?:[/?#]|$))"
        r"[a-zA-Z0-9_]{4,25}(?=[/?#\s]|$)"
    ),
    # Filter OnlyFans reserved paths
    "onlyfans": (
        r"onlyfans\.com/"
        r"(?!(?:login|signup|register|forgot-password|privacy|terms|about|faq"
        r"|help|contact|dm|my|queue|vault|settings|notifications|news|explore"
        r"|api|home|search|categories|creators|discover)(?:[/?#]|$))"
        r"[a-zA-Z0-9_.\-]{3,50}(?=[/?#\s]|$)"
    ),
    "rumble": r"rumble\.com/(?:c/|user/|embed/)[a-zA-Z0-9_\-]{3,50}",
    "twitch_clip": r"clips\.twitch\.tv/[a-zA-Z0-9_\-]{5,60}",
    # ── Paste / payload hosting (C2) ─────────────────────────────────────────
    "pastebin": (
        r"(?:pastebin\.com|ghostbin\.co|hastebin\.com|paste\.ee/p|rentry\.co"
        r"|dpaste\.com|bin\.bz|controlc\.com|paste\.rs|0paste\.com|paste\.fo"
        r"|toptal\.com/developers/hastebin)/(?:raw/|e/)?[a-zA-Z0-9]{4,20}(?=[/?#\s\"']|$)"
    ),
    # ── Tunneling / C2 infrastructure ────────────────────────────────────────
    # ngrok tunnels — heavily used for C2 / phishing / exfil over HTTPS
    "ngrok": (
        r"https?://[a-zA-Z0-9\-]+\.ngrok(?:-free|-static)?\.(?:app|io|com)"
        r"(?:/[a-zA-Z0-9_.\-/]*)?"
    ),
    # ── Dead drop / C2 file sharing ───────────────────────────────────────────
    "google_drive": r"(?:docs|drive|sheets|forms)\.google\.com/(?:document|spreadsheets|presentation|file|forms)/d/(?:e/)?[a-zA-Z0-9_\-]{25,100}",
    "notion": r"notion\.so/(?:[a-zA-Z0-9\-]+[-/])?[a-zA-Z0-9]{20,40}",
    "dropbox_link": r"(?:dropbox\.com/(?:s|sh)/[a-zA-Z0-9]{8,25}|1drv\.ms/[a-zA-Z0-9!_\-]{5,30})",
    "keybase": r"keybase\.io/[a-zA-Z0-9_]{3,30}(?:[/?#\s]|$)",
    "matrix": r"matrix\.to/#/[#@!][a-zA-Z0-9._~$&()*+,;=:@%\-]+:[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    # ── Crypto wallets ────────────────────────────────────────────────────────
    # BTC: legacy P2PKH/P2SH + bech32 SegWit; require non-alphanumeric boundaries
    "crypto_btc": r"(?<![a-zA-Z0-9/])(?:[13][a-km-zA-HJ-NP-Z1-9]{24,33}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59})(?![a-zA-Z0-9])",
    # ETH: 0x + 40 hex — require word boundaries to avoid matching 64-char tx hashes midstring
    "crypto_eth": r"\b0x[a-fA-F0-9]{40}\b",
    # XMR: 4 + 94 base58 = 95 chars, very distinctive
    "crypto_xmr": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    # USDT TRC20: T + 33 base58 = 34 chars
    "crypto_trc20": r"(?<![a-zA-Z0-9])T[a-km-zA-HJ-NP-Z1-9]{33}(?![a-zA-Z0-9])",
    # LTC: starts L/M (legacy) — 26-34 base58 chars
    "crypto_ltc": r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    # ── Hidden services ───────────────────────────────────────────────────────
    "onion": r"\b[a-z2-7]{56}\.onion\b|\b[a-z2-7]{16}\.onion\b",
    # ── Finance ───────────────────────────────────────────────────────────────
    # IBAN: country-code whitelist (only real IBAN-issuing countries) + minimum
    # BBAN length of 11 chars (shortest real IBAN is NO = 15 chars total).
    # Mod-97 check digit validation is applied in _is_false_positive() to
    # eliminate the ~1% of random strings that pass the structural pattern.
    "iban": (
        r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DK|DO"
        r"|EE|EG|ES|FI|FK|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS"
        r"|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MR|MT|MU|MZ"
        r"|NI|NL|NO|PK|PL|PS|PT|QA|RO|RS|SA|SC|SD|SE|SI|SK|SM|ST|SV"
        r"|TL|TN|TR|UA|VA|VG|XK)"
        r"\d{2}[A-Z0-9]{11,30}\b"
    ),
    # ── Bots / webhooks ───────────────────────────────────────────────────────
    "telegram_bot_token": r"\b\d{8,12}:AA[a-zA-Z0-9_\-]{33,35}\b",
    "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[a-zA-Z0-9_\-]{60,80}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}",
    "slack_token": r"\bxox[bpoas]-[0-9a-zA-Z\-]{10,100}\b",
    # ── API keys / credentials ────────────────────────────────────────────────
    # OpenAI: sk- or sk-proj- prefix, require ≥ 32 chars to avoid test values
    "api_key_openai": r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{32,200}\b",
    "api_key_anthropic": r"\bsk-ant-[a-zA-Z0-9\-_]{80,}\b",
    "api_key_aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "api_key_aws_secret": r"(?:aws_secret|AWS_SECRET)[_A-Z]*\s*[=:\"'\s]+([A-Za-z0-9/+]{40})\b",
    # GitHub tokens: classic ghp/gho/ghu/ghs/ghr_ + new github_pat_ format
    "api_key_github": r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b|\bgithub_pat_[a-zA-Z0-9_]{50,}\b",
    "api_key_stripe": r"\b(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b",
    "api_key_sendgrid": r"\bSG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}\b",
    "api_key_google": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "api_key_twilio": r"\bSK[a-f0-9]{32}\b",
    "api_key_mailgun": r"\bkey-[a-f0-9]{32}\b",
    "api_key_paypal": r"\bA21AA[a-zA-Z0-9\-_]{60,}\b",
    # Generic: require key/secret/token keyword + assignment + value with mixed chars
    "api_key_generic": (
        r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token"
        r"|bearer[_\-]?token|private[_\-]?token|client[_\-]?secret)"
        r"[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9\-_]{20,64})"
    ),
    # JWT: three base64url parts, eyJ prefix is characteristic of {"
    "jwt": r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
    "private_key_header": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
}

_STRIP_TRAIL = re.compile(r"[/?#\s]+$")

# Email prefixes / domains to skip as noise
_SKIP_EMAIL_PREFIXES = frozenset(
    {
        "noreply@",
        "no-reply@",
        "donotreply@",
        "do-not-reply@",
        "mailer-daemon@",
        "postmaster@",
        "bounce@",
        "bounces@",
        "notifications@",
        "notification@",
        "alerts@",
        "alert@",
        "support@example",
        "test@example",
        "user@example",
        "admin@example",
        "info@example",
        "contact@example",
    }
)
_SKIP_EMAIL_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "localhost.com",
        "invalid.com",
        "w3.org",
        "schema.org",
        "openid.net",
        "sentry.io",  # sentry DSN emails in JS bundles
    }
)

# Hostnames that commonly appear in source code as false-positive github URLs
_SKIP_GITHUB_PATHS = re.compile(
    r"github\.com/(?:actions/|orgs/|apps/|marketplace/|sponsors/|new|"
    r"settings|notifications|dashboard|codespaces|copilot|features|security)(?:[/?#]|$)",
    re.IGNORECASE,
)


def _clean(val: str) -> str:
    return _STRIP_TRAIL.sub("", val.strip())


def _is_noise(cat: str, v: str) -> bool:
    lv = v.lower()
    if cat == "emails":
        if any(lv.startswith(p) for p in _SKIP_EMAIL_PREFIXES):
            return True
        domain = lv.split("@", 1)[-1] if "@" in lv else ""
        if domain in _SKIP_EMAIL_DOMAINS:
            return True
        return False
    if cat == "github":
        # Skip paths that are navigational / infrastructure
        if _SKIP_GITHUB_PATHS.search(v):
            return True
        return False
    if cat in {"crypto_btc", "crypto_trc20", "crypto_ltc", "crypto_eth", "crypto_xmr"}:
        # Reject transaction hashes (64 hex chars)
        if re.fullmatch(r"[a-fA-F0-9]{64}", v):
            return True
        # camelCase → JS identifier, not a crypto address
        if re.search(r"[a-z][A-Z]", v):
            return True
        # Base58 explicitly excludes 0, O, I, l; re.IGNORECASE lets them slip through.
        # ETH uses hex (not base58); bech32 BTC (bc1...) uses its own lowercase charset.
        if cat != "crypto_eth" and not v.startswith("bc1"):
            if re.search(r"[0OIl]", v):
                return True
        return False
    if cat == "phones":
        # Reject year-range patterns like +2016-2017 or +2016/2017 where both
        # groups are 4-digit years (19xx or 20xx) separated by a single punctuation.
        if re.search(r"(?:19|20)\d{2}[-/](?:19|20)\d{2}", v):
            return True
        return False
    if cat == "iban":
        stripped = re.sub(r"\s+", "", v).upper()
        if not (15 <= len(stripped) <= 34):
            return True
        # Mod-97 check digit validation (ISO 13616).
        # Move first 4 chars to the end, convert letters → digits (A=10…Z=35),
        # then compute mod 97.  A valid IBAN always yields remainder 1.
        # This eliminates ~99 % of structural false positives.
        rearranged = stripped[4:] + stripped[:4]
        numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
        try:
            return int(numeric) % 97 != 1
        except ValueError:
            return True
    return False


def extract(texts: list[str]) -> dict[str, list[str]]:
    """Run all IOC patterns over a list of text strings. Returns categories sorted by severity."""
    combined = "\n".join(t for t in texts if t)
    if not combined.strip():
        return {}
    raw: dict[str, list[str]] = {}
    for cat, pat in _PATS.items():
        matches: set[str] = set()
        for m in re.finditer(pat, combined, re.IGNORECASE):
            try:
                v = _clean(m.group(1))
            except IndexError:
                v = _clean(m.group(0))
            if len(v) >= 3 and not _is_noise(cat, v):
                matches.add(v)
        if matches:
            raw[cat] = sorted(matches)[:_MAX_VALUES]
    # Sort categories: highest severity first, then alphabetically within same score
    return dict(sorted(raw.items(), key=lambda kv: (-SCORES.get(kv[0], 0), kv[0])))


def merge(existing: dict[str, list[str]], new: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {k: list(v) for k, v in existing.items()}
    for cat, values in new.items():
        combined_set = set(merged.get(cat, [])) | set(values)
        merged[cat] = sorted(combined_set)[:_MAX_VALUES]
    return dict(sorted(merged.items(), key=lambda kv: (-SCORES.get(kv[0], 0), kv[0])))


def delete_item(efi: dict[str, list[str]], category: str, value: str) -> dict[str, list[str]]:
    result = {k: list(v) for k, v in efi.items()}
    if category in result:
        result[category] = [v for v in result[category] if v != value]
        if not result[category]:
            del result[category]
    return result
