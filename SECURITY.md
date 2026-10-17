# Security

## Reporting a vulnerability

Please do not open a public issue for security problems. Email the maintainer
address listed on the repository profile, or use GitHub's private vulnerability
reporting on this repository. Include steps to reproduce and the version
(`/health` returns it). You will get an acknowledgement within a few days.

## Supported versions

Only the latest minor release receives security fixes.

## Deployment notes

- Run behind the bundled Caddy proxy with a real domain so HTTPS, HSTS and the
  `Secure` cookie flag are active (`HUNTER_PRODUCTION=true`).
- Set a strong `HUNTER_JWT_SECRET`; rotating it signs every user out.
- Leave `HUNTER_ADMIN_PASSWORD` empty so the first start generates a random
  admin password (never a shared default), then change it in the app.
- Keep `HUNTER_ALLOW_PRIVATE_TARGETS=false` unless the instance is isolated;
  it disables the SSRF guard on purpose.
- The application analyses hostile content (malware, phishing kits, APKs).
  Keep the container unprivileged, as shipped, and do not mount host paths
  other than the data volume.
- Enable single sign-on with a domain allow-list for team deployments and
  leave `HUNTER_INVITE_CODE` empty when registration is not needed.

## API keys

Keys are random 256-bit values prefixed `hbg_`, stored only as SHA-256 hashes,
shown once at creation and revocable by their owner or an administrator.
Deleting an account revokes its keys. Treat them like passwords; rotate a key
by creating a new one and revoking the old.

## Threat model summary

The service fetches arbitrary attacker-controlled URLs. Controls in place:
private-address blocking on every outbound request and redirect hop,
size-capped downloads and archive entries, per-user result isolation,
rate limiting, origin checks on writes, bcrypt passwords, signed HttpOnly
session cookies, a strict Content Security Policy and a non-root container
with all Linux capabilities dropped.
