#!/usr/bin/env bash
# Container entrypoint: starts Tor, the optional nightly feed ingestion loop
# and the API server. All configuration comes from HUNTER_* environment
# variables (see .env.example).
set -euo pipefail

PORT="${HUNTER_PORT:-8000}"

# ── Tor (used for .onion targets and the "random exit IP" scan option) ───────
if [ "${HUNTER_TOR_ENABLED:-true}" = "true" ]; then
  mkdir -p "$HOME/tor"
  tor --quiet --DataDirectory "$HOME/tor" --SocksPort 9050 &
fi

# ── Nightly threat-feed ingestion (opt-in) ────────────────────────────────────
# Pulls public phishing / ransomware feeds and scans them as public results.
# Requires the bootstrap admin credentials because it talks to the local API.
if [ "${HUNTER_FEED_INGEST:-false}" = "true" ]; then
  (
    until curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; do sleep 3; done
    while true; do
      if [ -z "${HUNTER_ADMIN_USER:-}" ] || [ -z "${HUNTER_ADMIN_PASSWORD:-}" ]; then
        echo "[ingest] HUNTER_ADMIN_USER / HUNTER_ADMIN_PASSWORD not set, skipping feed ingestion"
        sleep 86400
        continue
      fi
      # Compute the next midnight BEFORE the run so an overrunning run never
      # shifts the schedule. The 22h cap guarantees the run ends before then.
      midnight=$(date -u -d 'tomorrow 00:00' +%s)
      echo "[ingest] Starting scheduled feed ingestion"
      # shellcheck disable=SC2086
      timeout 22h python scripts/ingest_feeds.py \
        -u "$HUNTER_ADMIN_USER" -p "$HUNTER_ADMIN_PASSWORD" \
        --base-url "http://127.0.0.1:${PORT}" \
        --feeds ${HUNTER_FEED_INGEST_FEEDS:-openphish urlhaus threatfox} \
        || echo "[ingest] Run exited with status $? (failure or 22h timeout)"
      now=$(date -u +%s)
      if [ "$now" -lt "$midnight" ]; then
        echo "[ingest] Done. Sleeping until next midnight UTC"
        sleep $((midnight - now))
      fi
    done
  ) &
fi

# ── API server ────────────────────────────────────────────────────────────────
# X-Forwarded-* headers are only trusted from the proxies listed in
# HUNTER_FORWARDED_ALLOW_IPS (default: the Docker bridge networks). The app
# port is never published to the host by the compose file; Caddy is the
# public face.
echo "[startup] Starting Uvicorn on port ${PORT}"
exec uvicorn app.main:app \
  --host 0.0.0.0 --port "${PORT}" \
  --proxy-headers \
  --forwarded-allow-ips="${HUNTER_FORWARDED_ALLOW_IPS:-172.16.0.0/12,10.0.0.0/8,192.168.0.0/16}" \
  --no-server-header \
  --log-level "${HUNTER_UVICORN_LOG_LEVEL:-info}"
