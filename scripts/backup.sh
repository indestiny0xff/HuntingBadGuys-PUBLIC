#!/usr/bin/env bash
# Dump the PostgreSQL database and the application data volume.
#
#   bash scripts/backup.sh                 # writes backups/hbg_<timestamp>.sql.gz and .tar.gz
#   BACKUP_DIR=/mnt/backups bash scripts/backup.sh
#
# Schedule it with cron, for example daily at 03:00:
#   0 3 * * * cd /opt/huntingbadguys && bash scripts/backup.sh >> backups/backup.log 2>&1
set -euo pipefail

cd "$(dirname "$0")/.."
BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
STAMP=$(date -u +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# shellcheck disable=SC1091
set -a; [ -f .env ] && . ./.env; set +a
PG_USER="${POSTGRES_USER:-hunter}"
PG_DB="${POSTGRES_DB:-hunter}"

echo "[$(date -u +%FT%TZ)] Dumping database ${PG_DB}"
docker compose exec -T db pg_dump -U "$PG_USER" -d "$PG_DB" --no-owner --no-acl \
  | gzip > "$BACKUP_DIR/hbg_${STAMP}.sql.gz"

echo "[$(date -u +%FT%TZ)] Archiving data volume (users.json, GeoIP database)"
docker compose exec -T app tar czf - -C /data . > "$BACKUP_DIR/hbg_${STAMP}_data.tar.gz"

find "$BACKUP_DIR" -name "hbg_*" -mtime +"$RETENTION_DAYS" -delete
echo "[$(date -u +%FT%TZ)] Done: $(ls -1 "$BACKUP_DIR" | wc -l) file(s) kept (${RETENTION_DAYS}d retention)"
