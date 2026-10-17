#!/usr/bin/env bash
# Restore a database dump produced by scripts/backup.sh.
#
#   bash scripts/restore.sh backups/hbg_20260101_030000.sql.gz
#
# The app container is stopped during the restore and started again afterwards.
set -euo pipefail

DUMP="${1:?usage: restore.sh <backup.sql.gz>}"
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
set -a; [ -f .env ] && . ./.env; set +a
PG_USER="${POSTGRES_USER:-hunter}"
PG_DB="${POSTGRES_DB:-hunter}"

read -r -p "This replaces the current database '${PG_DB}'. Continue? [y/N] " answer
[[ "${answer,,}" == "y" ]] || exit 1

docker compose stop app
docker compose exec -T db psql -U "$PG_USER" -d postgres -c "DROP DATABASE IF EXISTS \"${PG_DB}\";"
docker compose exec -T db psql -U "$PG_USER" -d postgres -c "CREATE DATABASE \"${PG_DB}\";"
gunzip -c "$DUMP" | docker compose exec -T db psql -U "$PG_USER" -d "$PG_DB" --quiet
docker compose start app
echo "Restore complete."
