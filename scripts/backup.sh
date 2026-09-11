#!/usr/bin/env bash
# scripts/backup.sh — configuration + database backup, run automatically
# before install.sh --upgrade and callable directly (§37/§38). Never dumps
# secret *values* into the backup directory listing/logs — the .env file
# itself is copied (it has to be, to be useful for restore) but permissions
# are locked down and nothing about its content is echoed anywhere.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=install
# shellcheck source=lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
# shellcheck source=lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${ARGUS_BACKUP_DIR}/${STAMP}"

step "Backing up configuration + database metadata to backups/${STAMP}/"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

if [[ -f "$ARGUS_ENV_FILE" ]]; then
  cp "$ARGUS_ENV_FILE" "${OUT_DIR}/env.backup"
  chmod 600 "${OUT_DIR}/env.backup"
  ok "backed up .env"
fi

if [[ -f "${ARGUS_ROOT}/docker-compose.yml" ]]; then
  cp "${ARGUS_ROOT}/docker-compose.yml" "${OUT_DIR}/" 2>/dev/null || true
fi

db_load_config
if db_tcp_reachable && has_cmd pg_dump; then
  info "dumping database (${DB_NAME})…"
  if PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
       --format=custom --file="${OUT_DIR}/database.dump" 2>>"${ARGUS_LOG_DIR}/install.log"; then
    ok "database dump: ${OUT_DIR}/database.dump ($(du -h "${OUT_DIR}/database.dump" 2>/dev/null | cut -f1))"
  else
    warn "pg_dump failed — database was NOT backed up (config was); see ${ARGUS_LOG_DIR}/install.log"
  fi
elif db_tcp_reachable; then
  warn "pg_dump not installed — only configuration was backed up, not the database itself"
else
  warn "database unreachable — only configuration was backed up"
fi

if [[ -x "$ARGUS_VENV_PY" && -d "${ARGUS_GATEWAY_DIR}/alembic" ]]; then
  db_alembic_head >"${OUT_DIR}/alembic_head.txt" 2>/dev/null || true
fi

ok "backup complete: ${OUT_DIR}"
info "restore: pg_restore --clean -h HOST -U USER -d DB backups/${STAMP}/database.dump"
