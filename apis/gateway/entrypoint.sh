#!/usr/bin/env bash
# Gateway container entrypoint: wait for the database, migrate, optionally seed,
# then start the API server.
set -euo pipefail

echo "[entrypoint] waiting for database..."
python - <<'PY'
import os, time, sys
import psycopg
url = os.environ["DATABASE_URL"].replace("+asyncpg", "").replace("postgresql+psycopg", "postgresql")
for attempt in range(60):
    try:
        psycopg.connect(url).close()
        print("[entrypoint] database is up")
        break
    except Exception as exc:  # noqa
        print(f"[entrypoint] db not ready ({attempt}): {exc}")
        time.sleep(2)
else:
    sys.exit("[entrypoint] database never became ready")
PY

echo "[entrypoint] running migrations..."
alembic upgrade head

if [ "${ARGUS_ALLOW_SEED:-false}" = "true" ]; then
    echo "[entrypoint] seeding demo data..."
    python -m app.seed || echo "[entrypoint] seed skipped/failed (continuing)"
fi

echo "[entrypoint] starting gateway on ${ARGUS_API_HOST:-0.0.0.0}:${ARGUS_API_PORT:-8000}"
exec uvicorn app.main:app \
    --host "${ARGUS_API_HOST:-0.0.0.0}" \
    --port "${ARGUS_API_PORT:-8000}" \
    --proxy-headers --forwarded-allow-ips='*'
