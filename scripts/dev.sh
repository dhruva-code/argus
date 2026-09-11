#!/usr/bin/env bash
# Local dev launcher: backing services in Docker, app services from source.
# Usage: scripts/dev.sh [up|down|seed|test]
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=$(pwd)
export DATABASE_URL="postgresql+asyncpg://argus:${POSTGRES_PASSWORD:-argus}@localhost:5432/argus"
export REDIS_URL="redis://localhost:6379/0"
export ARGUS_TOOLS_BIN_DIR="${ARGUS_TOOLS_BIN_DIR:-$HOME/.local/bin}"

case "${1:-up}" in
  up)
    docker compose up -d postgres redis minio
    ( cd apis/gateway && alembic upgrade head )
    echo "Now run in separate terminals:"
    echo "  cd apis/gateway && uvicorn app.main:app --reload --port 8000"
    echo "  cd orchestrator && go run ./cmd/orchestrator"
    echo "  cd web && API_PROXY_TARGET=http://localhost:8000 npm run dev"
    ;;
  down)  docker compose down ;;
  seed)  ( cd apis/gateway && ARGUS_ALLOW_SEED=true python -m app.seed ) ;;
  test)
    ( cd apis/gateway && pytest -q )
    ( cd orchestrator && go test ./... )
    ( cd web && npm run typecheck )
    ;;
  *) echo "usage: $0 [up|down|seed|test]"; exit 1 ;;
esac
