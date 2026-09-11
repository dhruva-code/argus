# Development

## Prerequisites

- Docker + Docker Compose (for postgres / redis / minio)
- Python 3.11+ (3.12 recommended; the gateway container uses 3.12)
- Go 1.23+
- Node 20+

## Layout

```
apis/gateway/     FastAPI service   (app/, alembic/, tests/)
orchestrator/     Go service        (cmd/, internal/, pkg/)
web/              Next.js app       (src/app, src/components, src/lib)
cli/              argus CLI         (stdlib only)
db/migrations/    (reserved for raw SQL; alembic is authoritative)
testdata/         shared fixtures (scope parity)
docs/             documentation
deploy/k8s/       Kubernetes manifests
```

## Fast local loop (no container rebuilds)

```bash
cp .env.example .env          # fill in secrets
make infra                    # postgres + redis + minio in Docker

# gateway
cd apis/gateway
python -m venv .venv && . .venv/bin/venv/activate 2>/dev/null || . .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+asyncpg://argus:$POSTGRES_PASSWORD@localhost:5432/argus
export REDIS_URL=redis://localhost:6379/0
alembic upgrade head
ARGUS_ALLOW_SEED=true python -m app.seed        # demo data + demo logins
uvicorn app.main:app --reload --port 8000

# orchestrator (another shell)
cd orchestrator
REDIS_URL=redis://localhost:6379/0 ARGUS_TOOLS_BIN_DIR=$HOME/.local/bin \
  go run ./cmd/orchestrator

# web (another shell)
cd web
npm install
API_PROXY_TARGET=http://localhost:8000 npm run dev
# http://localhost:3000
```

> Background processes are SIGKILLed on shell exit in some sandboxes — run each
> service in its own terminal, or use `nohup`.

## Tests

```bash
make test               # gateway (pytest) + orchestrator (go test)
make test-scope-parity  # Go and Python scope engines vs the shared fixtures
make test-web           # tsc --noEmit + next lint
make lint               # ruff + gofmt + go vet + eslint
```

The gateway test suite uses an isolated SQLite schema per test and stubs Redis,
so it needs no running services.

## Adding a database change

```bash
make migration m="add findings table"   # autogenerate against a live postgres
# review apis/gateway/alembic/versions/*.py, then
make migrate
```

## Adding a tool plugin

1. Add the `cliTool{...}` entry (or a bespoke `plugin.Tool` impl) in
   `orchestrator/internal/tools/registry.go`.
2. Mirror its display metadata in `apis/gateway/app/tool_catalog.py`.
3. Add a health-state case to `orchestrator/internal/tools/registry_test.go`.

## Conventions

- Python: `ruff` (line length 110), type hints, async SQLAlchemy 2.0 style.
- Go: `gofmt`, `go vet` clean, table-driven tests.
- TS: strict mode, no `any` in shared types, server data through TanStack Query.
