# Contributing

## Ground rules

- Argus is for **authorized** security work. Contributions that add aggressive
  evasion, mass-targeting, or destructive-exploitation features will be
  declined. Dual-use capability must be gated behind scope + explicit
  authorization.
- Every outbound-request code path must go through the scope engine and the
  SSRF guard.
- No `shell=True` / string-built command lines. Use structured argv.

## Workflow

1. Branch from `main`.
2. `make lint && make test` must pass. New behavior needs tests.
3. A change to either scope engine must keep `make test-scope-parity` green; add
   fixtures for new semantics.
4. Database changes ship with an Alembic migration.
5. Open a PR describing the milestone it belongs to (see ROADMAP.md) and the
   security considerations.

## Commit / PR attribution

See the repository's contribution settings. Keep commits focused; explain *why*
in the body.

## Code style

| Area | Tooling |
|---|---|
| Python | `ruff check` + `ruff format` (line length 110) |
| Go | `gofmt`, `go vet` |
| TypeScript | `tsc --noEmit`, `next lint`, `prettier` |

## Plugin contributions

New tool plugins are welcome. Include: the plugin in
`orchestrator/internal/tools`, catalog metadata in
`apis/gateway/app/tool_catalog.py`, a health-state test, and the pinned
tested-version. Prefer official upstream release binaries.
