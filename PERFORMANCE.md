# Performance

## Host-level snapshot

```bash
./doctor.sh --performance
```

Prints load average, memory, disk usage for the project directory, a
per-service (gateway/orchestrator/web) CPU%/RSS table, current queue depth
(`argus:jobs:queued`/`argus:jobs:processing` in Redis, when `redis-cli` is
available), and a single database round-trip measurement. This is the
install-framework's host-level complement to the in-app Scan Performance
Dashboard (phase/tool-duration timings, requests/sec, DNS queries/sec —
that data comes from the scan pipeline itself, not this shell tooling).

## Idempotent installs, not repeated work

- `python_setup`/`node_setup` hash `requirements.txt`/`package-lock.json`
  and skip reinstalling when nothing changed — `./install.sh` re-run on an
  already-current environment does no network I/O for dependencies at all.
- `tool_install` checks the installed version against `minimum_version`
  before doing anything — a healthy toolchain is a no-op pass.
- `env_setup_run` never regenerates `.env`; it's a single early check.

## Process management overhead

`services.sh` starts each process via `setsid` (one extra fork, negligible)
so it becomes its own session/process-group leader — this is what lets
`service_stop` signal the *whole* group on shutdown rather than leaving
orphaned children, at the cost of one additional PID existing for a few
milliseconds during startup (see `_spawn_detached`'s polling loop, capped at
5s, typically resolves in <200ms).

## Known bottlenecks / not yet profiled here

This installer framework does not itself profile the recon pipeline's
internals (crawler throughput, HTTP probing rate, Nuclei execution time,
finding-dedup cost, report generation time) — those are scan-runtime
performance characteristics owned by the orchestrator/gateway code, tracked
via the in-app dashboard and `internal/recon` phase timings, not by
`install.sh`/`run.sh`/`doctor.sh`. This document covers only the
installation/startup/diagnostics tooling's own performance properties.
