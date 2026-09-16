# Local AI: Ollama + Qwen (installation & operations)

This document covers installing, configuring, and health-checking the
local AI stack (`scripts/lib/ollama.sh`). For what the AI pipeline
actually does with a configured provider (which phases it touches, how
results are stored, the fallback behavior), see
[AI_ANALYSIS.md](AI_ANALYSIS.md).

**AI is entirely optional.** Every AI call site in this codebase falls
back to a deterministic heuristic when no provider is configured, or a
call fails for any reason — nothing else in Argus (recon, scanning,
findings, secrets, reports) depends on it. Local AI in particular is
CPU/RAM-hungry with no GPU acceleration assumed; see "Resource
protection" below.

## Installation

`./install.sh` installs and configures Ollama + a Qwen model
automatically, between the bootstrap-admin step and final health checks
(see [INSTALL.md](INSTALL.md) for the full ordering). It:

1. Detects an existing Ollama install and version; installs via the
   official `https://ollama.com/install.sh` script if missing.
2. Starts the Ollama service (systemd if available, else a background
   `ollama serve`) and waits for `/api/tags` to respond.
3. Picks a Qwen 2.5 model size based on **detected RAM** (never assumes
   one size fits all hardware — see table below), unless
   `ARGUS_OLLAMA_MODEL` is already set in `.env`.
4. Pulls that model (idempotent — a no-op if already present).
5. Runs a **real inference call** (not just a connectivity ping) to
   confirm the model actually loads and generates a response on this
   host.
6. Persists the resolved `ARGUS_OLLAMA_BASE_URL`/`ARGUS_OLLAMA_MODEL`
   into `.env` so the gateway's AI service picks them up automatically.

Skip it entirely with `./install.sh --no-ai` or `ARGUS_SKIP_OLLAMA=1`.
None of these steps ever fail the install — a failure here is a `warn`,
not a `die` (see `scripts/lib/ollama.sh`'s module docstring).

## Model sizing

A 14B-parameter model at Q4 quantization is roughly 9GB on disk and needs
comparably more resident RAM during inference — confirmed to trigger the
Linux OOM killer on a 4-core/7.2GB host with no GPU. `install.sh` picks
a size with headroom for the rest of the stack (Postgres/Redis/
gateway/orchestrator) running on the same box:

| Detected RAM | Model picked |
|---|---|
| ≥ 24 GB | `qwen2.5:14b` |
| ≥ 12 GB | `qwen2.5:7b` |
| ≥ 6 GB | `qwen2.5:3b` |
| < 6 GB | `qwen2.5:1.5b` |

Override with `ARGUS_OLLAMA_MODEL` in `.env` if you know better for your
hardware (a bigger model on a beefier box than the installer saw, a GPU,
etc.) — `./repair.sh` will pull whatever's configured there.

## Health checks

```bash
./doctor.sh --ollama
```

Reports four distinct checks — **never treats "the binary/process
exists" as healthy on its own**:

```
OLLAMA / QWEN
[OK]   ollama 0.34.0
[OK]   ollama service reachable at http://localhost:11434
[OK]   model 'qwen2.5:3b' available
==> Ollama inference test (qwen2.5:3b)
[OK]   inference test passed
```

If Ollama isn't installed at all, this is a `[WARN]` (optional
component), not a `[FAIL]` — it never blocks `doctor.sh`'s overall
summary. If it's installed but broken (unreachable, model missing,
inference failing), each specific cause is reported separately so you
know exactly what to fix.

## Repair

```bash
./repair.sh   # includes ollama_repair: restarts the service if
              # unreachable, re-pulls the configured model if missing
```

## Troubleshooting

**Inference test fails / times out.** Almost always one of: the model is
too large for available RAM (check `dmesg`/`journalctl -u ollama` for
`oom-kill`/"killed some processes in this unit" — the service
restart-looping is the clearest signal), the service just started and is
still loading the model into memory (cold start on a large model can take
a minute+ on CPU), or the host is under heavy load from something else
(a concurrent scan). Fix: use a smaller model
(`ARGUS_OLLAMA_MODEL=qwen2.5:1.5b` in `.env`, then `./repair.sh`), add
RAM, or use a GPU-capable host.

**Argus never calls the AI at all.** Confirm `ARGUS_OLLAMA_MODEL` is set
in `.env` (or configure a provider in Settings → AI & Analysis) and that
`./doctor.sh --ollama` reports all four checks passing — see
[AI_ANALYSIS.md](AI_ANALYSIS.md) for which pipeline phases actually
invoke it and how to verify a specific one ran.

**Manual install/config**, if you'd rather not let `install.sh` manage
it: see [AI_ANALYSIS.md](AI_ANALYSIS.md#running-a-local-model-with-ollama).

## Resource protection

- Only **one** model is kept configured/loaded by default — `install.sh`
  never pulls multiple large models.
- No GPU is assumed anywhere in this stack; every size band above is
  chosen against CPU-only inference.
- The gateway serializes every LLM call (local or hosted) through a
  single semaphore (`app/services/ai.py`) — a burst of findings/secrets
  from an active scan can't pile up concurrent model calls and multiply
  memory pressure.
- AI-triage results are cached by an evidence fingerprint (see
  [AI_ANALYSIS.md](AI_ANALYSIS.md)) so unchanged findings/secrets are not
  re-analyzed on every re-observation.
