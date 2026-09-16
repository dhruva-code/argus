# AI-assisted analysis

AI analysis is **entirely optional** and **read-only** — it never triggers
scans, changes scope, or executes anything, and the platform works
identically with it disabled. Implementation: `apis/gateway/app/services/ai.py`.

See [AI.md](AI.md) for how `install.sh` installs/configures Ollama + a
Qwen model automatically (adaptive sizing based on detected RAM) and its
own health checks (`doctor.sh --ollama`) — this document covers the
AI-analysis *pipeline* (what gets analyzed, when, and how results are
used) once a provider is configured, either that way or manually below.

## Configuring it

**Settings → AI & Analysis** (org-level, requires the `settings.modify`
permission — held by every account in the single-role model, see
[AUTHENTICATION.md](AUTHENTICATION.md)):

- Enable/disable toggle.
- Provider: `anthropic` (hosted) or `ollama` (local/self-hosted — no API
  key needed, just a reachable server URL, default
  `http://localhost:11434`), and model.
- API key (Anthropic only) — stored **encrypted at rest** via the same
  secret-storage backend already used for tool API keys
  (`app.core.crypto`: local Fernet, or HashiCorp Vault Transit if
  `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_TRANSIT_KEY` are set). The plaintext
  key is **never** returned by any API response — `GET /api/settings/ai`
  only ever returns a masked preview (`api_key_masked`, e.g. `sk-a****`).
  It is never logged.
- **Test connection** button — for Anthropic, sends one minimal request
  (`max_tokens: 8`, "reply with the single word: ok"); for Ollama, calls
  `/api/tags` (cheap — never loads the model) and confirms the configured
  model is actually pulled on that server. Records the result as
  `not_configured` / `ok` / `failed`.
- **Analyze every phase** toggle — see "Per-phase bug-hunting strategy"
  below. Off by default.

A pre-UI deployment that only ever set `ARGUS_AI_API_KEY`/`ARGUS_AI_MODEL`
(or `ARGUS_OLLAMA_BASE_URL`/`ARGUS_OLLAMA_MODEL`) environment variables
keeps working — `resolve_config()` checks the org's `ai_settings` row
first and falls back to the environment variables if no row is
enabled/configured. This is checked directly by
`tests/test_ai_report_settings.py::test_resolve_config_*`.

### Running a local model with Ollama

```
ollama pull qwen2.5:14b     # or any other model
ollama serve                 # usually already running as a service
```

Then in Settings → AI & Analysis: provider `Ollama`, model `qwen2.5:14b`
(must match the pulled tag exactly, or at least the part before `:`),
server URL `http://localhost:11434` (or wherever it's reachable). Hit
**Test connection** — this only checks the server responds and the model
is *present*, not that it can actually be *loaded and run* (see sizing
note below).

**Memory sizing.** Ollama needs enough free RAM (or VRAM, with a GPU) to
hold the whole model. A 14B-parameter model at Q4 quantization is roughly
9GB on disk and needs comparably more resident during inference. On a
memory-constrained host (this was reproduced on a 4-core/7.2GB machine
with no GPU), the Linux kernel's OOM killer will kill the Ollama process
mid-request rather than let it swap — `journalctl -u ollama` shows this
unambiguously (`"The kernel OOM killer killed some processes in this
unit"`, and the service restart-looping). The connectivity/model-presence
check still succeeds afterward (it's a cheap metadata call), which is why
System Health re-checks Ollama live on every poll rather than trusting a
one-time test — it's the only way to notice this happened between manual
checks. If this happens: use a smaller/more-quantized model, add more
RAM, or use a GPU. Every AI call site in this codebase treats an
unreachable/crashed provider as "fall back to the heuristic," never as a
hard failure, so the rest of the app is unaffected either way.

## What it does

### Per-phase bug-hunting strategy (opt-in)

When `Settings → AI & Analysis → "Analyze every phase"` is on, every time a
recon scan finishes a phase (`checkpoint: <phase>` in the job's own event
log), a background task (`app.services.events._run_phase_analysis`) builds
a lightweight summary from that job's own recent event log — the same
lines a human watching the live log would see, no orchestrator changes
needed — and asks the configured AI for 2-4 sentences of concrete
strategy: what's worth prioritizing next, referencing the actual hosts/
paths/technologies found, not generic advice (`analyse_phase()` in
`app/services/ai.py`). If one comes back, it's stored as its own job event
(`type: "ai_insight"`) and rendered as a highlighted callout in the job's
live log (Job detail page) rather than blending into the raw log lines.

This is fired with `asyncio.create_task(...)`, not awaited inline in the
event consumer — a local model in particular can take a long time (or, on
an undersized host, fail outright — see the sizing note above), and this
must never stall ingestion of other jobs' events. A missing/failed AI call
here just means no note for that phase; nothing about the scan itself is
affected. Off by default since it's an extra AI call per phase per scan
regardless of provider.

### Project-level executive summary

`POST /api/projects/{id}/ai-summary` — given the project's current
findings, returns an executive summary, related-finding clusters, a
suggested fix order, and remediation themes. Falls back to a deterministic
heuristic (no LLM call) when AI is disabled or the LLM call fails for any
reason — a provider outage never blocks report generation or the rest of
the app.

### Per-finding analysis

`POST /api/projects/{id}/findings/{id}/ai-analysis` (surfaced as an "AI
analysis" button in the Findings panel) — classification, false-positive
likelihood, severity reasoning, and remediation guidance for **one**
finding. The response has three explicitly separate top-level keys:

```json
{
  "observed_evidence": { "...": "the finding's own scanner data, verbatim" },
  "ai_analysis":       { "classification": "...", "false_positive_likelihood": "...", "severity_reasoning": "..." },
  "ai_recommendation": { "remediation": "..." }
}
```

`observed_evidence` is never generated or modified by AI — it's read
directly off the `Finding` row and handed back unchanged. This separation
is deliberate and enforced in code (`analyse_finding()` builds
`observed_evidence` first, independently of whether the AI or heuristic
path runs) specifically so AI output can never overwrite or be mistaken
for the finding's actual evidence.

The heuristic fallback (used when AI is disabled, or an LLM call fails)
reads the finding's **tier tag** (`"likely"` vs `"verified"`, set by the
injection-testing engine) rather than trusting the generic `verification`
field alone — both tiers currently share the same `verification:
"payload_confirmed"` constant, so a naive check would over-trust an
unreproduced single-sample timing hit exactly as much as a genuinely
reproduced one. See `_heuristic_finding_analysis()`.

## Privacy / redaction

Before anything reaches an AI provider:

- The project-level summary only ever sends a small, fixed set of fields
  per finding (severity, status, confidence, name, template ID, host,
  path, CVE, tags) — never raw request/response bodies, secrets, or
  evidence excerpts.
- The per-finding analysis *does* send the finding's request/response
  evidence (that's the point — it needs it to reason about the finding),
  but every such field passes through `redact()` first, which scrubs:
  - `api_key=`, `token=`, `secret=`, `password=`/`passwd=` style
    key-value pairs,
  - `Authorization:` and `Cookie:` header lines (to end of line, not just
    the first token — `Authorization: Bearer <token>` is two tokens),
  - JWT-shaped strings (`xxx.yyy.zzz`).
- `redact()` is deliberately conservative (redacts to end of line on a
  header match) — over-redacting a non-secret is a much smaller problem
  than under-redacting a real one.

`tests/test_ai_report_settings.py` covers both the redaction patterns
directly and confirms a full per-finding analysis call never leaks a
credential embedded in the raw request.

## Known limitations

- Anthropic and Ollama are the only two providers actually implemented for
  analysis and connection-testing; any other `provider` value is accepted
  and stored but `test_connection()` reports it as unsupported.
- The project-summary and per-finding AI calls are synchronous within the
  request that triggers them (not a background job/queue) — a slow or
  unreachable provider adds latency to that one request, though it never
  blocks scanning (recon workers never call into this module) and always
  has the heuristic fallback. Per-phase analysis (above) is the exception —
  that one is already async/fire-and-forget by design.
- A local model needs real memory headroom to run reliably, not just to
  answer a metadata ping — see the sizing note under "Running a local
  model with Ollama" above.
