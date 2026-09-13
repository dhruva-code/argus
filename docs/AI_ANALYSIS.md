# AI-assisted analysis

AI analysis is **entirely optional** and **read-only** — it never triggers
scans, changes scope, or executes anything, and the platform works
identically with it disabled. Implementation: `apis/gateway/app/services/ai.py`.

## Configuring it

**Settings → AI & Analysis** (org-level, requires the `settings.modify`
permission — org_admin+):

- Enable/disable toggle.
- Provider (currently only `anthropic` is live-testable/callable; the
  field is free text for forward compatibility) and model.
- API key — stored **encrypted at rest** via the same secret-storage
  backend already used for tool API keys (`app.core.crypto`: local Fernet,
  or HashiCorp Vault Transit if `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_TRANSIT_KEY`
  are set). The plaintext key is **never** returned by any API response —
  `GET /api/settings/ai` only ever returns a masked preview
  (`api_key_masked`, e.g. `sk-a****`). It is never logged.
- **Test connection** button — sends one minimal request (`max_tokens: 8`,
  "reply with the single word: ok") to confirm the key/model/provider are
  valid, and records the result as `not_configured` / `ok` / `failed`.

A pre-UI deployment that only ever set `ARGUS_AI_API_KEY`/`ARGUS_AI_MODEL`
environment variables keeps working — `resolve_config()` checks the
org's `ai_settings` row first and falls back to the environment variables
if no row is enabled/configured. This is checked directly by
`tests/test_ai_report_settings.py::test_resolve_config_*`.

## What it does

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

- Only the Anthropic Messages API is actually implemented for both
  analysis and connection-testing; other `provider` values are accepted
  and stored but `test_connection()` reports them as unsupported.
- AI calls are synchronous within the request that triggers them (not a
  background job/queue) — a slow or unreachable provider adds latency to
  that one request, though it never blocks scanning (recon workers never
  call into this module) and always has the heuristic fallback.
