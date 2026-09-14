"""Optional AI-assisted analysis (M7).

Two entry points:

* `analyse()` — project-level: an executive summary, related-finding
  clusters, and a suggested fix order across all current findings.
* `analyse_finding()` — per-finding: classification, false-positive
  likelihood, severity reasoning and remediation for a single finding, with
  its output kept strictly separate from the finding's own scanner evidence
  (`observed_evidence` / `ai_analysis` / `ai_recommendation`) — the AI never
  overwrites or is mistaken for the original evidence.

Both are **read-only** — they never trigger scans, change scope, or execute
anything. When no API key is configured (or the LLM call fails for any
reason) they fall back to a deterministic heuristic, so the feature always
works offline and a provider outage never blocks the rest of the app.

Configuration is resolved per-org from the `ai_settings` table (Settings →
AI & Analysis in the UI) if present and enabled; otherwise from the
`ARGUS_AI_API_KEY`/`ARGUS_AI_MODEL` environment variables, for backward
compatibility with a pre-UI deployment. The API key is never logged, never
included in any API response, and never sent anywhere except directly to
the configured provider's own API.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections import Counter
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("argus.ai")

_MAX_FINDINGS = 60

# Patterns scrubbed from any freeform text before it's sent to an AI
# provider — defense in depth on top of the fact that the fields already
# selected for the outgoing payload (severity/host/path/tags/...) don't
# normally carry secrets. Applied to any longer freeform field (e.g. a
# finding's description/evidence) if a future caller starts including one.
_REDACT_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*\S+"),
    # header-style values: consume to end of line (not just the first
    # whitespace-delimited token), since "Authorization: Bearer <token>" is
    # two tokens and a narrower match would leave the token itself exposed.
    re.compile(r"(?i)authorization:.+"),
    re.compile(r"(?i)cookie:.+"),
    re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{20,}\b"),  # JWT-shaped
]


def redact(text: str) -> str:
    """Best-effort scrub of credential-shaped substrings from freeform text
    before it leaves the process for an AI provider."""
    out = text
    for pat in _REDACT_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


_DEFAULT_OLLAMA_URL = "http://localhost:11434"


@dataclass
class ResolvedAiConfig:
    enabled: bool
    provider: str  # "anthropic" | "ollama"
    model: str
    api_key: str | None  # unused for ollama — local servers aren't keyed
    ollama_base_url: str
    analyze_every_phase: bool
    source: str  # "settings" | "env" | "none"

    @property
    def usable(self) -> bool:
        """True once this config has everything needed to actually make a
        call — Anthropic needs a key, Ollama just needs to be enabled (its
        reachability is only known once test_connection()/a real call runs)."""
        if not self.enabled:
            return False
        return bool(self.api_key) if self.provider == "anthropic" else self.provider == "ollama"


async def resolve_config(session: AsyncSession, org_id: uuid.UUID) -> ResolvedAiConfig:
    from app.core.crypto import decrypt
    from app.models import AiSettings

    row = await session.get(AiSettings, org_id)
    if row is not None and row.enabled:
        if row.provider == "ollama":
            return ResolvedAiConfig(
                True,
                "ollama",
                row.model,
                None,
                row.ollama_base_url,
                row.analyze_every_phase,
                "settings",
            )
        if row.api_key_enc:
            try:
                key = decrypt(row.api_key_enc)
            except ValueError:
                log.warning("ai_settings.api_key_enc for org %s could not be decrypted", org_id)
                key = None
            if key:
                return ResolvedAiConfig(
                    True,
                    row.provider,
                    row.model,
                    key,
                    row.ollama_base_url,
                    row.analyze_every_phase,
                    "settings",
                )

    env_key = os.getenv("ARGUS_AI_API_KEY")
    if env_key:
        return ResolvedAiConfig(
            True,
            "anthropic",
            os.getenv("ARGUS_AI_MODEL", "claude-sonnet-5"),
            env_key,
            os.getenv("ARGUS_OLLAMA_BASE_URL", _DEFAULT_OLLAMA_URL),
            False,
            "env",
        )
    env_ollama = os.getenv("ARGUS_OLLAMA_BASE_URL")
    if env_ollama:
        return ResolvedAiConfig(
            True,
            "ollama",
            os.getenv("ARGUS_OLLAMA_MODEL", "qwen2.5:14b"),
            None,
            env_ollama,
            False,
            "env",
        )

    return ResolvedAiConfig(
        False,
        row.provider if row else "anthropic",
        row.model if row else "claude-sonnet-5",
        None,
        row.ollama_base_url if row else _DEFAULT_OLLAMA_URL,
        row.analyze_every_phase if row else False,
        "none",
    )


async def available(session: AsyncSession, org_id: uuid.UUID) -> bool:
    cfg = await resolve_config(session, org_id)
    return cfg.usable


async def test_connection(cfg: ResolvedAiConfig) -> tuple[bool, str]:
    """A minimal, cheap request that only proves the model/provider are
    valid and reachable — never used for real analysis."""
    if cfg.provider == "ollama":
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"{cfg.ollama_base_url.rstrip('/')}/api/tags")
            r.raise_for_status()
            names = {m.get("name", "") for m in r.json().get("models", [])}
            # Ollama model names are usually "tag:variant" (qwen2.5:14b); a
            # bare tag still counts as a match against "qwen2.5:14b-instruct" etc.
            if cfg.model in names or any(n.split(":")[0] == cfg.model.split(":")[0] for n in names):
                return True, f"connected to Ollama at {cfg.ollama_base_url} — model {cfg.model} is available"
            return (
                False,
                f"Ollama at {cfg.ollama_base_url} is reachable, but model '{cfg.model}' is not pulled (available: {', '.join(sorted(names)) or 'none'})",
            )
        except httpx.HTTPError as exc:
            return False, f"could not reach Ollama at {cfg.ollama_base_url}: {exc}"

    if not cfg.api_key:
        return False, "no API key configured"
    if cfg.provider != "anthropic":
        return False, f"provider '{cfg.provider}' is not supported for live testing in this build"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": cfg.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": cfg.model,
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
                },
            )
        if r.status_code == 401:
            return False, "authentication failed — check the API key"
        if r.status_code == 404:
            return False, f"model '{cfg.model}' not found for this provider/key"
        r.raise_for_status()
        return True, f"connected — model {cfg.model} responded"
    except httpx.HTTPStatusError as exc:
        return False, f"provider returned HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        return False, f"connection failed: {exc}"


# ── project-level executive summary ────────────────────────────────────


def _finding_brief(f) -> dict:
    return {
        "severity": f.severity.value,
        "status": f.status.value,
        "confidence": f.confidence,
        "priority": getattr(f, "_priority", None),
        "name": f.name or f.template_id,
        "template_id": f.template_id,
        "host": f.host,
        "path": f.normalized_path,
        "cve": f.cve,
        "tags": f.tags,
    }


def _heuristic(project, findings) -> dict:
    actionable = [f for f in findings if f.status.value in ("open", "confirmed", "probable", "needs_review")]
    by_sev = Counter(f.severity.value for f in actionable)
    by_host = Counter(f.host for f in actionable if f.host)
    by_tpl = Counter(f.template_id for f in actionable)

    themes = []
    tagc = Counter(t for f in actionable for t in (f.tags or []))
    for tag, n in tagc.most_common(5):
        if tag in ("derived", "edge", "synthetic"):
            continue
        themes.append(f"{n} finding(s) tagged '{tag}'")

    lines = [
        f"{project.name} has {len(actionable)} actionable finding(s): "
        + ", ".join(f"{n} {sev}" for sev, n in by_sev.most_common())
        + ".",
    ]
    crit = [f for f in actionable if f.severity.value in ("critical", "high")]
    if crit:
        lines.append(
            "Highest priority: " + "; ".join(f"{f.name or f.template_id} on {f.host}" for f in crit[:5]) + "."
        )
    if by_host:
        top = by_host.most_common(3)
        lines.append("Most-affected hosts: " + ", ".join(f"{h} ({n})" for h, n in top) + ".")
    if themes:
        lines.append("Themes: " + "; ".join(themes) + ".")

    clusters = [
        {"key": tpl, "count": n, "hosts": sorted({f.host for f in actionable if f.template_id == tpl})}
        for tpl, n in by_tpl.most_common(8)
        if n > 1
    ]
    return {
        "engine": "heuristic",
        "summary": " ".join(lines),
        "clusters": clusters,
        "recommended_order": [
            {"name": f.name or f.template_id, "host": f.host, "severity": f.severity.value}
            for f in sorted(
                actionable,
                key=lambda f: (
                    {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity.value],
                    f.confidence,
                ),
                reverse=True,
            )[:10]
        ],
    }


async def _call_llm(cfg: ResolvedAiConfig, prompt: str, *, max_tokens: int = 2000) -> str:
    if cfg.provider == "ollama":
        return await _call_ollama(cfg, prompt, max_tokens=max_tokens)
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": cfg.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": cfg.model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"].strip()


async def _call_ollama(cfg: ResolvedAiConfig, prompt: str, *, max_tokens: int = 2000) -> str:
    # A local model, so a generous timeout — CPU-bound inference on a
    # midsize (e.g. 14B-parameter) model on modest hardware can genuinely
    # take several minutes, much longer than a hosted API round-trip.
    async with httpx.AsyncClient(timeout=300) as c:
        r = await c.post(
            f"{cfg.ollama_base_url.rstrip('/')}/api/chat",
            json={
                "model": cfg.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
        )
        r.raise_for_status()
        return r.json()["message"]["content"].strip()


def _parse_json_response(text: str) -> dict | None:
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        text = text[4:].strip() if text.lower().startswith("json") else text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


async def _llm_summary(cfg: ResolvedAiConfig, project, findings) -> dict:
    briefs = [_finding_brief(f) for f in findings[:_MAX_FINDINGS]]
    prompt = (
        "You are a senior application security analyst. Given this JSON list of scanner findings "
        "for the project below, produce a concise JSON object with keys: "
        "`summary` (3-5 sentence executive summary), "
        "`clusters` (array of {theme, finding_names[], rationale}), "
        "`recommended_order` (array of {name, host, why} — the order to fix things), "
        "`remediation` (array of {theme, guidance}). "
        "Do not invent findings. Be specific and technical. Return ONLY the JSON.\n\n"
        f"Project: {project.name} (risk profile: {project.risk_profile.value})\n"
        f"Findings: {json.dumps(briefs)}"
    )
    text = await _call_llm(cfg, prompt)
    out = _parse_json_response(text)
    if out is None:
        return {"engine": "llm", "summary": text, "clusters": [], "recommended_order": []}
    out["engine"] = "llm"
    return out


async def analyse(session: AsyncSession, org_id: uuid.UUID, project, findings) -> dict:
    cfg = await resolve_config(session, org_id)
    if cfg.usable:
        try:
            return await _llm_summary(cfg, project, findings)
        except Exception as exc:  # noqa: BLE001
            log.warning("AI analysis LLM path failed, using heuristic: %s", exc)
    return _heuristic(project, findings)


# ── per-finding analysis (observed evidence / AI analysis / AI recommendation) ──


def _observed_evidence(f) -> dict:
    """The finding's own scanner-collected evidence, verbatim — this is
    never generated or modified by AI, only ever read by it."""
    return {
        "title": f.name or f.template_id,
        "severity": f.severity.value,
        "status": f.status.value,
        "confidence": f.confidence,
        "verification": f.verification,
        "engine": f.engine,
        "host": f.host,
        "path": f.normalized_path,
        "cwe": f.cwe,
        "cve": f.cve,
        "tags": f.tags,
        "description": f.description,
        "evidence_excerpt": (f.response_excerpt or "")[:2000],
        "request": redact(f.request or ""),
    }


def _heuristic_finding_analysis(f) -> dict:
    tags = set(f.tags or [])
    # The `verification` field ("payload_confirmed") is the same constant for
    # both the injection engine's Likely and Verified tiers — it does NOT by
    # itself distinguish a reproduced, high-confidence hit from a
    # single-sample one. The tier tag ("likely"/"verified") on the finding
    # does carry that distinction, so prefer it when present rather than
    # over-trusting "payload_confirmed" alone (see TEST_SCAN_REPORT.md's
    # note on this same finding-pipeline calibration gap).
    if f.status.value == "false_positive" or (f.confidence or 0) < 40:
        fp = "high"
    elif "verified" in tags:
        fp = "low"
    elif "likely" in tags:
        fp = "medium"
    elif f.verification == "payload_confirmed":
        fp = "low"
    else:
        fp = "medium"
    return {
        "engine": "heuristic",
        "classification": f.template_id or "unclassified",
        "false_positive_likelihood": fp,
        "severity_reasoning": (
            f"Scanner-assigned severity {f.severity.value} at {f.confidence}% confidence "
            f"(verification: {f.verification or 'unverified'}"
            + (", tier: likely — not independently reproduced" if "likely" in tags else "")
            + ")."
        ),
        "remediation": f.remediation or "No remediation guidance recorded for this finding template.",
    }


async def _llm_finding_analysis(cfg: ResolvedAiConfig, evidence: dict) -> dict:
    prompt = (
        "You are a senior application security analyst reviewing ONE scanner finding. "
        "Given the observed evidence below (JSON), return ONLY a JSON object with keys: "
        "`classification` (short category name), "
        '`false_positive_likelihood` ("low"|"medium"|"high" plus one sentence why), '
        "`severity_reasoning` (2-3 sentences justifying or questioning the scanner's assigned severity), "
        "`remediation` (concrete, actionable fix guidance). "
        "Base your analysis ONLY on the evidence given — never invent request/response details "
        "that are not present. If evidence is thin, say so explicitly rather than guessing.\n\n"
        f"Evidence: {json.dumps(evidence)}"
    )
    text = await _call_llm(cfg, prompt, max_tokens=800)
    out = _parse_json_response(text)
    if out is None:
        return {
            "engine": "llm",
            "classification": "",
            "false_positive_likelihood": "",
            "severity_reasoning": text,
            "remediation": "",
        }
    out["engine"] = "llm"
    return out


async def analyse_finding(session: AsyncSession, org_id: uuid.UUID, finding) -> dict:
    """Returns {observed_evidence, ai_analysis, ai_recommendation} — the
    three are kept in separate top-level keys everywhere this is rendered
    (API response, UI) specifically so AI output can never be confused with
    or overwrite the finding's own raw scanner evidence."""
    evidence = _observed_evidence(finding)
    cfg = await resolve_config(session, org_id)
    if cfg.usable:
        try:
            analysis = await _llm_finding_analysis(cfg, evidence)
        except Exception as exc:  # noqa: BLE001
            log.warning("AI finding analysis LLM path failed, using heuristic: %s", exc)
            analysis = _heuristic_finding_analysis(finding)
    else:
        analysis = _heuristic_finding_analysis(finding)
    return {
        "observed_evidence": evidence,
        "ai_analysis": {
            "engine": analysis["engine"],
            "classification": analysis.get("classification", ""),
            "false_positive_likelihood": analysis.get("false_positive_likelihood", ""),
            "severity_reasoning": analysis.get("severity_reasoning", ""),
        },
        "ai_recommendation": {
            "remediation": analysis.get("remediation", ""),
        },
    }


# ── per-phase bug-hunting strategy (opt-in, AiSettings.analyze_every_phase) ──

# Kept short and cheap on purpose: this runs once per phase per scan, as a
# background task off the event-ingestion path (see app/services/events.py),
# never blocking scanning. A local model (Ollama) in particular can take
# tens of seconds per call, so the prompt and output are both intentionally
# small — a quick strategic nudge, not a full report.
_MAX_PHASE_SAMPLES = 12


def _phase_prompt(project_name: str, phase: str, summary: dict) -> str:
    samples = summary.get("samples", [])[:_MAX_PHASE_SAMPLES]
    return (
        "You are an experienced bug-bounty hunter acting as a scan co-pilot, mid-assessment. "
        f"The '{phase}' phase of a recon scan against '{project_name}' just finished. "
        "Given this short summary of what it found, write 2-4 sentences of concrete, specific "
        "strategy for what to prioritize investigating next and why — reference the actual hosts/"
        "paths/technologies given, not generic advice. If nothing here looks worth prioritizing, "
        "say so briefly instead of padding the answer.\n\n"
        f"Phase: {phase}\n"
        f"Counts: {json.dumps(summary.get('counts', {}))}\n"
        f"Notable items: {json.dumps(samples)}"
    )


async def analyse_phase(
    session: AsyncSession, org_id: uuid.UUID, project_name: str, phase: str, summary: dict
) -> str | None:
    """Returns a short strategy note for this phase's results, or None if
    AI/per-phase analysis isn't enabled, the summary is empty, or the call
    fails for any reason — this is a bonus insight, never a scan blocker,
    so any failure here is swallowed (logged) rather than raised."""
    cfg = await resolve_config(session, org_id)
    if not cfg.usable or not cfg.analyze_every_phase:
        return None
    if not summary.get("counts") and not summary.get("samples"):
        return None
    try:
        text = await _call_llm(cfg, _phase_prompt(project_name, phase, summary), max_tokens=300)
        return text.strip() or None
    except Exception as exc:  # noqa: BLE001
        log.warning("per-phase AI analysis failed for phase %s: %s", phase, exc)
        return None
