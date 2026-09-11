"""Optional AI-assisted analysis (M7).

Given the project's current findings this produces an executive summary, groups
likely-related findings, and drafts remediation guidance. It is **read-only** —
it never triggers scans, changes scope, or executes anything. When no API key is
configured it falls back to a deterministic heuristic summary so the feature
always works offline.

Enable the LLM path with `ARGUS_AI_API_KEY` (an Anthropic API key) and,
optionally, `ARGUS_AI_MODEL` (default: claude-sonnet-5).
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter

import httpx

log = logging.getLogger("argus.ai")

_MODEL = os.getenv("ARGUS_AI_MODEL", "claude-sonnet-5")
_MAX_FINDINGS = 60


def available() -> bool:
    return bool(os.getenv("ARGUS_AI_API_KEY"))


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
            "Highest priority: "
            + "; ".join(f"{f.name or f.template_id} on {f.host}" for f in crit[:5])
            + "."
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
                key=lambda f: ({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity.value], f.confidence),
                reverse=True,
            )[:10]
        ],
    }


async def _llm(project, findings) -> dict:
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
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": os.environ["ARGUS_AI_API_KEY"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _MODEL,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        r.raise_for_status()
        text = r.json()["content"][0]["text"].strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1].lstrip("json").strip()
    try:
        out = json.loads(text)
    except json.JSONDecodeError:
        return {"engine": "llm", "summary": text, "clusters": [], "recommended_order": []}
    out["engine"] = "llm"
    return out


async def analyse(project, findings) -> dict:
    if available():
        try:
            return await _llm(project, findings)
        except Exception as exc:  # noqa: BLE001
            log.warning("AI analysis LLM path failed, using heuristic: %s", exc)
    return _heuristic(project, findings)
