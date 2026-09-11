"""Finding priority / risk scoring (M6 — the intelligent severity engine).

`priority_score` blends the raw severity with the verification engine's
confidence, the finding's triage status, and the project's declared risk
profile into a single 0-100 number the UI ranks by. It deliberately keeps
CVSS as *input context* rather than the output — a low-confidence critical is
not automatically the top of the queue.
"""

from __future__ import annotations

from app.models import Finding, FindingSeverity, FindingStatus, RiskProfile

_SEV_WEIGHT = {
    FindingSeverity.info: 5,
    FindingSeverity.low: 20,
    FindingSeverity.medium: 45,
    FindingSeverity.high: 72,
    FindingSeverity.critical: 92,
}

_RISK_MULT = {
    RiskProfile.low: 0.85,
    RiskProfile.moderate: 1.0,
    RiskProfile.high: 1.15,
    RiskProfile.critical: 1.3,
}

_STATUS_MULT = {
    FindingStatus.confirmed: 1.15,
    FindingStatus.probable: 1.0,
    FindingStatus.needs_review: 0.9,
    FindingStatus.open: 0.9,
    FindingStatus.accepted_risk: 0.4,
    FindingStatus.fixed: 0.0,
    FindingStatus.false_positive: 0.0,
}


def finding_priority(f: Finding, risk_profile: RiskProfile) -> int:
    base = _SEV_WEIGHT.get(f.severity, 20)
    conf = max(0.15, min(1.0, (f.confidence or 50) / 100))
    score = base * conf
    score *= _STATUS_MULT.get(f.status, 1.0)
    score *= _RISK_MULT.get(risk_profile, 1.0)
    # a real CVSS >= 9 nudges it up a little even at lower confidence
    if (f.cvss_score or 0) >= 9.0:
        score = max(score, base * 0.75)
    return max(0, min(100, round(score)))


def priority_band(score: int) -> str:
    if score >= 75:
        return "urgent"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"
