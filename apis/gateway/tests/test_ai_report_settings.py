"""Settings → AI & Analysis / Reports: storage, masking, validation, and
the AI service's config-resolution precedence and redaction."""

from __future__ import annotations

import uuid

from app.models import AiSettings, FindingSeverity, FindingStatus, Organization, Project, RiskProfile
from app.services.ai import analyse_finding, redact, resolve_config


async def _project(session, risk=RiskProfile.moderate):
    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    p = Project(org_id=org.id, name="Acme", program_name="Acme BB", risk_profile=risk)
    session.add(p)
    await session.flush()
    return org, p


# ── AI settings API ────────────────────────────────────────────────────


async def test_ai_settings_default_not_configured(admin_client):
    r = await admin_client.get("/api/settings/ai")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["api_key_masked"] == ""
    assert body["status"] == "not_configured"


async def test_ai_settings_key_never_returned_only_masked(admin_client):
    r = await admin_client.put(
        "/api/settings/ai",
        json={"enabled": True, "provider": "anthropic", "model": "claude-sonnet-5", "api_key": "sk-ant-verysecretkey12345"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "sk-ant-verysecretkey12345" not in r.text
    assert body["api_key_masked"].startswith("sk-a")
    assert "*" in body["api_key_masked"]
    assert body["enabled"] is True
    # test-connection result was invalidated by the new key
    assert body["status"] == "not_configured"

    r2 = await admin_client.get("/api/settings/ai")
    assert "sk-ant-verysecretkey12345" not in r2.text
    assert r2.json()["api_key_masked"] == body["api_key_masked"]


async def test_ai_settings_clear_key(admin_client):
    await admin_client.put("/api/settings/ai", json={"api_key": "sk-something"})
    r = await admin_client.put("/api/settings/ai", json={"api_key": ""})
    assert r.json()["api_key_masked"] == ""


async def test_ai_test_connection_without_key_fails_cleanly(admin_client):
    r = await admin_client.post("/api/settings/ai/test")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "no api key" in body["detail"].lower()


# ── Report settings API ───────────────────────────────────────────────


async def test_report_settings_roundtrip(admin_client):
    r = await admin_client.put(
        "/api/settings/reports",
        json={
            "company_name": "Acme Security",
            "report_title": "Penetration Test Report",
            "author": "Jane Analyst",
            "contact_email": "security@acme.test",
            "confidentiality_label": "Strictly Confidential",
            "accent_color": "#ff0000",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["company_name"] == "Acme Security"
    assert body["accent_color"] == "#ff0000"
    assert body["has_logo"] is False

    r2 = await admin_client.get("/api/settings/reports")
    assert r2.json()["report_title"] == "Penetration Test Report"


async def test_report_settings_rejects_bad_accent_color(admin_client):
    r = await admin_client.put("/api/settings/reports", json={"accent_color": "not-a-color"})
    assert r.status_code == 422


async def test_report_settings_rejects_svg_logo(admin_client):
    # SVG can embed <script> — explicitly rejected regardless of size.
    svg = "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="
    r = await admin_client.put("/api/settings/reports", json={"logo_data_uri": svg})
    assert r.status_code == 400
    assert "svg" in r.text.lower()


async def test_report_settings_rejects_oversized_logo(admin_client):
    # between the router's business limit (300KB) and the schema's hard
    # field cap (350KB) so this actually exercises the router's own size
    # check (and its friendlier error message) rather than Pydantic's.
    huge = "data:image/png;base64," + ("A" * 320_000)
    r = await admin_client.put("/api/settings/reports", json={"logo_data_uri": huge})
    assert r.status_code == 400
    assert "too large" in r.text.lower()


async def test_report_settings_rejects_absurdly_oversized_logo(admin_client):
    absurd = "data:image/png;base64," + ("A" * 500_000)
    r = await admin_client.put("/api/settings/reports", json={"logo_data_uri": absurd})
    assert r.status_code == 422


async def test_report_settings_accepts_valid_png_logo(admin_client):
    small = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    r = await admin_client.put("/api/settings/reports", json={"logo_data_uri": small})
    assert r.status_code == 200
    assert r.json()["has_logo"] is True


# ── AI config resolution + redaction (service layer) ──────────────────


async def test_resolve_config_prefers_db_settings_over_env(db_session, monkeypatch):
    monkeypatch.setenv("ARGUS_AI_API_KEY", "env-key")
    org, _ = await _project(db_session)
    from app.core.crypto import encrypt

    db_session.add(AiSettings(org_id=org.id, enabled=True, provider="anthropic", model="claude-sonnet-5", api_key_enc=encrypt("db-key")))
    await db_session.commit()

    cfg = await resolve_config(db_session, org.id)
    assert cfg.source == "settings"
    assert cfg.api_key == "db-key"


async def test_resolve_config_falls_back_to_env_when_db_disabled(db_session, monkeypatch):
    monkeypatch.setenv("ARGUS_AI_API_KEY", "env-key")
    monkeypatch.setenv("ARGUS_AI_MODEL", "claude-sonnet-5")
    org, _ = await _project(db_session)
    # no AiSettings row at all for this org
    cfg = await resolve_config(db_session, org.id)
    assert cfg.source == "env"
    assert cfg.api_key == "env-key"


async def test_resolve_config_none_when_nothing_configured(db_session, monkeypatch):
    monkeypatch.delenv("ARGUS_AI_API_KEY", raising=False)
    org, _ = await _project(db_session)
    cfg = await resolve_config(db_session, org.id)
    assert cfg.source == "none"
    assert cfg.enabled is False
    assert cfg.api_key is None


def test_redact_scrubs_credential_shaped_text():
    text = "curl -H 'Authorization: Bearer sk-ant-abc123' -H 'Cookie: session=deadbeef' http://x"
    out = redact(text)
    assert "sk-ant-abc123" not in out
    assert "deadbeef" not in out
    assert "[REDACTED]" in out


def test_redact_leaves_ordinary_text_alone():
    text = "GET /bank/showAccount?listAccounts=800000 returned 200 OK"
    assert redact(text) == text


# ── per-finding analysis: evidence / analysis / recommendation separation ──


class _Finding:
    def __init__(self, **kw):
        self.__dict__.update(
            {
                "name": "SQL Injection",
                "template_id": "injection-sqli",
                "severity": FindingSeverity.high,
                "status": FindingStatus.confirmed,
                "confidence": 80,
                "verification": "payload_confirmed",
                "engine": "injection-engine",
                "host": "example.com",
                "normalized_path": "/search",
                "cwe": ["CWE-89"],
                "cve": [],
                "tags": ["injection", "sqli", "verified"],
                "description": "SQL injection in the query parameter.",
                "response_excerpt": "HTTP/1.1 500 Internal Server Error",
                "request": "GET /search?q=' OR 1=1--\nAuthorization: Bearer secret-token-xyz",
                "remediation": "Use parameterized queries.",
            }
        )
        self.__dict__.update(kw)


async def test_analyse_finding_heuristic_separates_evidence_from_analysis(db_session):
    org, _ = await _project(db_session)
    f = _Finding()
    out = await analyse_finding(db_session, org.id, f)
    assert set(out.keys()) == {"observed_evidence", "ai_analysis", "ai_recommendation"}
    # the finding's own evidence is verbatim and untouched by "AI"
    assert out["observed_evidence"]["title"] == "SQL Injection"
    assert out["observed_evidence"]["host"] == "example.com"
    # the auth header embedded in the raw request must never reach here unredacted
    assert "secret-token-xyz" not in out["observed_evidence"]["request"]
    assert out["ai_analysis"]["engine"] == "heuristic"
    assert out["ai_recommendation"]["remediation"] == "Use parameterized queries."


async def test_analyse_finding_low_confidence_flagged_as_likely_fp(db_session):
    org, _ = await _project(db_session)
    f = _Finding(confidence=20, verification="unverified", tags=[])
    out = await analyse_finding(db_session, org.id, f)
    assert out["ai_analysis"]["false_positive_likelihood"] == "high"


async def test_analyse_finding_likely_tier_not_overtrusted_as_low_fp(db_session):
    """A finding whose injection-engine tier is "likely" (not "verified")
    carries the same `verification="payload_confirmed"` constant as a truly
    reproduced one — the heuristic must use the tier tag, not just that
    constant, or it over-trusts an unreproduced single-sample hit."""
    org, _ = await _project(db_session)
    f = _Finding(confidence=88, verification="payload_confirmed", tags=["injection", "sqli", "likely"])
    out = await analyse_finding(db_session, org.id, f)
    assert out["ai_analysis"]["false_positive_likelihood"] == "medium"
    assert "not independently reproduced" in out["ai_analysis"]["severity_reasoning"]


async def test_analyse_finding_verified_tier_is_low_fp(db_session):
    org, _ = await _project(db_session)
    f = _Finding(confidence=90, verification="payload_confirmed", tags=["injection", "sqli", "verified"])
    out = await analyse_finding(db_session, org.id, f)
    assert out["ai_analysis"]["false_positive_likelihood"] == "low"
