"""Ports + the vulnerability finding / verification engine (M5 — Phases 11-13).

`upsert_finding` is also the **false-positive reduction & verification engine**:
every incoming Nuclei match is deduplicated on a structural fingerprint, scored
for confidence from the signals the scanner reports (out-of-band confirmation,
named matchers, extracted values, CVE metadata, template reputation), and
auto-classified confirmed / probable / needs_review. A human triage decision
(confirmed / false_positive / fixed / accepted_risk) is never overwritten by a
later automated pass.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, Finding, FindingSeverity, FindingStatus, Port, PortState


def _now() -> datetime:
    return datetime.now(UTC)


# ── ports ─────────────────────────────────────────────────────────────────


async def upsert_port(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    ip = str(data.get("ip", "")).strip()
    try:
        port = int(data.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    if not ip or port <= 0:
        return
    protocol = str(data.get("protocol", "tcp"))[:8] or "tcp"

    row = await session.scalar(
        select(Port).where(
            Port.project_id == project_id,
            Port.ip == ip,
            Port.port == port,
            Port.protocol == protocol,
        )
    )
    if row is None:
        row = Port(
            org_id=org_id,
            project_id=project_id,
            ip=ip,
            port=port,
            protocol=protocol,
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
    row.last_seen = _now()
    try:
        row.state = PortState(data.get("state", "open"))
    except ValueError:
        row.state = PortState.open
    # only-update-if-provided so a bare re-emit doesn't wipe service detail
    for col, key in (
        ("service", "service"),
        ("product", "product"),
        ("version", "version"),
        ("banner", "banner"),
        ("http_title", "http_title"),
        ("source", "source"),
    ):
        v = data.get(key)
        if v:
            setattr(row, col, str(v)[:500])
    if data.get("tls") is not None:
        row.tls = bool(data["tls"])
    if data.get("http_status"):
        row.http_status = int(data["http_status"])
    hostnames = [h for h in (data.get("hostnames") or []) if isinstance(h, str)]
    if hostnames:
        row.hostnames = sorted({*(row.hostnames or []), *hostnames})
    row.in_scope = bool(data.get("in_scope", True))

    # link to the IP asset if we have one
    if row.asset_id is None:
        asset = await session.scalar(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.type == "ip",
                Asset.value == ip,
            )
        )
        if asset is not None:
            row.asset_id = asset.id

    await session.flush()
    await derive_from_port(session, row)


# ── findings + verification engine ────────────────────────────────────────

_SEV_BASE = {
    FindingSeverity.info: 25,
    FindingSeverity.low: 40,
    FindingSeverity.medium: 55,
    FindingSeverity.high: 65,
    FindingSeverity.critical: 72,
}

# Templates that fire on almost every host — real, but rarely a "finding" a
# triager wants surfaced as actionable. Confidence is pinned low and they never
# auto-promote past `probable`.
_LOW_SIGNAL_TEMPLATES = {
    "http-missing-security-headers",
    "missing-sri",
    "tech-detect",
    "wappalyzer-recognition",
    "waf-detect",
    "options-method",
    "http-trace",
    "ssl-issuer",
    "ssl-dns-names",
    "self-signed-ssl",
    "tls-version",
    "deprecated-tls",
    "weak-cipher-suites",
    "x-powered-by-header",
    "cookies-without-httponly",
    "cookies-without-secure",
    "robots-txt-endpoint",
    "caa-fingerprint",
    "dmarc-detect",
    "spf-record-detect",
    "txt-fingerprint",
    "nameserver-fingerprint",
    "mx-fingerprint",
}

_LOW_SIGNAL_TAGS = {"tech", "favicon", "waf", "ssl", "dns", "network-detect"}


def verify_finding(data: dict[str, Any], severity: FindingSeverity) -> tuple[int, FindingStatus, str, str]:
    """Score an incoming match and propose (confidence, status, verification, note)."""
    template_id = str(data.get("template_id", ""))
    tags = {str(t).lower() for t in (data.get("tags") or [])}
    oob = bool(data.get("oob_confirmed"))
    matcher = str(data.get("matcher_name", ""))
    extracted = [x for x in (data.get("extracted") or []) if x]
    cve = [x for x in (data.get("cve") or []) if x]
    level = str(data.get("level", "passive"))
    engine = str(data.get("engine", ""))

    score = _SEV_BASE.get(severity, 40)
    notes: list[str] = []
    verification = "unverified"

    if oob:
        score += 30
        verification = "oob_confirmed"
        notes.append("out-of-band interaction confirmed")
    if matcher:
        score += 8
    if extracted:
        score += 10
        notes.append(f"extracted {len(extracted)} value(s)")
    if cve:
        score += 10
    # a DAST match is a real payload that triggered a real response signature
    if engine == "nuclei-dast" or "injection" in tags:
        score += 15
        if verification == "unverified":
            verification = "payload_confirmed"
        notes.append("active payload confirmed")

    low_signal = template_id in _LOW_SIGNAL_TEMPLATES or (
        severity == FindingSeverity.info and tags & _LOW_SIGNAL_TAGS
    )
    if low_signal:
        score = min(score, 35)
        notes.append("low-signal template — informational")

    score = max(5, min(99, score))

    if verification in ("oob_confirmed", "payload_confirmed") or score >= 85:
        status = FindingStatus.confirmed
    elif score >= 60 and not low_signal:
        status = FindingStatus.probable
    else:
        status = FindingStatus.needs_review

    # manual-review level never auto-promotes past needs_review
    if level == "manual_review" and status in (FindingStatus.confirmed, FindingStatus.probable):
        status = FindingStatus.needs_review
        notes.append("manual_review scan level — held for analyst")

    return score, status, verification, "; ".join(notes)


# statuses a human set — automation must not clobber them
_HUMAN_STATUSES = {
    FindingStatus.confirmed,
    FindingStatus.false_positive,
    FindingStatus.fixed,
    FindingStatus.accepted_risk,
}


async def upsert_finding(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    fp = str(data.get("fingerprint", "")).strip()
    if not fp:
        return
    try:
        severity = FindingSeverity(str(data.get("severity", "info")).lower())
    except ValueError:
        severity = FindingSeverity.info

    row = await session.scalar(
        select(Finding).where(Finding.project_id == project_id, Finding.fingerprint == fp)
    )
    is_new = row is None
    if is_new:
        row = Finding(
            org_id=org_id,
            project_id=project_id,
            fingerprint=fp,
            template_id=str(data.get("template_id", ""))[:200],
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)

    row.last_seen = _now()
    row.severity = severity
    row.name = str(data.get("name", ""))[:300] or row.name
    row.engine = str(data.get("engine", "nuclei"))[:40]
    row.template_version = str(data.get("template_version", ""))[:40] or row.template_version
    row.scan_level = str(data.get("level", row.scan_level or "passive"))[:20]
    row.tags = [str(t)[:40] for t in (data.get("tags") or [])][:30]
    row.host = str(data.get("host", ""))[:255] or row.host
    row.matched_at = str(data.get("matched_at", ""))[:1000] or row.matched_at
    row.normalized_path = str(data.get("normalized_path", ""))[:500] or row.normalized_path
    row.matcher_name = str(data.get("matcher_name", ""))[:120]
    row.extracted = [str(x)[:300] for x in (data.get("extracted") or [])][:50]
    row.reference = [str(x)[:500] for x in (data.get("reference") or [])][:20]
    row.cve = [str(x).upper()[:30] for x in (data.get("cve") or [])][:10]
    row.cwe = [str(x)[:30] for x in (data.get("cwe") or [])][:10]
    if data.get("cvss_score"):
        try:
            row.cvss_score = float(data["cvss_score"])
        except (TypeError, ValueError):
            pass
    row.description = str(data.get("description", ""))[:4000] or row.description
    row.remediation = str(data.get("remediation", ""))[:4000] or row.remediation
    for col, key, cap in (
        ("request", "request", 8000),
        ("response_excerpt", "response_excerpt", 8000),
        ("curl_command", "curl_command", 4000),
    ):
        v = data.get(key)
        if v:
            setattr(row, col, str(v)[:cap])
    row.in_scope = bool(data.get("in_scope", True))

    # Injection Testing Engine (§1-13) enrichment — empty/zero for the normal
    # Nuclei-sourced findings that don't set these.
    row.parameter = str(data.get("parameter", ""))[:200]
    row.param_location = str(data.get("param_location", ""))[:20]
    row.injection_class = str(data.get("injection_class", ""))[:30]
    row.detection_method = str(data.get("detection_method", ""))[:30] or row.matcher_name[:30]
    if data.get("verification_tier"):
        row.verification_tier = str(data["verification_tier"])[:20]
    if data.get("evidence_quality") is not None:
        try:
            row.evidence_quality = int(data["evidence_quality"])
        except (TypeError, ValueError):
            pass
    if row.injection_point_id is None and row.injection_class and row.parameter:
        from app.models import InjectionPoint

        base_url = row.matched_at.split("?", 1)[0] if row.matched_at else ""
        ip_row = await session.scalar(
            select(InjectionPoint).where(
                InjectionPoint.project_id == project_id,
                InjectionPoint.url == base_url,
                InjectionPoint.param_name == row.parameter,
            )
        )
        if ip_row is not None:
            row.injection_point_id = ip_row.id

    score, auto_status, verification, note = verify_finding(data, severity)
    row.confidence = score
    row.verification = verification
    row.verification_note = note[:400]
    # never overwrite a human triage decision
    if is_new or row.status not in _HUMAN_STATUSES:
        row.status = auto_status

    if row.asset_id is None and row.host:
        asset = await session.scalar(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.type.in_(("domain", "subdomain")),
                Asset.value == row.host,
            )
        )
        if asset is not None:
            row.asset_id = asset.id


# ── unified finding engine (M6) ───────────────────────────────────────────
#
# Secrets, sensitive paths and dangerously-exposed services are also security
# findings — promoting them into the `findings` table means one prioritised
# queue, one report, and the exposure-delta covers everything.

# services that should never be reachable from the public internet, with the
# severity we assign when they are.
_DANGEROUS_SERVICES = {
    "redis": ("critical", "Redis is exposed without authentication in its default configuration."),
    "mongodb": ("critical", "MongoDB is exposed — older/default configs allow unauthenticated access."),
    "elasticsearch": ("high", "Elasticsearch HTTP API exposed — often unauthenticated."),
    "memcached": ("high", "Memcached exposed — unauthenticated, and usable for reflection DDoS."),
    "docker": ("critical", "Docker Engine API exposed — equivalent to root on the host."),
    "docker-tls": ("high", "Docker Engine API (TLS) exposed."),
    "kibana": ("medium", "Kibana exposed."),
    "rabbitmq-mgmt": ("high", "RabbitMQ management UI exposed."),
    "couchdb": ("high", "CouchDB exposed."),
    "mysql": ("medium", "MySQL reachable from the internet."),
    "postgres": ("medium", "PostgreSQL reachable from the internet."),
    "mssql": ("medium", "MS SQL Server reachable from the internet."),
    "rdp": ("medium", "RDP exposed — a common brute-force / CVE target."),
    "vnc": ("high", "VNC exposed."),
    "winrm": ("medium", "WinRM exposed."),
    "smb": ("high", "SMB exposed to the internet."),
    "ldap": ("medium", "LDAP exposed."),
    "ftp": ("low", "FTP exposed — often anonymous / cleartext."),
    "telnet": ("high", "Telnet exposed — cleartext credentials."),
}


async def _derive_finding(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    template_id: str,
    name: str,
    severity: str,
    host: str,
    matched_at: str,
    engine: str,
    description: str = "",
    remediation: str = "",
    extracted: list[str] | None = None,
    normalized_path: str = "/",
    tags: list[str] | None = None,
) -> None:
    import hashlib

    fp = hashlib.sha256(f"{template_id}|{host}|{normalized_path}|derived".encode()).hexdigest()
    await upsert_finding(
        session,
        org_id=org_id,
        project_id=project_id,
        scan_id=scan_id,
        data={
            "fingerprint": fp,
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "engine": engine,
            "host": host,
            "matched_at": matched_at,
            "normalized_path": normalized_path,
            "description": description,
            "remediation": remediation,
            "extracted": extracted or [],
            "tags": (tags or []) + ["derived"],
            "level": "passive",
        },
    )


async def derive_from_secret(session: AsyncSession, secret) -> None:
    """A live secret candidate is a finding."""
    from app.models import SecretStatus

    if secret.status == SecretStatus.false_positive:
        return
    host = secret.source or secret.location or "unknown"
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]
    await _derive_finding(
        session,
        org_id=secret.org_id,
        project_id=secret.project_id,
        scan_id=secret.first_seen_scan,
        template_id=f"exposed-secret-{secret.detector_type.lower()}",
        name=f"Exposed secret — {secret.detector_type}",
        severity=secret.severity.value,
        host=host[:255],
        matched_at=secret.location[:1000],
        engine="secret-scan",
        description=f"A {secret.detector_type} credential was found in {secret.source_kind} "
        f"({secret.detector} detector).",
        remediation="Revoke and rotate the credential; remove it from the source and add a "
        "pre-commit secret scan.",
        tags=["secret", secret.source_kind],
    )


async def derive_from_endpoint(session: AsyncSession, ep) -> None:
    """A high/critical sensitive path is a finding."""
    if ep.sensitivity.value not in ("high", "critical"):
        return
    await _derive_finding(
        session,
        org_id=ep.org_id,
        project_id=ep.project_id,
        scan_id=ep.first_seen_scan,
        template_id=f"sensitive-path-{ep.sensitivity.value}",
        name=f"Sensitive path exposed — {ep.path}",
        severity=ep.sensitivity.value,
        host=ep.host,
        matched_at=ep.sample_url or (ep.host + ep.path),
        normalized_path=ep.path[:500] or "/",
        engine="content-discovery",
        description=ep.sensitivity_reason or "A sensitive path is reachable.",
        remediation="Remove or authenticate the resource; block the path at the edge.",
        tags=["sensitive-path"],
    )


async def derive_from_port(session: AsyncSession, port) -> None:
    """A dangerously-exposed service is a finding."""
    spec = _DANGEROUS_SERVICES.get((port.service or "").lower())
    if not spec:
        return
    sev, desc = spec
    host = (port.hostnames[0] if port.hostnames else port.ip)
    await _derive_finding(
        session,
        org_id=port.org_id,
        project_id=port.project_id,
        scan_id=port.first_seen_scan,
        template_id=f"exposed-service-{port.service}",
        name=f"{port.service} exposed on {port.ip}:{port.port}",
        severity=sev,
        host=str(host)[:255],
        matched_at=f"{port.ip}:{port.port}",
        normalized_path=f"/:{port.port}",
        engine="port-scan",
        description=desc + (f" (product: {port.product} {port.version})" if port.product else ""),
        remediation="Firewall the port so it is only reachable from trusted networks; require auth.",
        extracted=[f"{port.service} {port.product} {port.version}".strip()],
        tags=["exposed-service"],
    )
