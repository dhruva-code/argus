"""Asset inventory, summary, and relationship graph (M2)."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.crypto import decrypt
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_permission
from app.models import (
    Asset,
    AssetEdge,
    AssetStatus,
    AssetType,
    Endpoint,
    Finding,
    FindingSeverity,
    FindingStatus,
    Port,
    Project,
    Repository,
    Secret,
    SecretStatus,
    Sensitivity,
    VHost,
    VHostClass,
)
from app.schemas import (
    AssetGraph,
    AssetGraphEdge,
    AssetGraphNode,
    AssetOut,
    AssetSummary,
    EndpointOut,
    EndpointSummary,
    FindingOut,
    FindingPatch,
    FindingSummary,
    PortOut,
    PortSummary,
    RepositoryOut,
    SecretOut,
    SecretPatch,
    SecretSummary,
    VHostOut,
)
from app.services.priority import finding_priority, priority_band

router = APIRouter(prefix="/api/projects/{project_id}", tags=["assets"])


async def _project(session: AsyncSession, principal: Principal, pid: uuid.UUID) -> Project:
    p = await session.get(Project, pid)
    if p is None or p.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return p


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    project_id: uuid.UUID,
    q: str | None = None,
    type: AssetType | None = None,
    asset_status: AssetStatus | None = Query(default=None, alias="status"),
    in_scope: bool | None = None,
    technology: str | None = None,
    sort: str = "last_seen",
    order: str = "desc",
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[AssetOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)

    stmt = select(Asset).where(Asset.project_id == project_id).options(selectinload(Asset.sources))
    if q:
        stmt = stmt.where(or_(Asset.value.ilike(f"%{q}%"), Asset.http_title.ilike(f"%{q}%")))
    if type:
        stmt = stmt.where(Asset.type == type)
    if asset_status:
        stmt = stmt.where(Asset.status == asset_status)
    if in_scope is not None:
        stmt = stmt.where(Asset.in_scope.is_(in_scope))
    if technology:
        stmt = stmt.where(Asset.technologies.contains([technology]))

    col = {
        "last_seen": Asset.last_seen,
        "first_seen": Asset.first_seen,
        "value": Asset.value,
        "confidence": Asset.confidence,
        "status": Asset.status,
    }.get(sort, Asset.last_seen)
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc())

    rows = (await session.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return [AssetOut.model_validate(r) for r in rows]


@router.get("/assets/summary", response_model=AssetSummary)
async def asset_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> AssetSummary:
    principal.require("project.read")
    await _project(session, principal, project_id)

    rows = (await session.execute(select(Asset).where(Asset.project_id == project_id))).scalars().all()
    by_type: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    techs: Counter[str] = Counter()
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    new_24h = 0
    for a in rows:
        by_type[a.type.value] += 1
        by_status[a.status.value] += 1
        for t in a.technologies or []:
            techs[t] += 1
        fs = a.first_seen
        if fs and fs.tzinfo is None:
            fs = fs.replace(tzinfo=UTC)
        if fs and fs >= cutoff:
            new_24h += 1

    edges = await session.scalar(select(func.count(AssetEdge.id)).where(AssetEdge.project_id == project_id))
    return AssetSummary(
        total=len(rows),
        in_scope=sum(1 for a in rows if a.in_scope),
        alive=by_status.get("alive", 0),
        resolved=by_status.get("resolved", 0) + by_status.get("alive", 0),
        by_type=dict(by_type),
        by_status=dict(by_status),
        technologies=[{"name": n, "count": c} for n, c in techs.most_common(15)],
        edges=edges or 0,
        new_last_24h=new_24h,
    )


@router.get("/assets/graph", response_model=AssetGraph)
async def asset_graph(
    project_id: uuid.UUID,
    limit: int = Query(default=400, le=2000),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> AssetGraph:
    principal.require("project.read")
    await _project(session, principal, project_id)

    assets = (
        (
            await session.execute(
                select(Asset)
                .where(Asset.project_id == project_id)
                .order_by(Asset.confidence.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    ids = {a.id for a in assets}
    edges = (
        (await session.execute(select(AssetEdge).where(AssetEdge.project_id == project_id))).scalars().all()
    )
    return AssetGraph(
        nodes=[
            AssetGraphNode(
                id=str(a.id),
                type=a.type.value,
                value=a.value,
                status=a.status.value,
                in_scope=a.in_scope,
            )
            for a in assets
        ],
        edges=[
            AssetGraphEdge(src=str(e.src_asset_id), dst=str(e.dst_asset_id), kind=e.kind.value)
            for e in edges
            if e.src_asset_id in ids and e.dst_asset_id in ids
        ],
    )


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> AssetOut:
    principal.require("project.read")
    await _project(session, principal, project_id)
    row = await session.scalar(
        select(Asset)
        .where(Asset.id == asset_id, Asset.project_id == project_id)
        .options(selectinload(Asset.sources))
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return AssetOut.model_validate(row)


# ── Virtual hosts (M3 Phase 6) ────────────────────────────────────────────


@router.get("/vhosts", response_model=list[VHostOut])
async def list_vhosts(
    project_id: uuid.UUID,
    classification: VHostClass | None = None,
    ip: str | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[VHostOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    stmt = select(VHost).where(VHost.project_id == project_id)
    if classification:
        stmt = stmt.where(VHost.classification == classification)
    if ip:
        stmt = stmt.where(VHost.ip == ip)
    rows = (
        (await session.execute(stmt.order_by(VHost.similarity.asc(), VHost.hostname).limit(1000)))
        .scalars()
        .all()
    )
    return [VHostOut.model_validate(r) for r in rows]


# ── Endpoints (M3 Phase 7) ────────────────────────────────────────────────


@router.get("/endpoints", response_model=list[EndpointOut])
async def list_endpoints(
    project_id: uuid.UUID,
    q: str | None = None,
    method: str | None = None,
    tag: str | None = None,
    host: str | None = None,
    sensitivity: Sensitivity | None = None,
    in_scope: bool | None = True,
    limit: int = Query(default=200, le=2000),
    offset: int = 0,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[EndpointOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    stmt = select(Endpoint).where(Endpoint.project_id == project_id)
    if q:
        stmt = stmt.where(Endpoint.normalized_url.ilike(f"%{q.lower()}%"))
    if method:
        stmt = stmt.where(Endpoint.method == method.upper())
    if tag:
        stmt = stmt.where(Endpoint.tags.contains([tag]))
    if host:
        stmt = stmt.where(Endpoint.host == host.lower())
    if sensitivity:
        stmt = stmt.where(Endpoint.sensitivity == sensitivity)
    if in_scope is not None:
        stmt = stmt.where(Endpoint.in_scope.is_(in_scope))
    # sensitive paths first
    rows = (
        (
            await session.execute(
                stmt.order_by(Endpoint.sensitivity.desc(), Endpoint.host, Endpoint.normalized_url)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [EndpointOut.model_validate(r) for r in rows]


@router.get("/endpoints/summary", response_model=EndpointSummary)
async def endpoint_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> EndpointSummary:
    principal.require("project.read")
    await _project(session, principal, project_id)
    rows = (await session.execute(select(Endpoint).where(Endpoint.project_id == project_id))).scalars().all()
    by_method: dict[str, int] = {}
    by_tag: dict[str, int] = {}
    by_sens: dict[str, int] = {}
    hosts: set[str] = set()
    with_params = 0
    for e in rows:
        by_method[e.method] = by_method.get(e.method, 0) + 1
        for t in e.tags or []:
            by_tag[t] = by_tag.get(t, 0) + 1
        if e.sensitivity != Sensitivity.none:
            by_sens[e.sensitivity.value] = by_sens.get(e.sensitivity.value, 0) + 1
        hosts.add(e.host)
        if e.params:
            with_params += 1
    return EndpointSummary(
        total=len(rows),
        in_scope=sum(1 for e in rows if e.in_scope),
        by_method=by_method,
        by_tag=dict(sorted(by_tag.items(), key=lambda kv: -kv[1])),
        by_sensitivity=by_sens,
        hosts=len(hosts),
        with_params=with_params,
    )


# ── Secrets (M4 Phase 8/10) ───────────────────────────────────────────────


def _secret_out(row: Secret) -> SecretOut:
    out = SecretOut.model_validate(row)
    out.has_encrypted_value = bool(row.value_enc)
    # Operators reaching this endpoint already hold finding.read; the full value
    # is what makes a finding verifiable, so it is returned in the clear.
    if row.value_enc:
        try:
            out.value = decrypt(row.value_enc)
        except Exception:  # noqa: BLE001 — fall back to the stored prefix
            out.value = row.value_preview
    else:
        out.value = row.value_preview
    return out


@router.get("/secrets", response_model=list[SecretOut])
async def list_secrets(
    project_id: uuid.UUID,
    secret_status: SecretStatus | None = Query(default=None, alias="status"),
    detector_type: str | None = None,
    source_kind: str | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[SecretOut]:
    principal.require("finding.read")
    await _project(session, principal, project_id)
    stmt = select(Secret).where(Secret.project_id == project_id)
    if secret_status:
        stmt = stmt.where(Secret.status == secret_status)
    if detector_type:
        stmt = stmt.where(Secret.detector_type == detector_type)
    if source_kind:
        stmt = stmt.where(Secret.source_kind == source_kind)
    rows = (
        (await session.execute(stmt.order_by(Secret.severity.desc(), Secret.last_seen.desc()).limit(1000)))
        .scalars()
        .all()
    )
    return [_secret_out(r) for r in rows]


@router.get("/secrets/summary", response_model=SecretSummary)
async def secret_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> SecretSummary:
    principal.require("finding.read")
    await _project(session, principal, project_id)
    rows = (await session.execute(select(Secret).where(Secret.project_id == project_id))).scalars().all()
    by_type: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for s in rows:
        by_type[s.detector_type] = by_type.get(s.detector_type, 0) + 1
        by_sev[s.severity.value] = by_sev.get(s.severity.value, 0) + 1
        by_kind[s.source_kind] = by_kind.get(s.source_kind, 0) + 1
    return SecretSummary(
        total=len(rows),
        unverified=sum(1 for s in rows if s.status == SecretStatus.unverified),
        verified=sum(1 for s in rows if s.status == SecretStatus.verified),
        false_positive=sum(1 for s in rows if s.status == SecretStatus.false_positive),
        by_type=dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        by_severity=by_sev,
        by_source_kind=by_kind,
    )


@router.patch("/secrets/{secret_id}", response_model=SecretOut)
async def patch_secret(
    project_id: uuid.UUID,
    secret_id: uuid.UUID,
    body: SecretPatch,
    request: Request,
    principal: Principal = Depends(require_permission("finding.modify")),
    session: AsyncSession = Depends(get_session),
) -> SecretOut:
    await _project(session, principal, project_id)
    row = await session.scalar(select(Secret).where(Secret.id == secret_id, Secret.project_id == project_id))
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "secret not found")
    before = row.status.value
    row.status = SecretStatus(body.status)
    row.verified = body.status == "verified"
    await audit.record(
        session,
        action="secret.status_change",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="secret",
        object_id=row.id,
        before={"status": before},
        after={"status": body.status},
        reason=body.reason,
    )
    await session.commit()
    await session.refresh(row)
    return _secret_out(row)


# ── Repositories (M4 Phase 10) ────────────────────────────────────────────


@router.get("/repositories", response_model=list[RepositoryOut])
async def list_repositories(
    project_id: uuid.UUID,
    in_scope: bool | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[RepositoryOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    stmt = select(Repository).where(Repository.project_id == project_id)
    if in_scope is not None:
        stmt = stmt.where(Repository.in_scope.is_(in_scope))
    rows = (
        (await session.execute(stmt.order_by(Repository.pushed_at.desc().nullslast()).limit(1000)))
        .scalars()
        .all()
    )
    return [RepositoryOut.model_validate(r) for r in rows]


# ── Ports (M5 Phase 11) ───────────────────────────────────────────────────

_WEB_SERVICES = ("http", "https", "http-alt", "https-alt", "http-dev")


@router.get("/ports", response_model=list[PortOut])
async def list_ports(
    project_id: uuid.UUID,
    ip: str | None = None,
    service: str | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[PortOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    stmt = select(Port).where(Port.project_id == project_id)
    if ip:
        stmt = stmt.where(Port.ip == ip)
    if service:
        stmt = stmt.where(Port.service == service)
    rows = (
        (await session.execute(stmt.order_by(Port.ip, Port.port).limit(2000))).scalars().all()
    )
    return [PortOut.model_validate(r) for r in rows]


@router.get("/ports/summary", response_model=PortSummary)
async def port_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> PortSummary:
    principal.require("project.read")
    await _project(session, principal, project_id)
    rows = (await session.execute(select(Port).where(Port.project_id == project_id))).scalars().all()
    by_service: dict[str, int] = {}
    by_port: dict[str, int] = {}
    hosts: set[str] = set()
    for p in rows:
        by_service[p.service or "unknown"] = by_service.get(p.service or "unknown", 0) + 1
        by_port[str(p.port)] = by_port.get(str(p.port), 0) + 1
        hosts.add(p.ip)
    return PortSummary(
        total=len(rows),
        hosts=len(hosts),
        by_service=dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
        by_port=dict(sorted(by_port.items(), key=lambda kv: -kv[1])),
        web_ports=sum(1 for p in rows if (p.service or "") in _WEB_SERVICES or p.http_status),
        tls_ports=sum(1 for p in rows if p.tls),
    )


# ── Findings + verification engine (M5 Phases 12-13) ──────────────────────

_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _finding_out(row: Finding, risk_profile) -> FindingOut:
    out = FindingOut.model_validate(row)
    out.priority_score = finding_priority(row, risk_profile)
    out.priority_band = priority_band(out.priority_score)
    return out


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    project_id: uuid.UUID,
    finding_status: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    template_id: str | None = None,
    host: str | None = None,
    min_confidence: int | None = None,
    sort: str = "priority",
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[FindingOut]:
    principal.require("finding.read")
    project = await _project(session, principal, project_id)
    stmt = select(Finding).where(Finding.project_id == project_id)
    if finding_status:
        stmt = stmt.where(Finding.status == FindingStatus(finding_status))
    if severity:
        stmt = stmt.where(Finding.severity == FindingSeverity(severity))
    if template_id:
        stmt = stmt.where(Finding.template_id == template_id)
    if host:
        stmt = stmt.where(Finding.host == host)
    if min_confidence is not None:
        stmt = stmt.where(Finding.confidence >= min_confidence)
    rows = (await session.execute(stmt.limit(2000))).scalars().all()
    out = [_finding_out(r, project.risk_profile) for r in rows]
    if sort == "severity":
        out.sort(key=lambda o: (_SEV_ORDER.get(o.severity, 0), o.confidence), reverse=True)
    else:
        out.sort(key=lambda o: o.priority_score, reverse=True)
    return out


@router.get("/findings/summary", response_model=FindingSummary)
async def finding_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> FindingSummary:
    principal.require("finding.read")
    await _project(session, principal, project_id)
    rows = (await session.execute(select(Finding).where(Finding.project_id == project_id))).scalars().all()
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    tv = ""
    for f in rows:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        tv = tv or f.template_version
    return FindingSummary(
        total=len(rows),
        open=sum(1 for f in rows if f.status == FindingStatus.open),
        confirmed=sum(1 for f in rows if f.status == FindingStatus.confirmed),
        needs_review=sum(1 for f in rows if f.status == FindingStatus.needs_review),
        false_positive=sum(1 for f in rows if f.status == FindingStatus.false_positive),
        by_severity=by_sev,
        by_status=by_status,
        oob_confirmed=sum(1 for f in rows if f.verification == "oob_confirmed"),
        template_version=tv,
    )


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def patch_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: FindingPatch,
    request: Request,
    principal: Principal = Depends(require_permission("finding.modify")),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    project = await _project(session, principal, project_id)
    row = await session.scalar(
        select(Finding).where(Finding.id == finding_id, Finding.project_id == project_id)
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    before = row.status.value
    row.status = FindingStatus(body.status)
    row.triage_reason = body.reason[:500]
    await audit.record(
        session,
        action="finding.status_change",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="finding",
        object_id=row.id,
        before={"status": before},
        after={"status": body.status},
        reason=body.reason,
    )
    await session.commit()
    await session.refresh(row)
    return _finding_out(row, project.risk_profile)
