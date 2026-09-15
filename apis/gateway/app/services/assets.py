"""Asset Identity Engine.

Turns the stream of normalized `asset` / `asset_edge` events from the
orchestrator into deduplicated rows: one Asset per (project, type, value),
accumulating source attribution, merging partial field updates, only ever
upgrading status, and recomputing a confidence score.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt
from app.models import (
    Asset,
    AssetEdge,
    AssetSource,
    AssetStatus,
    AssetType,
    EdgeKind,
    Endpoint,
    RepoProvider,
    Repository,
    Secret,
    Sensitivity,
    VHost,
    VHostClass,
)

# Higher = more informative. Status only moves up this ladder.
_STATUS_RANK = {
    AssetStatus.unknown: 0,
    AssetStatus.dead: 1,
    AssetStatus.resolved: 2,
    AssetStatus.alive: 3,
}

_MERGE_LIST_FIELDS = ("ip_addresses", "tls_names", "technologies")
_SCALAR_FIELDS = (
    "cname",
    "asn",
    "http_title",
    "http_server",
    "http_scheme",
    "content_type",
    "final_url",
)


def _now() -> datetime:
    return datetime.now(UTC)


def compute_confidence(*, sources: int, resolved: bool, alive: bool) -> int:
    score = 40 + 15 * min(sources, 3)
    if resolved:
        score += 15
    if alive:
        score += 25
    return max(1, min(99, score))


async def _get_or_create(
    session: AsyncSession,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    atype: AssetType,
    value: str,
    scan_id: uuid.UUID | None,
) -> tuple[Asset, bool]:
    value = value.strip().lower()
    row = await session.scalar(
        select(Asset).where(Asset.project_id == project_id, Asset.type == atype, Asset.value == value)
    )
    if row is not None:
        return row, False
    row = Asset(
        org_id=org_id,
        project_id=project_id,
        type=atype,
        value=value,
        first_seen=_now(),
        last_seen=_now(),
        first_seen_scan=scan_id,
    )
    session.add(row)
    await session.flush()
    return row, True


async def upsert_asset(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> Asset:
    raw_type = data.get("type", "")
    try:
        atype = AssetType(raw_type)
    except ValueError:
        atype = AssetType.subdomain
    value = str(data.get("value", "")).strip().lower()
    if not value:
        raise ValueError("asset event has no value")

    asset, _created = await _get_or_create(session, org_id, project_id, atype, value, scan_id)
    asset.last_seen = _now()

    # scope decision is authoritative from the orchestrator
    if "in_scope" in data:
        asset.in_scope = bool(data["in_scope"])
    if data.get("scope_reason"):
        asset.scope_reason = str(data["scope_reason"])[:200]

    # status only ever upgrades
    try:
        new_status = AssetStatus(data.get("status", "unknown"))
    except ValueError:
        new_status = AssetStatus.unknown
    if _STATUS_RANK[new_status] > _STATUS_RANK[asset.status]:
        asset.status = new_status

    # merge list fields (union, order-stable)
    for f in _MERGE_LIST_FIELDS:
        incoming = data.get(f) or []
        if incoming:
            merged = list(dict.fromkeys([*(getattr(asset, f) or []), *incoming]))
            setattr(asset, f, merged)

    # scalar fields: set when the incoming value is non-empty
    for f in _SCALAR_FIELDS:
        v = data.get(f)
        if v:
            setattr(asset, f, str(v)[:1000])

    if data.get("http_status"):
        asset.http_status = int(data["http_status"])
    if data.get("http_port"):
        asset.http_port = int(data["http_port"])
    if data.get("is_wildcard"):
        asset.is_wildcard = True

    # Phase-3 infrastructure enrichment (string key/values → columns)
    infra = data.get("infra") or {}
    for col in ("ptr", "netblock", "asn_org", "cloud_provider", "geo_country"):
        if infra.get(col):
            setattr(asset, col, str(infra[col])[:200])
    if infra.get("asn"):
        asset.asn = str(infra["asn"])[:32]

    for tag in data.get("tags") or []:
        if tag not in (asset.tags or []):
            asset.tags = [*(asset.tags or []), tag]

    # source attribution
    for src in data.get("sources") or []:
        src = str(src)[:60]
        existing = await session.scalar(
            select(AssetSource).where(AssetSource.asset_id == asset.id, AssetSource.source == src)
        )
        if existing is None:
            session.add(AssetSource(asset_id=asset.id, source=src, first_seen=_now(), last_seen=_now()))
        else:
            existing.last_seen = _now()

    await session.flush()
    n_sources = len(
        (await session.execute(select(AssetSource.id).where(AssetSource.asset_id == asset.id)))
        .scalars()
        .all()
    )
    asset.confidence = compute_confidence(
        sources=max(n_sources, len(data.get("sources") or [])),
        resolved=bool(asset.ip_addresses) or asset.status != AssetStatus.unknown,
        alive=asset.status == AssetStatus.alive,
    )
    return asset


async def upsert_edge(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    try:
        kind = EdgeKind(data.get("kind", ""))
    except ValueError:
        return
    src_v = str(data.get("src_value", "")).strip().lower()
    dst_v = str(data.get("dst_value", "")).strip().lower()
    if not src_v or not dst_v:
        return

    def _t(x: str) -> AssetType:
        try:
            return AssetType(x)
        except ValueError:
            return AssetType.subdomain

    src, _ = await _get_or_create(session, org_id, project_id, _t(data.get("src_type", "")), src_v, scan_id)
    dst, _ = await _get_or_create(session, org_id, project_id, _t(data.get("dst_type", "")), dst_v, scan_id)

    existing = await session.scalar(
        select(AssetEdge).where(
            AssetEdge.src_asset_id == src.id,
            AssetEdge.dst_asset_id == dst.id,
            AssetEdge.kind == kind,
        )
    )
    if existing is None:
        session.add(
            AssetEdge(
                project_id=project_id,
                src_asset_id=src.id,
                dst_asset_id=dst.id,
                kind=kind,
                first_seen=_now(),
                last_seen=_now(),
            )
        )
    else:
        existing.last_seen = _now()


# ── M3: virtual hosts & endpoints ─────────────────────────────────────────


async def upsert_vhost(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    ip = str(data.get("ip", "")).strip()
    hostname = str(data.get("hostname", "")).strip().lower()
    if not ip or not hostname:
        return
    row = await session.scalar(
        select(VHost).where(VHost.project_id == project_id, VHost.ip == ip, VHost.hostname == hostname)
    )
    try:
        cls = VHostClass(data.get("classification", "default"))
    except ValueError:
        cls = VHostClass.default
    if row is None:
        row = VHost(
            org_id=org_id,
            project_id=project_id,
            ip=ip,
            hostname=hostname,
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
    row.last_seen = _now()
    row.classification = cls
    row.scheme = data.get("scheme", "https")
    row.port = int(data.get("port", 443) or 443)
    row.status_code = data.get("status_code")
    row.response_bytes = int(data.get("response_bytes", 0) or 0)
    row.title = str(data.get("title", ""))[:500]
    row.server = str(data.get("server", ""))[:200]
    row.baseline_status = data.get("baseline_status")
    row.baseline_bytes = int(data.get("baseline_bytes", 0) or 0)
    row.similarity = float(data.get("similarity", 1.0) or 1.0)
    row.in_scope = bool(data.get("in_scope", True))
    row.evidence = {
        "baseline_status": data.get("baseline_status"),
        "baseline_bytes": data.get("baseline_bytes"),
        "vhost_bytes": data.get("response_bytes"),
    }


_ENDPOINT_TAG_LIMIT = 12


async def upsert_endpoint(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    norm = str(data.get("normalized_url", "")).strip().lower()
    method = str(data.get("method", "GET")).upper()[:10]
    if not norm:
        return
    row = await session.scalar(
        select(Endpoint).where(
            Endpoint.project_id == project_id,
            Endpoint.method == method,
            Endpoint.normalized_url == norm,
        )
    )
    host = str(data.get("host", "")).strip().lower()
    if row is None:
        row = Endpoint(
            org_id=org_id,
            project_id=project_id,
            method=method,
            normalized_url=norm,
            host=host,
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
        # link to the host asset if we have one
        asset = await session.scalar(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.value == host,
                Asset.type.in_([AssetType.subdomain, AssetType.domain]),
            )
        )
        if asset is not None:
            row.asset_id = asset.id
    row.last_seen = _now()
    row.host = host or row.host
    row.scheme = data.get("scheme", "https")
    row.path = str(data.get("path", "/"))[:1000]
    row.sample_url = str(data.get("sample_url", ""))[:2000]
    if data.get("status_code"):
        row.status_code = int(data["status_code"])
    if data.get("content_type"):
        row.content_type = str(data["content_type"])[:120]
    if data.get("content_length") is not None:
        row.content_length = int(data["content_length"])
    if data.get("sensitivity"):
        try:
            new_sev = Sensitivity(data["sensitivity"])
        except ValueError:
            new_sev = Sensitivity.none
        _rank = ["none", "low", "medium", "high", "critical"]
        if _rank.index(new_sev.value) > _rank.index(row.sensitivity.value):
            row.sensitivity = new_sev
            row.sensitivity_reason = str(data.get("sensitivity_reason", ""))[:300]
    row.in_scope = bool(data.get("in_scope", True))
    row.query_keys = list(dict.fromkeys([*(row.query_keys or []), *(data.get("query_keys") or [])]))

    # merge params by name
    have = {p["name"] for p in (row.params or []) if isinstance(p, dict) and "name" in p}
    merged = list(row.params or [])
    for p in data.get("params") or []:
        if isinstance(p, dict) and p.get("name") and p["name"] not in have:
            merged.append(p)
            have.add(p["name"])
    row.params = merged

    for t in data.get("tags") or []:
        if t not in (row.tags or []) and len(row.tags or []) < _ENDPOINT_TAG_LIMIT:
            row.tags = [*(row.tags or []), t]
    for s in data.get("sources") or []:
        if s not in (row.sources or []):
            row.sources = [*(row.sources or []), s]

    if data.get("wayback_observed_at"):
        try:
            wb_ts = datetime.fromisoformat(str(data["wayback_observed_at"]).replace("Z", "+00:00"))
        except ValueError:
            wb_ts = None
        if wb_ts is not None:
            # SQLite (used in tests) drops tzinfo on round-trip even for a
            # DateTime(timezone=True) column, unlike Postgres — normalize
            # both sides to aware UTC before comparing so this works
            # identically on both backends.
            def _aware(dt: datetime) -> datetime:
                return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

            cur_first = row.wayback_first_seen
            cur_last = row.wayback_last_seen
            if cur_first is None or wb_ts < _aware(cur_first):
                row.wayback_first_seen = wb_ts
            if cur_last is None or wb_ts > _aware(cur_last):
                row.wayback_last_seen = wb_ts

    if row.sensitivity.value in ("high", "critical"):
        from app.services.findings import derive_from_endpoint

        await session.flush()
        await derive_from_endpoint(session, row)


# ── M4: secrets & repositories ────────────────────────────────────────────

_SEV_RANK = ["none", "low", "medium", "high", "critical"]


async def upsert_secret(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> Secret | None:
    fp = str(data.get("fingerprint", "")).strip()
    if not fp:
        return None
    row = await session.scalar(
        select(Secret).where(Secret.project_id == project_id, Secret.fingerprint == fp)
    )
    if row is None:
        row = Secret(
            org_id=org_id,
            project_id=project_id,
            fingerprint=fp,
            detector_type=str(data.get("detector_type", "unknown"))[:80],
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
    row.last_seen = _now()
    row.detector = str(data.get("detector", ""))[:40]
    row.source_kind = str(data.get("source_kind", "js"))[:20]
    row.source = str(data.get("source", ""))[:1000]
    row.location = str(data.get("location", ""))[:500]
    row.verified = bool(data.get("verified", False))
    if data.get("confidence"):
        row.confidence = int(data["confidence"])
    try:
        sev = Sensitivity(data.get("severity", "high"))
    except ValueError:
        sev = Sensitivity.high
    row.severity = sev

    # The full value is shown to authorized operators (masking defeats
    # validation). We also keep it encrypted at rest so a DB/backup leak does
    # not expose it. `value_preview` is the real leading characters for list
    # views — a prefix, not a mask.
    value = data.get("value")
    if value is None:
        value = data.get("raw_for_vault")
    if value:
        row.value_preview = str(value)[:200]
        if row.value_enc is None:
            row.value_enc = encrypt(str(value))

    from app.services.findings import derive_from_secret

    await session.flush()
    await derive_from_secret(session, row)
    return row


async def upsert_repository(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    full = str(data.get("full_name", "")).strip()
    if not full:
        return
    try:
        provider = RepoProvider(data.get("provider", "github"))
    except ValueError:
        provider = RepoProvider.github
    row = await session.scalar(
        select(Repository).where(
            Repository.project_id == project_id,
            Repository.provider == provider,
            Repository.full_name == full,
        )
    )
    if row is None:
        row = Repository(
            org_id=org_id,
            project_id=project_id,
            provider=provider,
            full_name=full,
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
    row.last_seen = _now()
    if data.get("url"):
        row.url = str(data["url"])[:500]
    if data.get("description"):
        row.description = str(data["description"])[:2000]
    if data.get("default_branch"):
        row.default_branch = str(data["default_branch"])[:120]
    if "is_fork" in data:
        row.is_fork = bool(data["is_fork"])
    if "is_archived" in data:
        row.is_archived = bool(data["is_archived"])
    if data.get("stars"):
        row.stars = int(data["stars"])
    if data.get("discovered_via"):
        row.discovered_via = str(data["discovered_via"])[:120]
    if data.get("matched_terms"):
        row.matched_terms = list(dict.fromkeys([*(row.matched_terms or []), *data["matched_terms"]]))
    if data.get("iac_files"):
        row.iac_files = list(dict.fromkeys([*(row.iac_files or []), *data["iac_files"]]))
    if "in_scope" in data:
        row.in_scope = row.in_scope or bool(data["in_scope"])
    pushed = data.get("pushed_at")
    if pushed and isinstance(pushed, str) and not pushed.startswith("0001"):
        try:
            row.pushed_at = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        except ValueError:
            pass
