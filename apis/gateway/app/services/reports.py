"""On-the-fly assessment report generation (M6).

Rolls the project's current attack surface + findings into a single document in
JSON / Markdown / CSV / HTML. No external dependencies — PDF/DOCX are a later
addition. Secret *values* are never included; only type, location and masked
preview.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from html import escape
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__ as _argus_version
from app.models import (
    Asset,
    Endpoint,
    Finding,
    FindingStatus,
    Port,
    Project,
    ScanJob,
    Secret,
)
from app.services.priority import finding_priority, priority_band

FORMATS = ("json", "md", "csv", "html", "pdf")
_MEDIA = {
    "json": "application/json",
    "md": "text/markdown",
    "csv": "text/csv",
    "html": "text/html",
    "pdf": "application/pdf",
}

_ACTIONABLE = {
    FindingStatus.open,
    FindingStatus.confirmed,
    FindingStatus.probable,
    FindingStatus.needs_review,
}


async def _collect(session: AsyncSession, project: Project) -> dict[str, Any]:
    pid = project.id

    async def count(model, *where):
        return await session.scalar(select(func.count()).select_from(model).where(model.project_id == pid, *where))

    assets_total = await count(Asset)
    assets_alive = await count(Asset, Asset.status == "alive")
    findings = (await session.execute(select(Finding).where(Finding.project_id == pid))).scalars().all()
    secrets = (await session.execute(select(Secret).where(Secret.project_id == pid))).scalars().all()
    ports = (await session.execute(select(Port).where(Port.project_id == pid))).scalars().all()

    scored = []
    for f in findings:
        ps = finding_priority(f, project.risk_profile)
        scored.append((ps, f))
    scored.sort(key=lambda t: t[0], reverse=True)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    last_scan = await session.scalar(
        select(ScanJob)
        .where(ScanJob.project_id == pid, ScanJob.type == "recon.scan")
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "platform_version": _argus_version,
        "project": {
            "name": project.name,
            "program": project.program_name,
            "client": project.client,
            "risk_profile": project.risk_profile.value,
        },
        "last_scan": {
            "id": str(last_scan.id) if last_scan else None,
            "status": last_scan.status.value if last_scan else None,
            "finished_at": last_scan.finished_at.isoformat() if last_scan and last_scan.finished_at else None,
        },
        "surface": {
            "assets": assets_total or 0,
            "assets_alive": assets_alive or 0,
            "endpoints": (await count(Endpoint)) or 0,
            "open_ports": len(ports),
            "secrets": len(secrets),
        },
        "findings": {
            "total": len(findings),
            "actionable": sum(1 for f in findings if f.status in _ACTIONABLE),
            "confirmed": sum(1 for f in findings if f.status == FindingStatus.confirmed),
            "false_positive": sum(1 for f in findings if f.status == FindingStatus.false_positive),
            "by_severity": by_sev,
        },
        "top_findings": [
            {
                "priority": ps,
                "band": priority_band(ps),
                "severity": f.severity.value,
                "status": f.status.value,
                "confidence": f.confidence,
                "verification": f.verification,
                "name": f.name or f.template_id,
                "template_id": f.template_id,
                "host": f.host,
                "matched_at": f.matched_at,
                "cve": f.cve,
                "cwe": f.cwe,
                "cvss": f.cvss_score,
                "remediation": f.remediation,
            }
            for ps, f in scored[:50]
            if f.status in _ACTIONABLE
        ],
        "secrets": [
            {
                "type": s.detector_type,
                "severity": s.severity.value,
                "status": s.status.value,
                "source": s.source_kind,
                "location": s.location,
                "preview": s.value_preview,
            }
            for s in sorted(secrets, key=lambda s: s.last_seen, reverse=True)[:100]
        ],
        "exposed_services": [
            {"ip": p.ip, "port": p.port, "service": p.service, "product": p.product, "version": p.version}
            for p in sorted(ports, key=lambda p: (p.ip, p.port))
        ],
    }


def _render_md(d: dict) -> str:
    p, s, fnd = d["project"], d["surface"], d["findings"]
    out = [
        f"# Security assessment — {p['name']}",
        "",
        f"*Generated {d['generated_at']} · Argus v{d['platform_version']} · risk profile: **{p['risk_profile']}***",
        "",
        "## Attack surface",
        "",
        "| Assets | Alive | Endpoints | Open ports | Secrets |",
        "|---|---|---|---|---|",
        f"| {s['assets']} | {s['assets_alive']} | {s['endpoints']} | {s['open_ports']} | {s['secrets']} |",
        "",
        "## Findings",
        "",
        f"- **{fnd['actionable']}** actionable ({fnd['confirmed']} confirmed) of {fnd['total']} total; "
        f"{fnd['false_positive']} dismissed as false positive.",
        "- By severity: "
        + ", ".join(f"{k} {v}" for k, v in sorted(fnd["by_severity"].items(), key=lambda kv: -kv[1]))
        + ".",
        "",
        "### Top priorities",
        "",
        "| # | Priority | Severity | Status | Conf. | Finding | Host | CVE |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(d["top_findings"], 1):
        out.append(
            f"| {i} | {f['priority']} ({f['band']}) | {f['severity']} | {f['status']} | "
            f"{f['confidence']} | {f['name']} | {f['host']} | {', '.join(f['cve']) or '—'} |"
        )
    if d["secrets"]:
        out += ["", "## Secret candidates", "", "| Type | Severity | Status | Source | Location |", "|---|---|---|---|---|"]
        for x in d["secrets"]:
            out.append(f"| {x['type']} | {x['severity']} | {x['status']} | {x['source']} | {x['location']} |")
    if d["exposed_services"]:
        out += ["", "## Exposed services", "", "| IP | Port | Service | Product | Version |", "|---|---|---|---|---|"]
        for x in d["exposed_services"]:
            out.append(f"| {x['ip']} | {x['port']} | {x['service']} | {x['product'] or '—'} | {x['version'] or '—'} |")
    return "\n".join(out) + "\n"


def _render_csv(d: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["priority", "band", "severity", "status", "confidence", "verification",
                "name", "template_id", "host", "matched_at", "cve", "cwe", "cvss", "remediation"])
    for f in d["top_findings"]:
        w.writerow([f["priority"], f["band"], f["severity"], f["status"], f["confidence"],
                    f["verification"], f["name"], f["template_id"], f["host"], f["matched_at"],
                    " ".join(f["cve"]), " ".join(f["cwe"]), f["cvss"] or "", f["remediation"]])
    return buf.getvalue()


def _render_html(d: dict) -> str:
    p = d["project"]
    rows = "".join(
        f"<tr><td>{i}</td><td>{f['priority']} <em>({f['band']})</em></td>"
        f"<td>{escape(f['severity'])}</td><td>{escape(f['status'])}</td><td>{f['confidence']}</td>"
        f"<td>{escape(f['name'])}</td><td>{escape(f['host'])}</td>"
        f"<td>{escape(', '.join(f['cve']) or '—')}</td></tr>"
        for i, f in enumerate(d["top_findings"], 1)
    )
    s = d["surface"]
    return f"""<!doctype html><meta charset=utf-8>
<title>Assessment — {escape(p['name'])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #ccc;padding:.35rem .5rem;text-align:left}}
th{{background:#f4f4f5}}h1{{margin-bottom:.2rem}}.muted{{color:#71717a}}</style>
<h1>Security assessment — {escape(p['name'])}</h1>
<p class=muted>Generated {d['generated_at']} · Argus v{escape(d['platform_version'])} · risk profile: <strong>{escape(p['risk_profile'])}</strong></p>
<h2>Attack surface</h2>
<table><tr><th>Assets</th><th>Alive</th><th>Endpoints</th><th>Open ports</th><th>Secrets</th></tr>
<tr><td>{s['assets']}</td><td>{s['assets_alive']}</td><td>{s['endpoints']}</td><td>{s['open_ports']}</td><td>{s['secrets']}</td></tr></table>
<h2>Findings</h2>
<p>{d['findings']['actionable']} actionable ({d['findings']['confirmed']} confirmed) of {d['findings']['total']} total.</p>
<h3>Top priorities</h3>
<table><tr><th>#</th><th>Priority</th><th>Severity</th><th>Status</th><th>Conf.</th><th>Finding</th><th>Host</th><th>CVE</th></tr>{rows}</table>
"""


_SEV_FILL = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (113, 113, 122),
}


def _render_pdf(d: dict) -> bytes:
    from fpdf import FPDF

    p, s, fnd = d["project"], d["surface"], d["findings"]
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.multi_cell(0, 9, f"Security assessment - {p['name']}")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(110)
    pdf.cell(0, 6, f"Generated {d['generated_at']}  |  Argus v{d['platform_version']}  |  risk profile: {p['risk_profile']}", ln=1)
    pdf.set_text_color(0)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Attack surface", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"{s['assets']} assets ({s['assets_alive']} alive) | {s['endpoints']} endpoints | "
                   f"{s['open_ports']} open ports | {s['secrets']} secret candidates", ln=1)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Findings", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"{fnd['actionable']} actionable ({fnd['confirmed']} confirmed) of {fnd['total']} total; "
                   f"{fnd['false_positive']} dismissed.", ln=1)
    by = ", ".join(f"{k} {v}" for k, v in sorted(fnd["by_severity"].items(), key=lambda kv: -kv[1]))
    pdf.cell(0, 6, f"By severity: {by}", ln=1)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Top priorities", ln=1)
    widths = [10, 16, 20, 22, 62, 42]
    headers = ["#", "Prio", "Severity", "Status", "Finding", "Host"]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(244, 244, 245)
    for w, h in zip(widths, headers, strict=True):
        pdf.cell(w, 6, h, border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for i, f in enumerate(d["top_findings"][:40], 1):
        r, g, b = _SEV_FILL.get(f["severity"], (0, 0, 0))
        pdf.cell(widths[0], 6, str(i), border=1)
        pdf.cell(widths[1], 6, f"{f['priority']}", border=1)
        pdf.set_text_color(r, g, b)
        pdf.cell(widths[2], 6, f["severity"], border=1)
        pdf.set_text_color(0)
        pdf.cell(widths[3], 6, f["status"].replace("_", " "), border=1)
        pdf.cell(widths[4], 6, f["name"][:42], border=1)
        pdf.cell(widths[5], 6, f["host"][:30], border=1)
        pdf.ln()

    if d["secrets"]:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, f"Secret candidates ({len(d['secrets'])})", ln=1)
        pdf.set_font("Helvetica", "", 8)
        for x in d["secrets"][:30]:
            pdf.cell(0, 5, f"- [{x['severity']}] {x['type']} in {x['source']} - {x['location'][:80]}", ln=1)

    out = pdf.output()
    return bytes(out)


async def render_report(session: AsyncSession, project: Project, fmt: str) -> tuple:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported format {fmt!r} (one of {', '.join(FORMATS)})")
    data = await _collect(session, project)
    body = {
        "json": lambda: json.dumps(data, indent=2, default=str),
        "md": lambda: _render_md(data),
        "csv": lambda: _render_csv(data),
        "html": lambda: _render_html(data),
        "pdf": lambda: _render_pdf(data),
    }[fmt]()
    slug = project.name.lower().replace(" ", "-")[:40] or "project"
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return body, _MEDIA[fmt], f"argus-{slug}-{stamp}.{fmt}"
