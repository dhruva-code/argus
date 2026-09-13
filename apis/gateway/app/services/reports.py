"""On-the-fly assessment report generation (M6).

Rolls the project's current attack surface + findings into a single document
in JSON / Markdown / CSV / HTML / PDF. Secret *values* are never included;
only type, location and masked preview. Any freeform evidence text (raw
request/response excerpts) is passed through `_redact()` before it reaches
any report format — API keys, passwords, cookies, session tokens and
Authorization headers are scrubbed regardless of output format.

The PDF report (`_render_pdf`) is a genuine multi-section document: cover
page, auto-generated table of contents, numbered sections, a running
header/footer with page numbers, a severity-distribution bar chart, and a
full per-finding detail section (evidence, reproduction, sanitized
request/response, remediation, references) — built with fpdf2's real
page-break/TOC/outline support rather than a single flat page of cells.
`validate_pdf()` does a best-effort structural sanity check (non-empty,
`%PDF-`/`%%EOF` markers present, rough page count) after generation, so a
broken render surfaces as a clear error instead of a corrupt file.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import uuid
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
    ReportSettings,
    ScanJob,
    Secret,
)
from app.services.priority import finding_priority, priority_band

log = logging.getLogger("argus.reports")

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

# Same intent as app.services.ai.redact — kept as a separate, dependency-free
# copy here so report generation never has to import the AI module (this
# path must keep working even if that subsystem is disabled/misconfigured).
_REDACT_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)authorization:.+"),
    re.compile(r"(?i)cookie:.+"),
    re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{20,}\b"),  # JWT-shaped
]


def _redact(text: str) -> str:
    out = text or ""
    for pat in _REDACT_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


async def _report_branding(session: AsyncSession, org_id: uuid.UUID) -> dict[str, Any]:
    row = await session.get(ReportSettings, org_id)
    if row is None:
        return {
            "company_name": "",
            "logo_data_uri": None,
            "report_title": "Security Assessment Report",
            "author": "",
            "contact_email": "",
            "confidentiality_label": "Confidential",
            "accent_color": "#2563eb",
        }
    return {
        "company_name": row.company_name,
        "logo_data_uri": row.logo_data_uri,
        "report_title": row.report_title,
        "author": row.author,
        "contact_email": row.contact_email,
        "confidentiality_label": row.confidentiality_label,
        "accent_color": row.accent_color,
    }


async def _collect(session: AsyncSession, project: Project) -> dict[str, Any]:
    pid = project.id

    async def count(model, *where):
        return await session.scalar(
            select(func.count()).select_from(model).where(model.project_id == pid, *where)
        )

    assets_total = await count(Asset)
    assets_alive = await count(Asset, Asset.status == "alive")
    findings = (await session.execute(select(Finding).where(Finding.project_id == pid))).scalars().all()
    secrets = (await session.execute(select(Secret).where(Secret.project_id == pid))).scalars().all()
    ports = (await session.execute(select(Port).where(Port.project_id == pid))).scalars().all()
    endpoints = (await session.execute(select(Endpoint).where(Endpoint.project_id == pid))).scalars().all()
    scope_rows = (
        await session.execute(
            select(Asset.type, func.count()).where(Asset.project_id == pid).group_by(Asset.type)
        )
    ).all()

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

    branding = await _report_branding(session, project.org_id)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "platform_version": _argus_version,
        "branding": branding,
        "project": {
            "name": project.name,
            "program": project.program_name,
            "client": project.client,
            "risk_profile": project.risk_profile.value,
            "rules_of_engagement": project.rules_of_engagement,
        },
        "last_scan": {
            "id": str(last_scan.id) if last_scan else None,
            "status": last_scan.status.value if last_scan else None,
            "finished_at": last_scan.finished_at.isoformat() if last_scan and last_scan.finished_at else None,
        },
        "surface": {
            "assets": assets_total or 0,
            "assets_alive": assets_alive or 0,
            "endpoints": len(endpoints),
            "endpoints_with_params": sum(1 for e in endpoints if e.params),
            "open_ports": len(ports),
            "secrets": len(secrets),
            "by_asset_type": {t.value if hasattr(t, "value") else str(t): n for t, n in scope_rows},
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
                "id": str(f.id)[:8],
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
                "normalized_path": f.normalized_path,
                "cve": f.cve,
                "cwe": f.cwe,
                "cvss": f.cvss_score,
                "description": f.description,
                "remediation": f.remediation,
                "reference": f.reference,
                "engine": f.engine,
                "matcher_name": f.matcher_name,
                "extracted": f.extracted,
                "curl_command": _redact(f.curl_command or ""),
                "request": _redact(f.request or ""),
                "response_excerpt": _redact(f.response_excerpt or ""),
                "verification_note": f.verification_note,
                "in_scope": f.in_scope,
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
        out += [
            "",
            "## Secret candidates",
            "",
            "| Type | Severity | Status | Source | Location |",
            "|---|---|---|---|---|",
        ]
        for x in d["secrets"]:
            out.append(f"| {x['type']} | {x['severity']} | {x['status']} | {x['source']} | {x['location']} |")
    if d["exposed_services"]:
        out += [
            "",
            "## Exposed services",
            "",
            "| IP | Port | Service | Product | Version |",
            "|---|---|---|---|---|",
        ]
        for x in d["exposed_services"]:
            out.append(
                f"| {x['ip']} | {x['port']} | {x['service']} | {x['product'] or '—'} | {x['version'] or '—'} |"
            )
    return "\n".join(out) + "\n"


def _render_csv(d: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "priority",
            "band",
            "severity",
            "status",
            "confidence",
            "verification",
            "name",
            "template_id",
            "host",
            "matched_at",
            "cve",
            "cwe",
            "cvss",
            "remediation",
        ]
    )
    for f in d["top_findings"]:
        w.writerow(
            [
                f["priority"],
                f["band"],
                f["severity"],
                f["status"],
                f["confidence"],
                f["verification"],
                f["name"],
                f["template_id"],
                f["host"],
                f["matched_at"],
                " ".join(f["cve"]),
                " ".join(f["cwe"]),
                f["cvss"] or "",
                f["remediation"],
            ]
        )
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
<title>Assessment — {escape(p["name"])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #ccc;padding:.35rem .5rem;text-align:left}}
th{{background:#f4f4f5}}h1{{margin-bottom:.2rem}}.muted{{color:#71717a}}</style>
<h1>Security assessment — {escape(p["name"])}</h1>
<p class=muted>Generated {d["generated_at"]} · Argus v{escape(d["platform_version"])} · risk profile: <strong>{escape(p["risk_profile"])}</strong></p>
<h2>Attack surface</h2>
<table><tr><th>Assets</th><th>Alive</th><th>Endpoints</th><th>Open ports</th><th>Secrets</th></tr>
<tr><td>{s["assets"]}</td><td>{s["assets_alive"]}</td><td>{s["endpoints"]}</td><td>{s["open_ports"]}</td><td>{s["secrets"]}</td></tr></table>
<h2>Findings</h2>
<p>{d["findings"]["actionable"]} actionable ({d["findings"]["confirmed"]} confirmed) of {d["findings"]["total"]} total.</p>
<h3>Top priorities</h3>
<table><tr><th>#</th><th>Priority</th><th>Severity</th><th>Status</th><th>Conf.</th><th>Finding</th><th>Host</th><th>CVE</th></tr>{rows}</table>
"""


# ── PDF ─────────────────────────────────────────────────────────────────

_SEV_RGB = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (113, 113, 122),
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = (h or "#2563eb").lstrip("#")
    if len(h) != 6:
        return (37, 99, 235)
    try:
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    except ValueError:
        return (37, 99, 235)


# fpdf2's core fonts (Helvetica/Courier) are latin-1 only; embedding a full
# Unicode TTF font is possible but depends on a font file being present on
# the host, which is exactly the kind of "missing fonts" fragility this
# report generator should never have. Instead, common "smart" punctuation
# is transliterated to a safe ASCII equivalent, and anything else outside
# latin-1 (CJK, emoji, etc. in a scraped page title or asset name) is
# replaced rather than crashing the whole report — a report with a "?" in
# one field is a much smaller failure than no report at all.
_UNICODE_TRANSLITERATIONS = {
    "—": "-",
    "–": "-",  # em/en dash
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',  # curly quotes
    "…": "...",  # ellipsis
    "•": "-",  # bullet
    " ": " ",  # nbsp
}


def _pdf_safe(text: str) -> str:
    if text is None:
        return ""
    text = str(text)
    for src, dst in _UNICODE_TRANSLITERATIONS.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _data_uri_to_bytes(data_uri: str) -> tuple[bytes, str] | None:
    """Returns (raw_bytes, extension) or None if the URI is malformed."""
    import base64

    m = re.match(r"^data:image/(png|jpe?g|webp);base64,(.+)$", data_uri, re.DOTALL)
    if not m:
        return None
    ext = {"png": "png", "jpg": "jpg", "jpeg": "jpg", "webp": "webp"}[m.group(1).lower()]
    try:
        return base64.b64decode(m.group(2)), ext
    except Exception:  # noqa: BLE001
        return None


def _render_pdf(d: dict) -> bytes:
    import tempfile
    from pathlib import Path

    from fpdf import FPDF
    from fpdf.enums import WrapMode, XPos, YPos
    from fpdf.fonts import TextStyle

    branding = d["branding"]
    accent = _hex_to_rgb(branding["accent_color"])
    p, s, fnd = d["project"], d["surface"], d["findings"]

    class ArgusPDF(FPDF):
        # Every piece of text in this report — including data pulled from
        # scan results (asset/host names, finding titles) — passes through
        # `cell`/`multi_cell` eventually, so sanitizing text at exactly
        # these two chokepoints protects every call site at once, including
        # header()/footer()/the TOC renderer, without having to remember to
        # wrap each one individually.
        def cell(self, *args, **kwargs):  # noqa: D102
            if "text" in kwargs:
                kwargs["text"] = _pdf_safe(kwargs["text"])
            elif len(args) >= 3:
                args = (*args[:2], _pdf_safe(args[2]), *args[3:])
            return super().cell(*args, **kwargs)

        def multi_cell(self, *args, **kwargs):  # noqa: D102
            if "text" in kwargs:
                kwargs["text"] = _pdf_safe(kwargs["text"])
            elif len(args) >= 3:
                args = (*args[:2], _pdf_safe(args[2]), *args[3:])
            return super().multi_cell(*args, **kwargs)

        def header(self) -> None:  # noqa: N802 - fpdf2 API
            if self.page_no() == 1:
                return
            self.set_font("Helvetica", "", 8)
            self.set_text_color(120, 120, 120)
            self.set_y(8)
            label = branding["company_name"] or "Argus"
            self.cell(95, 5, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(
                95, 5, branding["confidentiality_label"], align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
            self.set_draw_color(220, 220, 220)
            self.line(10, 14, 200, 14)
            self.set_text_color(0, 0, 0)
            self.set_y(18)

        def footer(self) -> None:  # noqa: N802 - fpdf2 API
            if self.page_no() == 1:
                return
            self.set_y(-15)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(120, 120, 120)
            self.cell(95, 10, f"Argus v{d['platform_version']}", new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(95, 10, f"Page {self.page_no()}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)

    pdf = ArgusPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_section_title_styles(
        level0=TextStyle(font_family="Helvetica", font_style="B", font_size_pt=15, color=accent),
        level1=TextStyle(font_family="Helvetica", font_style="B", font_size_pt=11),
    )

    # ── cover page ──────────────────────────────────────────────────────
    pdf.add_page()
    logo = _data_uri_to_bytes(branding["logo_data_uri"] or "")
    if logo is not None:
        raw, ext = logo
        with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tf:
            tf.write(raw)
            tmp_path = tf.name
        try:
            pdf.image(tmp_path, x=15, y=20, w=40)
        except Exception:  # noqa: BLE001 - a malformed logo must not break the whole report
            log.warning("failed to embed report logo image", exc_info=True)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    pdf.set_y(75)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*accent)
    pdf.multi_cell(
        0,
        12,
        branding["report_title"] or "Security Assessment Report",
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 16)
    pdf.multi_cell(0, 9, p["name"], align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if p["client"]:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(90, 90, 90)
        pdf.multi_cell(0, 7, p["client"], align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    pdf.set_font("Helvetica", "B", 10)
    box_y = pdf.get_y()
    pdf.set_fill_color(245, 245, 247)
    pdf.rect(45, box_y, 120, 42, style="F")
    pdf.set_y(box_y + 4)
    for label, value in (
        ("Assessment date", datetime.now(UTC).strftime("%Y-%m-%d")),
        ("Report version", d["platform_version"]),
        ("Prepared by", branding["author"] or "—"),
        ("Contact", branding["contact_email"] or "—"),
    ):
        pdf.set_x(50)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 8, label, new_x=XPos.LEFT, new_y=YPos.TOP)
        pdf.set_x(95)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(65, 8, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(-40)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*accent)
    pdf.cell(
        0,
        8,
        branding["confidentiality_label"] or "Confidential",
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_text_color(0, 0, 0)

    # ── table of contents (auto-filled from start_section calls below) ──
    def _render_toc(pdf_: FPDF, outline) -> None:
        pdf_.set_font("Helvetica", "B", 16)
        pdf_.cell(0, 12, "Table of Contents", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf_.ln(2)
        pdf_.set_font("Helvetica", "", 11)
        for section in outline:
            indent = 6 * section.level
            pdf_.set_x(10 + indent)
            link = pdf_.add_link(page=section.page_number)
            pdf_.cell(0, 8, f"{section.name}", link=link, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # allow_extra_pages: a reserved 1-page TOC is normally plenty for 8
    # top-level sections, but this is a defensive backstop, not the primary
    # fix — the primary fix is that per-finding headings (below) don't
    # register as TOC entries at all, so the TOC stays a real table of
    # *contents* (8 sections) rather than growing one row per finding.
    pdf.insert_toc_placeholder(_render_toc, pages=1, allow_extra_pages=True)

    def h1(title: str) -> None:
        pdf.add_page()
        pdf.start_section(title, level=0)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(*accent)
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    def h2(title: str) -> None:
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.start_section(title, level=1)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    def finding_heading(title: str) -> None:
        """Like h2, but intentionally NOT added to the table of
        contents/outline — with up to 50 findings per report, one TOC
        entry per finding would make the TOC useless (and, with enough
        findings, overflow its reserved page). Findings are still fully
        readable and individually addressable (each has its own ID), just
        not enumerated in the navigation."""
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    def body(text: str, *, size: int = 10, mono: bool = False) -> None:
        pdf.set_font("Courier" if mono else "Helvetica", "", size)
        pdf.multi_cell(0, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT, wrapmode=WrapMode.CHAR)
        pdf.ln(1)

    def code_block(text: str) -> None:
        if not text:
            return
        pdf.set_fill_color(245, 245, 247)
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(
            0,
            4.5,
            text[:3000],
            border=1,
            fill=True,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            wrapmode=WrapMode.CHAR,
        )
        pdf.ln(1)

    # ── 1. executive summary ─────────────────────────────────────────────
    h1("1. Executive Summary")
    target_desc = p["name"] + (f" ({p['program']})" if p["program"] else "")
    body(
        f"This report presents the results of an automated security assessment of "
        f"{target_desc}, performed with Argus v{d['platform_version']}. The assessment identified "
        f"{fnd['total']} finding(s), of which {fnd['actionable']} are actionable "
        f"({fnd['confirmed']} confirmed) and {fnd['false_positive']} were triaged as false positives. "
        f"The project's configured risk profile is '{p['risk_profile']}'."
    )
    if fnd["by_severity"]:
        body(
            "Severity distribution: "
            + ", ".join(f"{v} {k}" for k, v in sorted(fnd["by_severity"].items(), key=lambda kv: -kv[1]))
            + "."
        )

    # ── 2. scope ──────────────────────────────────────────────────────────
    h1("2. Scope")
    body(f"Target: {p['name']}" + (f" — {p['client']}" if p["client"] else ""))
    if p["rules_of_engagement"]:
        h2("Rules of engagement")
        body(p["rules_of_engagement"])
    if s["by_asset_type"]:
        h2("Asset types in scope")
        body(", ".join(f"{k}: {v}" for k, v in s["by_asset_type"].items()))

    # ── 3. methodology ────────────────────────────────────────────────────
    h1("3. Methodology")
    body(
        "Reconnaissance and testing followed Argus's staged recon pipeline: passive and active "
        "subdomain enumeration, infrastructure mapping, WAF/CDN/origin intelligence, virtual-host "
        "enumeration, URL and endpoint discovery (crawl, historical URLs including the Wayback "
        "Machine's CDX archive, and well-known-path probing), JavaScript analysis, directory "
        "discovery, source-code intelligence, port/service fingerprinting, automated vulnerability "
        "scanning, and a dedicated injection-testing phase — each gated behind explicit scope rules "
        "and, for active testing, an explicit authorization acknowledgement. Every finding is scored "
        "for confidence and verification status rather than reported at face value; a scanner-only "
        "match is never presented as independently verified without corroborating evidence."
    )

    # ── 4. attack surface summary ────────────────────────────────────────
    h1("4. Attack Surface Summary")
    for label, value in (
        ("Assets discovered", s["assets"]),
        ("Assets alive / in scope", s["assets_alive"]),
        ("Endpoints discovered", s["endpoints"]),
        ("Endpoints with parameters", s["endpoints_with_params"]),
        ("Open ports", s["open_ports"]),
        ("Secret candidates", s["secrets"]),
    ):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(70, 7, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── 5. findings summary + severity chart ─────────────────────────────
    h1("5. Findings Summary")
    body(
        f"{fnd['actionable']} actionable finding(s) ({fnd['confirmed']} confirmed) of {fnd['total']} "
        f"total; {fnd['false_positive']} dismissed as false positive."
    )
    if fnd["by_severity"]:
        h2("Severity distribution")
        max_n = max(fnd["by_severity"].values())
        chart_x, bar_max_w = 55, 110
        for sev in _SEV_ORDER:
            n = fnd["by_severity"].get(sev, 0)
            if n == 0:
                continue
            y = pdf.get_y()
            pdf.set_font("Helvetica", "", 9)
            pdf.set_xy(10, y)
            pdf.cell(40, 6, sev.capitalize(), new_x=XPos.LMARGIN, new_y=YPos.TOP)
            w = max(2, bar_max_w * n / max_n)
            r, g, b = _SEV_RGB[sev]
            pdf.set_fill_color(r, g, b)
            pdf.rect(chart_x, y + 0.5, w, 5, style="F")
            pdf.set_xy(chart_x + w + 3, y)
            pdf.cell(15, 6, str(n), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    # ── 6. detailed findings ─────────────────────────────────────────────
    h1("6. Detailed Findings")
    if not d["top_findings"]:
        body("No actionable findings were recorded at report generation time.")
    for i, f in enumerate(d["top_findings"][:50], 1):
        finding_heading(f"6.{i} [{f['id']}] {f['name']}")
        r, g, b = _SEV_RGB.get(f["severity"], (0, 0, 0))
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(
            0,
            6,
            f"{f['severity'].upper()}  ·  confidence {f['confidence']}%  ·  {f['status'].replace('_', ' ')}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.set_text_color(0, 0, 0)

        meta_bits = []
        if f["cwe"]:
            meta_bits.append("CWE: " + ", ".join(f["cwe"]))
        if f["cve"]:
            meta_bits.append("CVE: " + ", ".join(f["cve"]))
        if f["cvss"]:
            meta_bits.append(f"CVSS: {f['cvss']}")
        meta_bits.append(f"Detection source: {f['engine']}")
        meta_bits.append(f"Verification: {f['verification'] or 'unverified'}")
        if meta_bits:
            body(" · ".join(meta_bits), size=9)

        body(f"Affected: {f['host']}{f['normalized_path']}", size=9, mono=True)
        if f["matched_at"] and f["matched_at"] != f["host"] + f["normalized_path"]:
            body(f"URL: {f['matched_at']}", size=9, mono=True)

        if f["description"]:
            finding_heading("Description")
            body(f["description"])
        if f["matcher_name"] or f["extracted"]:
            finding_heading("Evidence")
            if f["matcher_name"]:
                body(f"Matcher: {f['matcher_name']}", size=9)
            if f["extracted"]:
                body("Extracted: " + ", ".join(str(x) for x in f["extracted"]), size=9)
        if f["verification_note"]:
            finding_heading("Reproduction / verification notes")
            body(f["verification_note"])
        if f["curl_command"] or f["request"]:
            finding_heading("Sanitized request")
            code_block(f["curl_command"] or f["request"])
        if f["response_excerpt"]:
            finding_heading("Response excerpt (sanitized)")
            code_block(f["response_excerpt"])
        if f["remediation"]:
            finding_heading("Remediation")
            body(f["remediation"])
        if f["reference"]:
            finding_heading("References")
            body("\n".join(f["reference"]), size=8, mono=True)
        pdf.ln(3)

    # ── 7. remediation summary ───────────────────────────────────────────
    h1("7. Remediation Summary")
    seen_remediation: dict[str, list[str]] = {}
    for f in d["top_findings"]:
        if f["remediation"]:
            seen_remediation.setdefault(f["remediation"], []).append(f["name"])
    if not seen_remediation:
        body("No remediation guidance was recorded for the actionable findings above.")
    for rem, names in seen_remediation.items():
        finding_heading(f"Affects: {', '.join(names[:5])}{'...' if len(names) > 5 else ''}")
        body(rem)

    # ── 8. appendix: asset & endpoint summary, secrets, services ─────────
    h1("8. Appendix")
    h2("A. Secret candidates")
    if not d["secrets"]:
        body("None detected.")
    for x in d["secrets"][:40]:
        body(f"[{x['severity']}] {x['type']} via {x['source']} — {x['location'][:100]}", size=8, mono=True)

    h2("B. Exposed network services")
    if not d["exposed_services"]:
        body("None detected.")
    for x in d["exposed_services"][:60]:
        body(
            f"{x['ip']}:{x['port']}  {x['service'] or '?'}  {x['product'] or ''} {x['version'] or ''}".strip(),
            size=8,
            mono=True,
        )

    out = pdf.output()
    return bytes(out)


def validate_pdf(data: bytes, *, min_pages: int = 1) -> list[str]:
    """Best-effort structural sanity check — not a full PDF-spec validator,
    but enough to catch a truncated/corrupt render before it reaches a
    client: non-empty, has the `%PDF-`/`%%EOF` markers every valid PDF file
    has, and a rough page count from counting `/Type /Page` object markers.
    Returns a list of problems; empty means it looks structurally sound."""
    problems = []
    if not data:
        problems.append("empty output")
        return problems
    if not data.startswith(b"%PDF-"):
        problems.append("missing %PDF- header")
    if b"%%EOF" not in data[-2048:]:
        problems.append("missing %%EOF trailer (possibly truncated)")
    # a real /Type/Pages dict also matches "/Type/Page" as a substring, so
    # this rough count is a slight overcount by design — used only as a
    # "is this suspiciously empty" signal, not an exact page count.
    page_count = len(re.findall(rb"/Type\s*/Page[^s]", data))
    if page_count < min_pages:
        problems.append(f"suspiciously low page count ({page_count}, expected >= {min_pages})")
    return problems


async def render_report(session: AsyncSession, project: Project, fmt: str) -> tuple:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported format {fmt!r} (one of {', '.join(FORMATS)})")
    data = await _collect(session, project)
    body_fn = {
        "json": lambda: json_dumps(data),
        "md": lambda: _render_md(data),
        "csv": lambda: _render_csv(data),
        "html": lambda: _render_html(data),
        "pdf": lambda: _render_pdf(data),
    }[fmt]
    body = body_fn()
    if fmt == "pdf":
        # A failed/corrupt render must be a clear error, never a silently
        # broken file handed to the client.
        problems = validate_pdf(body, min_pages=9)  # cover + TOC + 8 numbered sections, at minimum
        if problems:
            log.error("generated PDF failed validation for project %s: %s", project.id, "; ".join(problems))
            raise RuntimeError(f"PDF generation produced an invalid document: {'; '.join(problems)}")
    slug = project.name.lower().replace(" ", "-")[:40] or "project"
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return body, _MEDIA[fmt], f"argus-{slug}-{stamp}.{fmt}"


def json_dumps(data: dict) -> str:
    import json

    return json.dumps(data, indent=2, default=str)
