# Assessment reports

`GET /api/projects/{id}/report?format={json|md|csv|html|pdf}&download=bool`
(permission: `report.generate`). Implementation: `apis/gateway/app/services/reports.py`.

All five formats are built from the same `_collect()` snapshot of the
project's current attack surface and findings, so they never disagree with
each other. Generation is synchronous within the request (see *Known
limitations* below).

## Branding

**Settings → Reports** (org-level, `settings.modify` permission):

| Field | Used for |
|---|---|
| Company name | Cover page + running header |
| Logo | Cover page (PNG/JPEG/WebP only, ≤300KB — **SVG is rejected**, it can embed `<script>`) |
| Report title | Cover page main title (default "Security Assessment Report") |
| Author | Cover page "Prepared by" |
| Contact email | Cover page "Contact" |
| Confidentiality label | Cover page badge + every page's header/footer |
| Accent color | Section headings, severity-chart accents |

The logo is stored as a `data:` URI on `report_settings.logo_data_uri`
(no object-storage/MinIO upload path is wired into the gateway app in this
build) — capped at 300KB at the API layer with a clear 400 error above
that, well below the schema's hard 350KB field limit (which exists purely
so the friendlier business-rule error fires before Pydantic's generic one).

## PDF structure

Built with `fpdf2`'s real page-break/table-of-contents/outline support
(`FPDF.insert_toc_placeholder`, `FPDF.start_section`), not a single flat
page of manually-positioned cells:

1. **Cover page** — logo, title, target/client, assessment date, report
   version, prepared-by/contact, confidentiality label.
2. **Table of contents** — auto-generated from the 8 numbered top-level
   sections below, with clickable page links.
3. **1. Executive Summary**
4. **2. Scope** — target, rules of engagement, in-scope asset types.
5. **3. Methodology** — the recon pipeline stages, in plain language.
6. **4. Attack Surface Summary** — asset/endpoint/port/secret counts.
7. **5. Findings Summary** — actionable/confirmed/false-positive counts
   plus a severity-distribution bar chart.
8. **6. Detailed Findings** — one block per finding (up to 50, ordered by
   priority score): ID, title, severity, confidence, status, CWE/CVE/CVSS,
   affected host/path/URL, description, evidence (matcher + extracted
   values), reproduction/verification notes, a sanitized request and
   response excerpt (redacted, monospace, character-wrapped so long
   URLs/tokens never overflow the page), remediation, references,
   detection source, verification status.
9. **7. Remediation Summary** — findings grouped by identical remediation
   text, so a fix that resolves five findings is written up once.
10. **8. Appendix** — secret candidates (masked previews only) and exposed
    network services.

Per-finding headings (and their Description/Evidence/Sanitized
request/etc. sub-headings) deliberately do **not** register in the table
of contents — with up to 50 findings, one TOC row per finding (or per
finding *sub-section*) would make the TOC useless and, before this was
fixed, could overflow its reserved page and crash generation outright (see
CHANGELOG). The TOC stays a genuine 8-section table of contents regardless
of how many findings a project has.

## Redaction

Every raw request/response/curl-command field is passed through a
redaction pass (`_redact()`, a standalone copy of the same patterns used
in `app.services.ai.redact` — kept separate so report generation never
depends on the AI subsystem being available) before it reaches *any*
report format, not just PDF: `Authorization:`/`Cookie:` header lines,
`api_key=`/`token=`/`secret=`/`password=`-style key-value pairs, and
JWT-shaped strings are all replaced with `[REDACTED]`. Secret *values*
are never included in any report format regardless — only type, location,
and an already-masked preview (`Secret.value_preview`).

## Reliability

- **Unicode safety**: fpdf2's core fonts (Helvetica/Courier) only support
  latin-1. Rather than depend on a Unicode TTF font file being present on
  every deployment host (itself a "missing fonts" risk), all PDF text
  passes through `_pdf_safe()`: common "smart" punctuation (em/en dash,
  curly quotes, ellipsis, bullets) is transliterated to a safe ASCII
  equivalent, and anything else outside latin-1 (CJK, emoji, etc., which
  can show up in a scraped page title or asset name) is replaced rather
  than crashing generation. Verified with a stress test covering 60
  findings with mixed Unicode content — see `git log` /
  `tests/test_reports.py`.
- **Validation after generation**: `validate_pdf()` does a best-effort
  structural check (non-empty, `%PDF-`/`%%EOF` markers present, a rough
  page count from counting `/Type /Page` object markers) immediately after
  rendering. A failed check raises `RuntimeError` with the specific
  problem(s) rather than handing a client a silently corrupt file.
- **Long text**: request/response/code blocks render with
  `wrapmode=WrapMode.CHAR`, so a single long unbroken token (a URL, a
  base64 blob) wraps mid-token instead of overflowing the page width —
  the pre-existing failure mode with fpdf2's default word-wrap mode.

## Known limitations

- PDF generation is synchronous in the request path, not a background job
  — see the CHANGELOG's "Known limitations" for why that was judged out of
  scope for this pass, and the stress-test numbers (60 findings → 38-51
  pages, well under a second) for why it hasn't been a practical problem
  so far.
- `validate_pdf()` is a best-effort structural sniff test, not a full
  PDF-specification validator — it catches truncation/corruption, not
  every possible malformed-PDF edge case.
