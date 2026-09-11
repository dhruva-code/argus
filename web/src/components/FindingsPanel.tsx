"use client";

import { api } from "@/lib/api";
import type { Finding, FindingSummary } from "@/lib/types";
import { timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { Badge, Card, CardHeader, EmptyState, Select, Spinner } from "./ui";

const SEV_TONE: Record<string, "danger" | "warn" | "accent" | "neutral"> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "accent",
  info: "neutral",
};

const STATUS_OPTS = [
  "open",
  "confirmed",
  "probable",
  "needs_review",
  "false_positive",
  "fixed",
  "accepted_risk",
];

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function FindingsPanel({
  projectId,
  canModify,
}: {
  projectId: string;
  canModify: boolean;
}) {
  const qc = useQueryClient();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const summary = useQuery({
    queryKey: ["finding-summary", projectId],
    queryFn: () => api<FindingSummary>(`/projects/${projectId}/findings/summary`),
    refetchInterval: 5000,
  });
  const findings = useQuery({
    queryKey: ["findings", projectId, status, severity],
    queryFn: () => {
      const qs = new URLSearchParams();
      if (status) qs.set("status", status);
      if (severity) qs.set("severity", severity);
      return api<Finding[]>(`/projects/${projectId}/findings?${qs}`);
    },
    refetchInterval: 5000,
  });

  const patch = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) =>
      api(`/projects/${projectId}/findings/${id}`, { method: "PATCH", body: { status: s } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings", projectId] });
      qc.invalidateQueries({ queryKey: ["finding-summary", projectId] });
    },
  });

  const s = summary.data;
  const rows = [...(findings.data ?? [])].sort(
    (a, b) => b.priority_score - a.priority_score || (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0),
  );

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Findings" value={s?.total ?? 0} />
        <Stat label="Confirmed" value={s?.confirmed ?? 0} tone="danger" />
        <Stat label="Needs review" value={s?.needs_review ?? 0} tone="warn" />
        <Stat
          label="High + critical"
          value={(s?.by_severity?.high ?? 0) + (s?.by_severity?.critical ?? 0)}
          tone="danger"
        />
        <Stat label="OOB confirmed" value={s?.oob_confirmed ?? 0} tone="accent" />
      </div>

      <Card>
        <CardHeader
          title="Vulnerability findings"
          action={
            <div className="flex gap-2">
              <Select className="h-7" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">any severity</option>
                {["critical", "high", "medium", "low", "info"].map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </Select>
              <Select className="h-7" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">any status</option>
                {STATUS_OPTS.map((x) => (
                  <option key={x} value={x}>
                    {x.replace(/_/g, " ")}
                  </option>
                ))}
              </Select>
            </div>
          }
        />
        <p className="border-b border-border px-4 py-2 text-xs text-muted">
          Each match is deduplicated on a structural fingerprint and scored by the verification
          engine — out-of-band confirmation, named matchers, extracted values and CVE metadata raise
          confidence; low-signal templates are pinned down. Your triage decision is never overwritten
          by a later scan.
          {s?.template_version ? ` · nuclei-templates ${s.template_version}` : ""}
        </p>
        {findings.isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No findings"
            hint="The automated_vuln_scan phase runs a bounded Nuclei scan (dos / intrusive / fuzzing / bruteforce templates are always excluded). Enable finding_verification for out-of-band confirmation."
          />
        ) : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-right font-medium">Priority</th>
                  <th className="p-2 text-left font-medium">Severity</th>
                  <th className="p-2 text-left font-medium">Finding</th>
                  <th className="p-2 text-left font-medium">Host</th>
                  <th className="p-2 text-right font-medium">Conf.</th>
                  <th className="p-2 text-left font-medium">Verification</th>
                  <th className="p-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <Fragment key={f.id}>
                    <tr
                      className="cursor-pointer border-b border-border last:border-0 hover:bg-surface"
                      onClick={() => setOpen(open === f.id ? null : f.id)}
                    >
                      <td className="p-2 text-right">
                        <span
                          className={`font-semibold tabular-nums ${
                            f.priority_band === "urgent"
                              ? "text-critical"
                              : f.priority_band === "high"
                                ? "text-medium"
                                : "text-muted"
                          }`}
                          title={f.priority_band}
                        >
                          {f.priority_score}
                        </span>
                      </td>
                      <td className="p-2">
                        <Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge>
                      </td>
                      <td className="p-2">
                        <div className="font-medium">{f.name || f.template_id}</div>
                        <div className="font-mono text-[11px] text-muted">
                          {f.template_id}
                          {f.cve.length > 0 && ` · ${f.cve.join(", ")}`}
                        </div>
                      </td>
                      <td className="max-w-[220px] truncate p-2 font-mono text-xs text-muted">
                        {f.host}
                      </td>
                      <td className="p-2 text-right tabular-nums">{f.confidence}</td>
                      <td className="p-2 text-xs">
                        {f.verification === "oob_confirmed" ? (
                          <Badge tone="danger">OOB confirmed</Badge>
                        ) : (
                          <span className="text-muted">{f.verification}</span>
                        )}
                      </td>
                      <td className="p-2" onClick={(e) => e.stopPropagation()}>
                        <Select
                          className="h-7"
                          value={f.status}
                          disabled={!canModify}
                          onChange={(e) => patch.mutate({ id: f.id, s: e.target.value })}
                        >
                          {STATUS_OPTS.map((x) => (
                            <option key={x} value={x}>
                              {x.replace(/_/g, " ")}
                            </option>
                          ))}
                        </Select>
                      </td>
                    </tr>
                    {open === f.id && (
                      <tr className="border-b border-border bg-surface">
                        <td colSpan={7} className="p-3">
                          <FindingDetail f={f} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  return (
    <div className="space-y-2 text-xs">
      {f.description && <p className="text-muted">{f.description}</p>}
      <div className="flex flex-wrap gap-x-6 gap-y-1">
        <span>
          <span className="text-muted">Matched at:</span>{" "}
          <span className="font-mono break-all">{f.matched_at}</span>
        </span>
        {f.matcher_name && (
          <span>
            <span className="text-muted">Matcher:</span> {f.matcher_name}
          </span>
        )}
        {f.cvss_score != null && (
          <span>
            <span className="text-muted">CVSS:</span> {f.cvss_score}
          </span>
        )}
        {f.cwe.length > 0 && (
          <span>
            <span className="text-muted">CWE:</span> {f.cwe.join(", ")}
          </span>
        )}
        <span>
          <span className="text-muted">Level:</span> {f.scan_level} · seen {timeAgo(f.last_seen)}
        </span>
      </div>
      {f.verification_note && (
        <p>
          <span className="text-muted">Verification:</span> {f.verification_note}
        </p>
      )}
      {f.extracted.length > 0 && (
        <div>
          <span className="text-muted">Extracted:</span>{" "}
          <span className="font-mono">{f.extracted.join(", ")}</span>
        </div>
      )}
      {f.curl_command && (
        <pre className="overflow-x-auto rounded border border-border bg-bg p-2 font-mono text-[11px]">
          {f.curl_command}
        </pre>
      )}
      {f.response_excerpt && (
        <details>
          <summary className="cursor-pointer text-muted">Response excerpt</summary>
          <pre className="mt-1 max-h-60 overflow-auto rounded border border-border bg-bg p-2 font-mono text-[11px]">
            {f.response_excerpt}
          </pre>
        </details>
      )}
      {f.remediation && (
        <p>
          <span className="text-muted">Remediation:</span> {f.remediation}
        </p>
      )}
      {f.reference.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {f.reference.map((r) => (
            <a key={r} href={r} target="_blank" rel="noreferrer" className="text-accent underline">
              ref
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "danger" | "warn" | "accent";
}) {
  const c =
    tone === "danger"
      ? "text-critical"
      : tone === "warn"
        ? "text-medium"
        : tone === "accent"
          ? "text-accent"
          : "text-fg";
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${c}`}>{value}</div>
    </Card>
  );
}
