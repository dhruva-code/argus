"use client";

import { api } from "@/lib/api";
import type { Repository, Secret, SecretSummary } from "@/lib/types";
import { timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Card, CardHeader, EmptyState, Select, Spinner } from "./ui";

const SEV_TONE: Record<string, "danger" | "warn" | "accent" | "neutral"> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "accent",
  none: "neutral",
};

export function SecretsPanel({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState("");
  // Suppressed = scanner-status false_positive, or AI-classified
  // false_positive. Raw evidence is never deleted — toggle on to review
  // everything, including suppressed candidates.
  const [includeSuppressed, setIncludeSuppressed] = useState(false);

  const summary = useQuery({
    queryKey: ["secret-summary", projectId],
    queryFn: () => api<SecretSummary>(`/projects/${projectId}/secrets/summary`),
    refetchInterval: 5000,
  });
  const secrets = useQuery({
    queryKey: ["secrets", projectId, status, includeSuppressed],
    queryFn: () => {
      const qs = new URLSearchParams();
      if (status) qs.set("status", status);
      if (includeSuppressed) qs.set("include_suppressed", "true");
      return api<Secret[]>(`/projects/${projectId}/secrets?${qs}`);
    },
    refetchInterval: 5000,
  });
  const repos = useQuery({
    queryKey: ["repositories", projectId],
    queryFn: () => api<Repository[]>(`/projects/${projectId}/repositories`),
    refetchInterval: 8000,
  });

  const patch = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) =>
      api(`/projects/${projectId}/secrets/${id}`, { method: "PATCH", body: { status: s } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["secrets", projectId] });
      qc.invalidateQueries({ queryKey: ["secret-summary", projectId] });
    },
  });

  const s = summary.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Secret candidates" value={s?.total ?? 0} tone="danger" />
        <Stat label="Unverified" value={s?.unverified ?? 0} tone="warn" />
        <Stat label="Verified" value={s?.verified ?? 0} tone="danger" />
        <Stat label="Suppressed" value={s?.suppressed_total ?? 0} />
        <Stat label="Repositories" value={repos.data?.length ?? 0} />
      </div>

      <Card>
        <CardHeader
          title="Secret candidates"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Select className="h-7" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">all</option>
                {["unverified", "verified", "false_positive", "revoked"].map((x) => (
                  <option key={x} value={x}>
                    {x.replace(/_/g, " ")}
                  </option>
                ))}
              </Select>
              <label className="flex items-center gap-1 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={includeSuppressed}
                  onChange={(e) => setIncludeSuppressed(e.target.checked)}
                />
                show suppressed
              </label>
            </div>
          }
        />
        <p className="border-b border-border px-4 py-2 text-xs text-muted">
          Full values are shown for validation and are stored encrypted at rest. Treat this view as
          sensitive — access is limited to the <span className="font-mono">finding.read</span>{" "}
          permission and every status change is audited.
        </p>
        {secrets.isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !secrets.data || secrets.data.length === 0 ? (
          <EmptyState
            title="No secret candidates"
            hint="The js_analysis_secrets and source_code_intel phases run TruffleHog + Gitleaks + custom detectors over discovered JavaScript and repositories."
          />
        ) : (
          <div className="max-h-[440px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Type</th>
                  <th className="p-2 text-left font-medium">Severity</th>
                  <th className="p-2 text-left font-medium">Value</th>
                  <th className="p-2 text-left font-medium">Location</th>
                  <th className="p-2 text-left font-medium">Detector</th>
                  <th className="p-2 text-left font-medium">AI assessment</th>
                  <th className="p-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {secrets.data.map((sec) => (
                  <tr
                    key={sec.id}
                    className={`border-b border-border last:border-0 ${
                      sec.status === "false_positive" || sec.ai_classification === "false_positive"
                        ? "opacity-60"
                        : ""
                    }`}
                  >
                    <td className="p-2 font-medium">{sec.detector_type}</td>
                    <td className="p-2">
                      <Badge tone={SEV_TONE[sec.severity]}>{sec.severity}</Badge>
                    </td>
                    <td className="p-2">
                      <SecretValue value={sec.value || sec.value_preview || ""} />
                    </td>
                    <td className="max-w-[280px] truncate p-2 font-mono text-[11px] text-muted">
                      {sec.location}
                    </td>
                    <td className="p-2 text-xs text-muted">
                      {sec.detector} · {sec.source_kind}
                    </td>
                    <td className="p-2 text-xs">
                      {!sec.ai_engine ? (
                        <span className="text-muted">not yet analyzed</span>
                      ) : (
                        <span
                          title={sec.ai_reasoning}
                          className={
                            sec.ai_classification === "true_positive"
                              ? "text-critical"
                              : sec.ai_classification === "false_positive"
                                ? "text-muted"
                                : "text-medium"
                          }
                        >
                          {sec.ai_classification.replace(/_/g, " ") || "assessed"}
                        </span>
                      )}
                    </td>
                    <td className="p-2">
                      <Select
                        className="h-7"
                        value={sec.status}
                        onChange={(e) => patch.mutate({ id: sec.id, s: e.target.value })}
                      >
                        {["unverified", "verified", "false_positive", "revoked"].map((x) => (
                          <option key={x} value={x}>
                            {x.replace(/_/g, " ")}
                          </option>
                        ))}
                      </Select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <CardHeader
          title="Source repositories"
          action={<span className="text-xs text-muted">{repos.data?.length ?? 0} discovered</span>}
        />
        {!repos.data || repos.data.length === 0 ? (
          <EmptyState
            title="No repositories"
            hint="The source_code_intel phase enumerates GitHub org/user repos derived from the root domains (set GITHUB_TOKEN for higher rate limits)."
          />
        ) : (
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Repository</th>
                  <th className="p-2 text-left font-medium">IaC</th>
                  <th className="p-2 text-left font-medium">Matched</th>
                  <th className="p-2 text-right font-medium">Stars</th>
                  <th className="p-2 text-left font-medium">Pushed</th>
                </tr>
              </thead>
              <tbody>
                {repos.data.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-0">
                    <td className="p-2">
                      <a href={r.url} target="_blank" rel="noreferrer" className="font-mono text-xs text-accent">
                        {r.full_name}
                      </a>
                      {r.is_fork && <Badge>fork</Badge>}
                      {r.in_scope && <Badge tone="accent">in scope</Badge>}
                    </td>
                    <td className="p-2">
                      <div className="flex flex-wrap gap-0.5">
                        {r.iac_files.map((t) => (
                          <Badge key={t}>{t}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="p-2 text-[11px] text-muted">{r.matched_terms.join(", ") || "—"}</td>
                    <td className="p-2 text-right tabular-nums">{r.stars}</td>
                    <td className="p-2 text-xs text-muted">{r.pushed_at ? timeAgo(r.pushed_at) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function SecretValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const [full, setFull] = useState(false);
  if (!value) return <span className="text-muted">—</span>;
  const short = value.length > 48 && !full ? `${value.slice(0, 48)}…` : value;
  return (
    <div className="flex items-start gap-1">
      <code
        className="block max-w-[340px] cursor-pointer break-all font-mono text-[11px] leading-tight"
        title={full ? "click to collapse" : "click to reveal full value"}
        onClick={() => setFull((f) => !f)}
      >
        {short}
      </code>
      <button
        type="button"
        className="shrink-0 rounded border border-border px-1 text-[10px] text-muted hover:text-fg"
        onClick={() => {
          navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        {copied ? "✓" : "copy"}
      </button>
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
  tone?: "danger" | "warn";
}) {
  const c = tone === "danger" ? "text-critical" : tone === "warn" ? "text-medium" : "text-fg";
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${c}`}>{value}</div>
    </Card>
  );
}
