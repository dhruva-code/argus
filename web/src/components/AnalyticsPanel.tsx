"use client";

import { api } from "@/lib/api";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button, Card, CardHeader, EmptyState, Spinner } from "./ui";

interface Analytics {
  window_days: number;
  findings_total: number;
  false_positive_rate: number;
  mean_hours_to_triage: number | null;
  scans_in_window: number;
  mean_scan_minutes: number | null;
  riskiest_hosts: [string, number][];
  noisiest_templates: [string, number][];
  verification_mix: Record<string, number>;
}

interface AiSummary {
  engine: string;
  llm_available: boolean;
  summary: string;
  clusters?: { theme?: string; key?: string; count?: number; hosts?: string[]; rationale?: string }[];
  recommended_order?: { name: string; host: string; severity?: string; why?: string }[];
  remediation?: { theme: string; guidance: string }[];
}

export function AnalyticsPanel({ projectId }: { projectId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["analytics", projectId],
    queryFn: () => api<Analytics>(`/projects/${projectId}/analytics`),
    refetchInterval: 20000,
  });
  const [ai, setAi] = useState<AiSummary | null>(null);
  const runAi = useMutation({
    mutationFn: () => api<AiSummary>(`/projects/${projectId}/ai-summary`, { method: "POST" }),
    onSuccess: setAi,
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title="Program analytics" action={<span className="text-xs text-muted">last 30 days</span>} />
        {isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !data ? (
          <EmptyState title="No data yet" />
        ) : (
          <div className="space-y-4 p-4 text-[13px]">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Metric label="Findings" v={data.findings_total} />
              <Metric label="False-positive rate" v={`${(data.false_positive_rate * 100).toFixed(0)}%`} />
              <Metric
                label="Mean time to triage"
                v={data.mean_hours_to_triage != null ? `${data.mean_hours_to_triage} h` : "—"}
              />
              <Metric
                label="Mean scan time"
                v={data.mean_scan_minutes != null ? `${data.mean_scan_minutes} min` : "—"}
              />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <RankList title="Riskiest hosts" rows={data.riskiest_hosts} />
              <RankList title="Noisiest templates" rows={data.noisiest_templates} />
            </div>
          </div>
        )}
      </Card>

      <Card>
        <CardHeader
          title="AI-assisted analysis"
          action={
            <Button variant="outline" disabled={runAi.isPending} onClick={() => runAi.mutate()}>
              {runAi.isPending ? "Analysing…" : ai ? "Re-run" : "Analyse findings"}
            </Button>
          }
        />
        <div className="space-y-3 p-4 text-[13px]">
          {!ai ? (
            <p className="text-muted">
              Read-only: summarises and clusters the current findings and drafts a fix order. Uses an
              LLM when configured, otherwise a deterministic heuristic. Never triggers scans or
              changes scope.
            </p>
          ) : (
            <>
              <p className="text-xs text-muted">
                engine: {ai.engine}
                {ai.engine === "heuristic" && !ai.llm_available && " (set ARGUS_AI_API_KEY for LLM analysis)"}
              </p>
              <p className="whitespace-pre-wrap">{ai.summary}</p>
              {(ai.recommended_order ?? []).length > 0 && (
                <div>
                  <div className="mb-1 font-medium">Suggested fix order</div>
                  <ol className="list-decimal space-y-0.5 pl-5 text-muted">
                    {ai.recommended_order!.slice(0, 10).map((r, i) => (
                      <li key={i}>
                        <span className="text-fg">{r.name}</span> — {r.host}
                        {r.severity ? ` (${r.severity})` : ""}
                        {r.why ? ` · ${r.why}` : ""}
                      </li>
                    ))}
                  </ol>
                </div>
              )}
              {(ai.clusters ?? []).length > 0 && (
                <div>
                  <div className="mb-1 font-medium">Related-finding clusters</div>
                  <ul className="space-y-0.5 text-muted">
                    {ai.clusters!.map((c, i) => (
                      <li key={i}>
                        <span className="text-fg">{c.theme ?? c.key}</span>
                        {c.count ? ` ×${c.count}` : ""}
                        {c.rationale ? ` — ${c.rationale}` : ""}
                        {c.hosts?.length ? ` (${c.hosts.slice(0, 4).join(", ")})` : ""}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {(ai.remediation ?? []).length > 0 && (
                <div>
                  <div className="mb-1 font-medium">Remediation guidance</div>
                  <ul className="space-y-1 text-muted">
                    {ai.remediation!.map((r, i) => (
                      <li key={i}>
                        <span className="text-fg">{r.theme}:</span> {r.guidance}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>
      </Card>
    </div>
  );
}

function Metric({ label, v }: { label: string; v: string | number }) {
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 text-lg font-semibold tabular-nums">{v}</div>
    </Card>
  );
}

function RankList({ title, rows }: { title: string; rows: [string, number][] }) {
  return (
    <div>
      <div className="mb-1 font-medium">{title}</div>
      {rows.length === 0 ? (
        <p className="text-xs text-muted">—</p>
      ) : (
        <ul className="space-y-0.5">
          {rows.map(([k, n]) => (
            <li key={k} className="flex justify-between text-xs">
              <span className="truncate font-mono">{k}</span>
              <span className="tabular-nums text-muted">{n}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
