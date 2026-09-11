"use client";

import { api } from "@/lib/api";
import type { Endpoint, EndpointSummary } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Badge, Card, CardHeader, EmptyState, Input, Select, Spinner } from "./ui";

const METHOD_TONE: Record<string, "ok" | "accent" | "warn" | "danger" | "neutral"> = {
  GET: "neutral",
  POST: "accent",
  PUT: "warn",
  PATCH: "warn",
  DELETE: "danger",
};

export function EndpointsPanel({ projectId }: { projectId: string }) {
  const [q, setQ] = useState("");
  const [method, setMethod] = useState("");
  const [tag, setTag] = useState("");

  const summary = useQuery({
    queryKey: ["endpoint-summary", projectId],
    queryFn: () => api<EndpointSummary>(`/projects/${projectId}/endpoints/summary`),
    refetchInterval: 5000,
  });

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: "600" });
    if (q) p.set("q", q);
    if (method) p.set("method", method);
    if (tag) p.set("tag", tag);
    return p.toString();
  }, [q, method, tag]);

  const endpoints = useQuery({
    queryKey: ["endpoints", projectId, params],
    queryFn: () => api<Endpoint[]>(`/projects/${projectId}/endpoints?${params}`),
    refetchInterval: 5000,
  });

  const s = summary.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Endpoints" value={s?.total ?? 0} />
        <Stat label="Hosts" value={s?.hosts ?? 0} />
        <Stat label="With parameters" value={s?.with_params ?? 0} />
        <Stat
          label="Sensitive (high+)"
          value={(s?.by_sensitivity?.high ?? 0) + (s?.by_sensitivity?.critical ?? 0)}
          tone="danger"
        />
        <Stat label="Sensitive (medium)" value={s?.by_sensitivity?.medium ?? 0} tone="warn" />
      </div>

      {s && Object.keys(s.by_tag).length > 0 && (
        <Card className="p-3">
          <div className="mb-2 text-xs text-muted">Endpoint intelligence</div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(s.by_tag).map(([t, c]) => (
              <button key={t} onClick={() => setTag(tag === t ? "" : t)}>
                <Badge tone={tag === t ? "accent" : "neutral"}>
                  {t} · {c}
                </Badge>
              </button>
            ))}
          </div>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Endpoint inventory"
          action={
            <div className="flex items-center gap-2">
              <Input
                className="h-7 w-52"
                placeholder="Filter normalized URL…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
              <Select className="h-7" value={method} onChange={(e) => setMethod(e.target.value)}>
                <option value="">any method</option>
                {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </Select>
            </div>
          }
        />
        {endpoints.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !endpoints.data || endpoints.data.length === 0 ? (
          <EmptyState
            title="No endpoints yet"
            hint="The url_endpoint_discovery phase runs katana (crawl), gau (historical URLs) and well-known probes (robots / sitemap / OpenAPI / GraphQL), then deduplicates by structural signature."
          />
        ) : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Method</th>
                  <th className="p-2 text-left font-medium">Normalized endpoint</th>
                  <th className="p-2 text-left font-medium">Params</th>
                  <th className="p-2 text-left font-medium">Tags</th>
                  <th className="p-2 text-left font-medium">Sources</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.data.map((e) => (
                  <tr key={e.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                    <td className="p-2">
                      <Badge tone={METHOD_TONE[e.method] ?? "neutral"}>{e.method}</Badge>
                    </td>
                    <td className="p-2">
                      <div className="font-mono text-xs">{e.normalized_url}</div>
                      <div className="flex gap-1">
                        {!e.in_scope && <Badge tone="warn">out of scope</Badge>}
                        {e.sensitivity !== "none" && (
                          <Badge
                            tone={
                              e.sensitivity === "critical" || e.sensitivity === "high"
                                ? "danger"
                                : "warn"
                            }
                          >
                            {e.sensitivity}
                          </Badge>
                        )}
                      </div>
                      {e.sensitivity_reason && (
                        <div className="text-[11px] text-muted">{e.sensitivity_reason}</div>
                      )}
                    </td>
                    <td className="p-2 text-[11px] text-muted">
                      {e.params.map((p) => `${p.name}:${p.kind}`).join(", ") || "—"}
                    </td>
                    <td className="p-2">
                      <div className="flex flex-wrap gap-0.5">
                        {e.tags.map((t) => (
                          <Badge key={t}>{t}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="p-2 text-[11px] text-muted">{e.sources.join(", ")}</td>
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
