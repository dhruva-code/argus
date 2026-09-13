"use client";

import { api } from "@/lib/api";
import type { Endpoint, EndpointSummary } from "@/lib/types";
import { fmtDate } from "@/lib/utils";
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

export function WaybackPanel({ projectId }: { projectId: string }) {
  const [q, setQ] = useState("");
  const [domain, setDomain] = useState("");
  const [statusCode, setStatusCode] = useState("");
  const [extension, setExtension] = useState("");
  const [onlyParams, setOnlyParams] = useState(false);
  const [onlyInteresting, setOnlyInteresting] = useState(false);

  const summary = useQuery({
    queryKey: ["endpoint-summary", projectId],
    queryFn: () => api<EndpointSummary>(`/projects/${projectId}/endpoints/summary`),
    refetchInterval: 5000,
  });

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: "600", source: "wayback" });
    if (q) p.set("q", q);
    if (domain) p.set("host", domain);
    if (statusCode) p.set("status_code", statusCode);
    if (extension) p.set("extension", extension);
    if (onlyParams) p.set("has_params", "true");
    if (onlyInteresting) p.set("sensitivity", "medium");
    return p.toString();
  }, [q, domain, statusCode, extension, onlyParams, onlyInteresting]);

  const urls = useQuery({
    queryKey: ["wayback-endpoints", projectId, params],
    queryFn: () => api<Endpoint[]>(`/projects/${projectId}/endpoints?${params}`),
    refetchInterval: 5000,
  });

  const s = summary.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Total Wayback URLs" value={s?.wayback_total ?? 0} />
        <Stat label="New (Wayback-only)" value={s?.wayback_new ?? 0} tone="accent" />
        <Stat label="Parameterized" value={s?.wayback_parameterized ?? 0} />
        <Stat label="Interesting / sensitive" value={s?.wayback_interesting ?? 0} tone="warn" />
      </div>

      <Card>
        <CardHeader
          title="Wayback URLs"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Input
                className="h-7 w-44"
                placeholder="Filter URL…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
              <Input
                className="h-7 w-36"
                placeholder="Domain…"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
              <Input
                className="h-7 w-24"
                placeholder="Extension"
                value={extension}
                onChange={(e) => setExtension(e.target.value)}
              />
              <Select
                className="h-7"
                value={statusCode}
                onChange={(e) => setStatusCode(e.target.value)}
              >
                <option value="">any status</option>
                {[200, 301, 302, 403, 404, 500].map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
              <label className="flex items-center gap-1 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={onlyParams}
                  onChange={(e) => setOnlyParams(e.target.checked)}
                />
                parameterized only
              </label>
              <label className="flex items-center gap-1 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={onlyInteresting}
                  onChange={(e) => setOnlyInteresting(e.target.checked)}
                />
                interesting/sensitive only
              </label>
            </div>
          }
        />
        {urls.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !urls.data || urls.data.length === 0 ? (
          <EmptyState
            title="No Wayback URLs yet"
            hint="The url_endpoint_discovery phase queries the Internet Archive's CDX API (web.archive.org) for historical URLs under each in-scope root, alongside katana (crawl) and gau (historical URLs). Results are deduplicated with the existing endpoint inventory — a URL already found by another source is not reprocessed. Network/API failures against the CDX API are reported as a WARNING in the scan's job log, not silently ignored."
          />
        ) : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Method</th>
                  <th className="p-2 text-left font-medium">URL</th>
                  <th className="p-2 text-left font-medium">Params</th>
                  <th className="p-2 text-left font-medium">Historical date</th>
                  <th className="p-2 text-left font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {urls.data.map((e) => (
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
                        {e.sources.length > 1 && <Badge>also: {e.sources.filter((s2) => s2 !== "wayback").join(", ")}</Badge>}
                      </div>
                    </td>
                    <td className="p-2 text-[11px] text-muted">
                      {e.params.map((p) => `${p.name}:${p.kind}`).join(", ") || "—"}
                    </td>
                    <td className="p-2 text-[11px] text-muted">
                      {e.wayback_first_seen ? (
                        e.wayback_first_seen === e.wayback_last_seen ? (
                          fmtDate(e.wayback_first_seen)
                        ) : (
                          <>
                            {fmtDate(e.wayback_first_seen)} → {fmtDate(e.wayback_last_seen ?? e.wayback_first_seen)}
                          </>
                        )
                      ) : (
                        "—"
                      )}
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
