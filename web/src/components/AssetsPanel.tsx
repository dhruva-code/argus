"use client";

import { api } from "@/lib/api";
import type { Asset, AssetSummary } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Badge, Card, CardHeader, EmptyState, Input, Select, Spinner, StatusBadge } from "./ui";

const TYPES = ["", "domain", "subdomain", "ip", "url"];
const STATUSES = ["", "alive", "resolved", "dead", "unknown"];

export function AssetsPanel({ projectId }: { projectId: string }) {
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [status, setStatus] = useState("");
  const [scopeOnly, setScopeOnly] = useState(true);
  const [tech, setTech] = useState("");

  const summary = useQuery({
    queryKey: ["asset-summary", projectId],
    queryFn: () => api<AssetSummary>(`/projects/${projectId}/assets/summary`),
    refetchInterval: 5000,
  });

  const params = useMemo(() => {
    // "status" (alive assets surface first) — "confidence" was the previous
    // default, but that column is no longer shown in this table.
    const p = new URLSearchParams({ limit: "500", sort: "status" });
    if (q) p.set("q", q);
    if (type) p.set("type", type);
    if (status) p.set("status", status);
    if (scopeOnly) p.set("in_scope", "true");
    if (tech) p.set("technology", tech);
    return p.toString();
  }, [q, type, status, scopeOnly, tech]);

  const assets = useQuery({
    queryKey: ["assets", projectId, params],
    queryFn: () => api<Asset[]>(`/projects/${projectId}/assets?${params}`),
    refetchInterval: 5000,
  });

  const s = summary.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Assets" value={s?.total ?? 0} />
        <Stat label="In scope" value={s?.in_scope ?? 0} />
        <Stat label="Alive" value={s?.alive ?? 0} tone="ok" />
        <Stat label="Relationships" value={s?.edges ?? 0} />
        <Stat label="New · 24h" value={s?.new_last_24h ?? 0} tone="accent" />
      </div>

      {s && s.technologies.length > 0 && (
        <Card className="p-3">
          <div className="mb-2 text-xs text-muted">Technology distribution</div>
          <div className="flex flex-wrap gap-1.5">
            {s.technologies.map((t) => (
              <button
                key={t.name}
                onClick={() => setTech(tech === t.name ? "" : t.name)}
                className={tech === t.name ? "ring-1 ring-accent rounded" : ""}
              >
                <Badge tone={tech === t.name ? "accent" : "neutral"}>
                  {t.name} · {t.count}
                </Badge>
              </button>
            ))}
          </div>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Asset inventory"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Input
                className="h-7 w-48"
                placeholder="Search host / title…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
              <Select className="h-7" value={type} onChange={(e) => setType(e.target.value)}>
                {TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t || "all types"}
                  </option>
                ))}
              </Select>
              <Select className="h-7" value={status} onChange={(e) => setStatus(e.target.value)}>
                {STATUSES.map((t) => (
                  <option key={t} value={t}>
                    {t || "any status"}
                  </option>
                ))}
              </Select>
              <label className="flex items-center gap-1 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={scopeOnly}
                  onChange={(e) => setScopeOnly(e.target.checked)}
                />
                in scope only
              </label>
            </div>
          }
        />
        {assets.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !assets.data || assets.data.length === 0 ? (
          <EmptyState
            title="No assets yet"
            hint="Run a recon scan from the Scan Jobs tab — passive + active subdomain enumeration and alive-host detection populate this inventory."
          />
        ) : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Asset</th>
                  <th className="p-2 text-left font-medium">Type</th>
                  <th className="p-2 text-left font-medium">Status</th>
                  <th className="p-2 text-left font-medium">HTTP</th>
                  <th className="p-2 text-left font-medium">Tech</th>
                </tr>
              </thead>
              <tbody>
                {assets.data.map((a) => (
                  <tr key={a.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                    <td className="p-2">
                      <div className="font-mono text-xs">{a.value}</div>
                      {a.ip_addresses.length > 0 && (
                        <div className="text-[11px] text-muted">{a.ip_addresses.join(", ")}</div>
                      )}
                      {!a.in_scope && <Badge tone="warn">out of scope</Badge>}
                      {a.is_wildcard && <Badge>wildcard</Badge>}
                    </td>
                    <td className="p-2 text-xs text-muted">{a.type}</td>
                    <td className="p-2">
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="p-2 text-xs">
                      {a.http_status ? (
                        <span>
                          <span className="font-mono">{a.http_status}</span>{" "}
                          <span className="text-muted">{a.http_server}</span>
                          {a.http_title && (
                            <div className="max-w-[220px] truncate text-[11px] text-muted">
                              {a.http_title}
                            </div>
                          )}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="p-2">
                      <div className="flex max-w-[160px] flex-wrap gap-0.5">
                        {a.technologies.slice(0, 4).map((t) => (
                          <Badge key={t}>{t}</Badge>
                        ))}
                      </div>
                    </td>
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
  tone?: "ok" | "accent";
}) {
  const c = tone === "ok" ? "text-ok" : tone === "accent" ? "text-accent" : "text-fg";
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${c}`}>{value}</div>
    </Card>
  );
}
