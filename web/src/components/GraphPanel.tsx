"use client";

import { api } from "@/lib/api";
import type { AssetGraph } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Card, CardHeader, EmptyState, Spinner } from "./ui";

const COLS = ["domain", "subdomain", "ip", "netblock", "asn"] as const;
const TYPE_COLOR: Record<string, string> = {
  domain: "#2563eb",
  subdomain: "#0891b2",
  ip: "#16a34a",
  netblock: "#ca8a04",
  asn: "#9333ea",
  url: "#64748b",
};

interface Placed {
  id: string;
  label: string;
  type: string;
  in_scope: boolean;
  x: number;
  y: number;
}

export function GraphPanel({ projectId }: { projectId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["asset-graph", projectId],
    queryFn: () => api<AssetGraph>(`/projects/${projectId}/assets/graph?limit=800`),
    refetchInterval: 10000,
  });
  const [hover, setHover] = useState<string | null>(null);

  const { nodes, links, height } = useMemo(() => {
    const g = data ?? { nodes: [], edges: [] };
    const colW = 240;
    const rowH = 26;
    const buckets: Record<string, typeof g.nodes> = {};
    for (const n of g.nodes) {
      const col = (COLS as readonly string[]).includes(n.type) ? n.type : "url";
      (buckets[col] ??= []).push(n);
    }
    const order = [...COLS, "url"].filter((c) => buckets[c]?.length);
    const placed: Record<string, Placed> = {};
    let maxRows = 0;
    order.forEach((col, ci) => {
      const list = (buckets[col] ?? []).slice().sort((a, b) => a.value.localeCompare(b.value));
      maxRows = Math.max(maxRows, list.length);
      list.forEach((n, ri) => {
        placed[n.id] = {
          id: n.id,
          label: n.value,
          type: n.type,
          in_scope: n.in_scope,
          x: 60 + ci * colW,
          y: 40 + ri * rowH,
        };
      });
    });
    const ls = g.edges
      .map((e) => ({ s: placed[e.src], t: placed[e.dst], kind: e.kind }))
      .filter((l) => l.s && l.t) as { s: Placed; t: Placed; kind: string }[];
    return {
      nodes: Object.values(placed),
      links: ls,
      height: Math.max(300, 60 + maxRows * rowH),
      width: 80 + order.length * colW,
    };
  }, [data]);

  const W = 80 + (COLS.length + 1) * 240;
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of nodes) c[n.type] = (c[n.type] ?? 0) + 1;
    return c;
  }, [nodes]);
  const connected = useMemo(() => {
    if (!hover) return new Set<string>();
    const s = new Set<string>([hover]);
    for (const l of links) {
      if (l.s.id === hover) s.add(l.t.id);
      if (l.t.id === hover) s.add(l.s.id);
    }
    return s;
  }, [hover, links]);

  return (
    <Card>
      <CardHeader
        title="Attack-surface graph"
        action={
          <div className="flex flex-wrap gap-2 text-[11px]">
            {Object.entries(counts).map(([t, n]) => (
              <span key={t} className="flex items-center gap-1">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ background: TYPE_COLOR[t] ?? "#888" }}
                />
                {t} {n}
              </span>
            ))}
          </div>
        }
      />
      {isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <Spinner className="h-5 w-5" />
        </div>
      ) : nodes.length === 0 ? (
        <EmptyState
          title="No graph yet"
          hint="Run infrastructure_mapping + merge_resolve_alive to build the domain → subdomain → IP → netblock → ASN chain."
        />
      ) : (
        <div className="overflow-auto p-3">
          <svg width={W} height={height} className="text-fg" style={{ minWidth: "100%" }}>
            {[...COLS, "url"]
              .filter((c) => counts[c])
              .map((c, i) => (
                <text
                  key={c}
                  x={60 + i * 240}
                  y={20}
                  className="fill-muted text-[10px] uppercase tracking-wide"
                >
                  {c}
                </text>
              ))}
            {links.map((l, i) => {
              const active = !hover || connected.has(l.s.id);
              return (
                <path
                  key={i}
                  d={`M ${l.s.x} ${l.s.y} C ${(l.s.x + l.t.x) / 2} ${l.s.y}, ${
                    (l.s.x + l.t.x) / 2
                  } ${l.t.y}, ${l.t.x} ${l.t.y}`}
                  fill="none"
                  stroke="currentColor"
                  strokeOpacity={active ? 0.35 : 0.06}
                />
              );
            })}
            {nodes.map((n) => {
              const dim = hover && !connected.has(n.id);
              return (
                <g
                  key={n.id}
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  style={{ cursor: "pointer", opacity: dim ? 0.25 : 1 }}
                >
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={n.type === "asn" || n.type === "netblock" ? 6 : 4.5}
                    fill={TYPE_COLOR[n.type] ?? "#888"}
                    stroke={n.in_scope ? "none" : "#dc2626"}
                    strokeDasharray={n.in_scope ? "0" : "2 2"}
                    fillOpacity={n.in_scope ? 1 : 0.5}
                  />
                  <text x={n.x + 9} y={n.y + 3} className="fill-fg text-[10px]">
                    {n.label.length > 30 ? n.label.slice(0, 30) + "…" : n.label}
                  </text>
                </g>
              );
            })}
          </svg>
          <p className="pt-2 text-[11px] text-muted">
            Columns follow the resolution chain. Dashed red ring = out of scope. Hover to isolate a
            node and its neighbours.
          </p>
        </div>
      )}
    </Card>
  );
}
