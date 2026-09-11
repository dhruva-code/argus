"use client";

import { Card, CardHeader, EmptyState, Spinner, StatusBadge } from "@/components/ui";
import { api } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";
import { timeAgo } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const AXIS = { stroke: "var(--muted)", fontSize: 11 };

export default function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardStats>("/dashboard"),
    refetchInterval: 10000,
  });

  if (isLoading || !data)
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner className="h-6 w-6" />
      </div>
    );

  const statusData = Object.entries(data.job_status_breakdown)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k.replace(/_/g, " "), value: v }));

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Executive Dashboard</h1>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <Stat label="Projects" value={data.projects} />
        <Stat label="Assets" value={data.assets} />
        <Stat label="Alive hosts" value={data.assets_alive} tone="ok" />
        <Stat label="New assets · 24h" value={data.assets_new_24h} />
        <Stat label="Active jobs" value={data.active_jobs} />
        <Stat label="Jobs · 24h" value={data.jobs_last_24h} />
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
        <Stat label="Tools OK" value={data.tools_ok} tone="ok" />
        <Stat label="Tools degraded" value={data.tools_degraded} tone="warn" />
        <Stat label="Tools missing" value={data.tools_missing} tone="danger" />
        <Stat label="Scope rules" value={data.scope_rules} />
        <Stat label="Open secrets" value={data.secrets_open} tone="danger" />
        <Stat label="Sensitive paths" value={data.sensitive_paths} tone="danger" />
        <Stat label="Open ports" value={data.open_ports} />
        <Stat label="Open findings" value={data.findings_open} tone="danger" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Job activity · 14 days" />
          <div className="h-56 p-3">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.jobs_over_time}>
                <defs>
                  <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="var(--accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="date" tick={AXIS} tickFormatter={(d) => d.slice(5)} />
                <YAxis tick={AXIS} allowDecimals={false} width={24} />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="var(--accent)"
                  strokeWidth={2}
                  fill="url(#g)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <CardHeader title="Exposure score" />
          <div className="flex flex-col items-center justify-center gap-2 p-6">
            <div className="text-5xl font-semibold tabular-nums">{data.exposure_score}</div>
            <div className="text-xs text-muted">/ 100 — lower is better</div>
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${data.exposure_score}%`,
                  background:
                    data.exposure_score > 66
                      ? "var(--critical)"
                      : data.exposure_score > 33
                        ? "var(--medium)"
                        : "var(--ok)",
                }}
              />
            </div>
            <p className="mt-2 text-center text-[11px] text-muted">
              M1 heuristic from tool health, active work and scope tightness. Replaced by the
              finding-driven priority score in a later milestone.
            </p>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Jobs by status" />
          <div className="h-48 p-3">
            {statusData.length === 0 ? (
              <EmptyState title="No jobs yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusData} layout="vertical">
                  <XAxis type="number" tick={AXIS} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={AXIS} width={110} />
                  <Bar dataKey="value" radius={3}>
                    {statusData.map((_, i) => (
                      <Cell key={i} fill="var(--accent)" />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Recent jobs"
            action={
              <Link href="/jobs" className="text-xs text-accent">
                View all
              </Link>
            }
          />
          <div className="divide-y divide-border">
            {data.recent_jobs.length === 0 && <EmptyState title="No jobs yet" />}
            {data.recent_jobs.map((j) => (
              <Link
                key={j.id}
                href={`/jobs/${j.id}`}
                className="flex items-center justify-between px-4 py-2 text-[13px] hover:bg-surface-2"
              >
                <span className="font-mono text-xs">{j.type}</span>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-muted">{timeAgo(j.created_at)}</span>
                  <StatusBadge status={j.status} />
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>
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
  tone?: "ok" | "warn" | "danger";
}) {
  const color =
    tone === "ok"
      ? "text-ok"
      : tone === "warn"
        ? "text-medium"
        : tone === "danger"
          ? "text-critical"
          : "text-fg";
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</div>
    </Card>
  );
}
