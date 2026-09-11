"use client";

import { Card, CardHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";

interface SystemHealth {
  database: { healthy: boolean; latency_ms?: number; error?: string };
  redis: { healthy: boolean; queued: number | null; processing: number | null };
  orchestrator: { reachable: boolean };
  queue: { queued: number | null; processing: number | null };
}

export default function SystemHealthPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => api<SystemHealth>("/system/health"),
    refetchInterval: 10000,
  });

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">System Health</h1>
      <Card>
        <CardHeader title="Core services" />
        {isLoading || !data ? (
          <div className="p-6">
            <Spinner className="h-5 w-5" />
          </div>
        ) : (
          <div className="grid gap-px bg-border sm:grid-cols-3">
            <HealthCell
              name="Database"
              ok={data.database.healthy}
              detail={data.database.healthy ? `${data.database.latency_ms ?? "?"} ms` : data.database.error || "unreachable"}
            />
            <HealthCell
              name="Redis"
              ok={data.redis.healthy}
              detail={`queued ${data.redis.queued ?? "?"} · processing ${data.redis.processing ?? "?"}`}
            />
            <HealthCell
              name="Orchestrator"
              ok={data.orchestrator.reachable}
              detail={data.orchestrator.reachable ? "worker alive" : "no heartbeat"}
            />
          </div>
        )}
      </Card>
      <Card className="p-4 text-[13px] text-muted">
        Frontend and gateway status are implicit — you&apos;re looking at a page this app just
        served you. Worker/scheduler process detail (PID, uptime, resource use) is available via{" "}
        <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-xs">./doctor.sh --performance</code>{" "}
        on the host, or{" "}
        <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-xs">./run.sh status</code>.
      </Card>
    </div>
  );
}

function HealthCell({ name, ok, detail }: { name: string; ok: boolean; detail: string }) {
  return (
    <div className="bg-surface p-4">
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${ok ? "bg-ok" : "bg-critical"}`} />
        <span className="text-[13px] font-medium">{name}</span>
      </div>
      <p className="mt-1 text-xs text-muted">{detail}</p>
    </div>
  );
}
