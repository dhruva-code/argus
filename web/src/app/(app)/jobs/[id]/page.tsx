"use client";

import { Badge, Button, Card, CardHeader, Select, Spinner, StatusBadge } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api, streamEvents } from "@/lib/api";
import type { Job, JobEvent } from "@/lib/types";
import { cn, duration, fmtDate } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

const LEVEL_COLOR: Record<string, string> = {
  ERROR: "text-critical",
  WARNING: "text-medium",
  RESULT: "text-ok",
  TOOL: "text-accent",
  DEBUG: "text-muted",
  INFO: "text-fg",
};

export default function JobDetail() {
  const { id } = useParams<{ id: string }>();
  const { can } = useAuth();
  const qc = useQueryClient();

  const { data: job } = useQuery({
    queryKey: ["job", id],
    queryFn: () => api<Job>(`/jobs/${id}`),
    refetchInterval: (q) =>
      q.state.data && ["running", "queued", "paused"].includes(q.state.data.status) ? 3000 : false,
  });

  const { data: initialEvents } = useQuery({
    queryKey: ["job-events", id],
    queryFn: () => api<JobEvent[]>(`/jobs/${id}/events`),
  });

  const [live, setLive] = useState<any[]>([]);
  const [filter, setFilter] = useState("");
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    if (job && ["running", "queued", "paused"].includes(job.status)) {
      streamEvents(
        `/jobs/${id}/stream`,
        (ev) => {
          if (ev.event === "ping") return;
          setLive((l) => [...l, ev.data]);
          if (ev.data?.type === "status") qc.invalidateQueries({ queryKey: ["job", id] });
        },
        controller.signal,
      ).catch(() => {});
    }
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.status, id, qc]);

  const rows = useMemo(() => {
    const base = (initialEvents ?? []).map((e) => ({
      level: e.level,
      message: e.message,
      at: e.at,
      type: e.type,
    }));
    const merged = [...base, ...live];
    return filter ? merged.filter((r) => r.level === filter) : merged;
  }, [initialEvents, live, filter]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [rows.length]);

  const cancel = useMutation({
    mutationFn: () => api(`/jobs/${id}/cancel`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["job", id] }),
  });

  if (!job)
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner className="h-6 w-6" />
      </div>
    );

  const isActive = ["running", "queued", "paused"].includes(job.status);

  return (
    <div className="space-y-4">
      <div>
        <Link href="/jobs" className="text-xs text-muted hover:text-fg">
          ← Scan Jobs
        </Link>
        <div className="mt-1 flex items-center gap-3">
          <h1 className="font-mono text-base font-semibold">{job.type}</h1>
          <StatusBadge status={job.status} />
          {isActive && can("scan.cancel") && (
            <Button size="sm" variant="danger" onClick={() => cancel.mutate()}>
              Cancel job
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <Meta label="Worker" value={job.worker ?? "—"} />
        <Meta label="Results" value={String(job.result_count)} />
        <Meta label="Errors" value={String(job.error_count)} />
        <Meta label="Duration" value={duration(job.started_at, job.finished_at)} />
      </div>

      {job.error && (
        <Card className="border-critical/40 bg-critical/5 p-3 text-[13px] text-critical">
          {job.error}
        </Card>
      )}

      <Card className="overflow-hidden">
        <CardHeader
          title="Log & results"
          action={
            <Select value={filter} onChange={(e) => setFilter(e.target.value)} className="h-7">
              <option value="">All</option>
              {["INFO", "WARNING", "ERROR", "RESULT", "TOOL", "DEBUG"].map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </Select>
          }
        />
        <div
          ref={logRef}
          className="max-h-[460px] overflow-auto bg-[var(--bg)] p-3 font-mono text-xs leading-relaxed"
        >
          {rows.length === 0 && <p className="text-muted">No log lines yet.</p>}
          {rows.map((r, i) => (
            <div key={i} className="flex gap-2">
              <span className="shrink-0 text-muted">
                {new Date(r.at ?? Date.now()).toLocaleTimeString()}
              </span>
              <span className={cn("shrink-0 w-14", LEVEL_COLOR[r.level] ?? "text-fg")}>
                {r.level}
              </span>
              <span className="whitespace-pre-wrap break-all">{r.message}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <CardHeader title="Parameters" />
        <pre className="overflow-x-auto p-4 font-mono text-xs text-muted">
          {JSON.stringify({ params: job.params, rate_limits: job.rate_limits }, null, 2)}
        </pre>
      </Card>

      <p className="text-xs text-muted">
        Created {fmtDate(job.created_at)} · Project{" "}
        <Link href={`/projects/${job.project_id}`} className="text-accent">
          {job.project_id.slice(0, 8)}
        </Link>
      </p>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </Card>
  );
}
