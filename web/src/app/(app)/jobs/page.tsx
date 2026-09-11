"use client";

import { Button, Card, CardHeader, EmptyState, Select, Spinner, StatusBadge } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";
import { duration, timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

export default function JobsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["jobs", status],
    queryFn: () => api<Job[]>(`/jobs${status ? `?status_filter=${status}` : ""}`),
    refetchInterval: 5000,
  });

  const stop = useMutation({
    mutationFn: () => api("/jobs/emergency-stop", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Scan Jobs</h1>
        <div className="flex items-center gap-2">
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {["queued", "running", "paused", "completed", "failed", "cancelled", "partially_completed"].map(
              (s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, " ")}
                </option>
              ),
            )}
          </Select>
          {can("scan.cancel") && (
            <Button variant="danger" onClick={() => stop.mutate()} disabled={stop.isPending}>
              Emergency stop all
            </Button>
          )}
        </div>
      </div>

      <Card>
        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !data || data.length === 0 ? (
          <EmptyState title="No jobs" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead className="text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2.5 text-left font-medium">Type</th>
                  <th className="p-2.5 text-left font-medium">Status</th>
                  <th className="p-2.5 text-left font-medium">Worker</th>
                  <th className="p-2.5 text-right font-medium">Results</th>
                  <th className="p-2.5 text-right font-medium">Errors</th>
                  <th className="p-2.5 text-left font-medium">Duration</th>
                  <th className="p-2.5 text-left font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.map((j) => (
                  <tr key={j.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                    <td className="p-2.5">
                      <Link href={`/jobs/${j.id}`} className="font-mono text-xs text-accent">
                        {j.type}
                      </Link>
                    </td>
                    <td className="p-2.5">
                      <StatusBadge status={j.status} />
                    </td>
                    <td className="p-2.5 text-xs text-muted">{j.worker ?? "—"}</td>
                    <td className="p-2.5 text-right tabular-nums">{j.result_count}</td>
                    <td className="p-2.5 text-right tabular-nums">{j.error_count}</td>
                    <td className="p-2.5 text-xs text-muted">
                      {duration(j.started_at, j.finished_at)}
                    </td>
                    <td className="p-2.5 text-xs text-muted">{timeAgo(j.created_at)}</td>
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
