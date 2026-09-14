"use client";

import { Button, Card, CardHeader, EmptyState, Select, Spinner, StatusBadge } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";
import { duration, timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

const TERMINAL = new Set(["completed", "failed", "cancelled", "partially_completed"]);

type DeleteResult = { deleted: number; purged: Record<string, number>; skipped: string[] };

export default function JobsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [purge, setPurge] = useState(false);
  const [delOpen, setDelOpen] = useState(false);

  const canDelete = can("scan.cancel");
  const canPurge = can("project.write");

  const { data, isLoading } = useQuery({
    queryKey: ["jobs", status],
    queryFn: () => api<Job[]>(`/jobs${status ? `?status_filter=${status}` : ""}`),
    refetchInterval: 5000,
  });

  const stop = useMutation({
    mutationFn: () => api("/jobs/emergency-stop", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
  });

  // The delete endpoint is per-project (POST /projects/{id}/scans/delete —
  // it audit-logs one "scan.delete" action per project, listing every job
  // id deleted in that call). This global, cross-project view groups the
  // selection by project so a mixed-project bulk delete still produces one
  // clean audit entry per affected project, not N single-job entries.
  const del = useMutation({
    mutationFn: async () => {
      const byProject = new Map<string, string[]>();
      for (const id of selected) {
        const job = data?.find((j) => j.id === id);
        if (!job) continue;
        byProject.set(job.project_id, [...(byProject.get(job.project_id) ?? []), id]);
      }
      const results = await Promise.all(
        [...byProject.entries()].map(([projectId, jobIds]) =>
          api<DeleteResult>(`/projects/${projectId}/scans/delete`, {
            method: "POST",
            body: { job_ids: jobIds, purge_data: purge },
          }),
        ),
      );
      return results.reduce<DeleteResult>(
        (acc, r) => ({
          deleted: acc.deleted + r.deleted,
          purged: Object.fromEntries(
            Object.entries({ ...acc.purged, ...r.purged }).map(([k, v]) => [
              k,
              (acc.purged[k] ?? 0) + (r.purged[k] ?? 0),
            ]),
          ),
          skipped: [...acc.skipped, ...r.skipped],
        }),
        { deleted: 0, purged: {}, skipped: [] },
      );
    },
    onSuccess: () => {
      setSelected(new Set());
      setPurge(false);
      setDelOpen(false);
      qc.invalidateQueries({ queryKey: ["jobs"] });
    },
  });

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const deletableIds = (data ?? []).filter((j) => TERMINAL.has(j.status)).map((j) => j.id);
  const allSelected = deletableIds.length > 0 && deletableIds.every((id) => selected.has(id));

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
        <CardHeader
          title="Jobs"
          action={
            canDelete && selected.size > 0 ? (
              <div className="flex items-center gap-3 text-xs">
                {canPurge && (
                  <label className="flex items-center gap-1 text-muted">
                    <input type="checkbox" checked={purge} onChange={(e) => setPurge(e.target.checked)} />
                    also delete discovered data
                  </label>
                )}
                <Button variant="outline" onClick={() => setDelOpen(true)}>
                  Delete {selected.size} scan{selected.size > 1 ? "s" : ""}
                </Button>
              </div>
            ) : canDelete && deletableIds.length > 0 ? (
              <label className="flex items-center gap-1 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={(e) => setSelected(e.target.checked ? new Set(deletableIds) : new Set())}
                />
                select all finished
              </label>
            ) : undefined
          }
        />
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
                  {canDelete && <th className="w-8 p-2.5" />}
                  <th className="p-2.5 text-left font-medium">Type</th>
                  <th className="p-2.5 text-left font-medium">Status</th>
                  <th className="p-2.5 text-left font-medium">Worker</th>
                  <th className="p-2.5 text-right font-medium">Results</th>
                  <th className="p-2.5 text-right font-medium">Errors</th>
                  <th className="p-2.5 text-left font-medium">Duration</th>
                  <th className="p-2.5 text-left font-medium">Created</th>
                  {canDelete && <th className="p-2.5" />}
                </tr>
              </thead>
              <tbody>
                {data.map((j) => {
                  const canPick = canDelete && TERMINAL.has(j.status);
                  return (
                    <tr key={j.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                      {canDelete && (
                        <td className="p-2.5">
                          <input
                            type="checkbox"
                            disabled={!canPick}
                            checked={selected.has(j.id)}
                            onChange={() => toggle(j.id)}
                          />
                        </td>
                      )}
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
                      <td className="p-2.5 text-xs text-muted">{duration(j.started_at, j.finished_at)}</td>
                      <td className="p-2.5 text-xs text-muted">{timeAgo(j.created_at)}</td>
                      {canDelete && (
                        <td className="p-2.5 text-right">
                          {canPick && (
                            <button
                              className="text-[11px] text-muted hover:text-critical"
                              onClick={() => {
                                setSelected(new Set([j.id]));
                                setDelOpen(true);
                              }}
                            >
                              Delete
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {delOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md p-5">
            <h3 className="text-sm font-semibold">
              Delete {selected.size} scan{selected.size > 1 ? "s" : ""}?
            </h3>
            <p className="mt-2 text-xs text-muted">
              This removes the scan record and its event log. Running or queued scans are skipped —
              cancel them first.
              {purge
                ? " Because “also delete discovered data” is checked, the assets, endpoints, secrets, ports and findings that these scans first discovered will also be deleted (anything a later scan re-confirmed is kept)."
                : " The assets and findings discovered by these scans stay in the inventory."}
            </p>
            {del.error && <p className="mt-2 text-xs text-critical">{String((del.error as Error).message)}</p>}
            {del.data && del.data.skipped.length > 0 && (
              <p className="mt-2 text-xs text-medium">
                {del.data.skipped.length} job(s) were skipped (not in a finished state, or not found).
              </p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setDelOpen(false)}>
                Cancel
              </Button>
              <Button disabled={del.isPending} onClick={() => del.mutate()}>
                {del.isPending ? "Deleting…" : purge ? "Delete scans + data" : "Delete scans"}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
