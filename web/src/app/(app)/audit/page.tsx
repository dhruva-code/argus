"use client";

import { Badge, Card, EmptyState, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import type { AuditRow } from "@/lib/types";
import { fmtDate } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

export default function AuditPage() {
  const [q, setQ] = useState("");
  const { data, isLoading, error } = useQuery({
    queryKey: ["audit"],
    queryFn: () => api<AuditRow[]>("/audit-logs?limit=200"),
  });

  const rows = (data ?? []).filter(
    (r) =>
      !q ||
      r.action.includes(q) ||
      r.actor_email.includes(q) ||
      r.object_type.includes(q),
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Audit Logs</h1>
        <Input
          className="w-64"
          placeholder="Filter action / actor / object…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>
      <p className="text-xs text-muted">
        Append-only. Every mutation — scope changes, scans, tool config, account changes — is
        recorded here and cannot be edited from the UI.
      </p>

      <Card>
        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : error ? (
          <EmptyState title="Couldn't load audit logs" hint="Check that the gateway API is reachable and try again." />
        ) : rows.length === 0 ? (
          <EmptyState title="No audit entries" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead className="text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2.5 text-left font-medium">Time</th>
                  <th className="p-2.5 text-left font-medium">Actor</th>
                  <th className="p-2.5 text-left font-medium">Action</th>
                  <th className="p-2.5 text-left font-medium">Object</th>
                  <th className="p-2.5 text-left font-medium">IP</th>
                  <th className="p-2.5 text-left font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-0">
                    <td className="whitespace-nowrap p-2.5 text-xs text-muted">{fmtDate(r.at)}</td>
                    <td className="p-2.5 text-xs">{r.actor_email || "—"}</td>
                    <td className="p-2.5">
                      <Badge tone="accent">{r.action}</Badge>
                    </td>
                    <td className="p-2.5 text-xs text-muted">
                      {r.object_type} {r.object_id && `#${r.object_id.slice(0, 8)}`}
                    </td>
                    <td className="p-2.5 text-xs text-muted">{r.ip || "—"}</td>
                    <td className="max-w-xs truncate p-2.5 text-xs text-muted">
                      {r.reason || (r.after ? JSON.stringify(r.after) : "—")}
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
