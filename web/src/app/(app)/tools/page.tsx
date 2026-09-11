"use client";

import { Badge, Button, Card, CardHeader, Input, Spinner, StatusBadge } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { Job, Tool } from "@/lib/types";
import { timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

export default function ToolsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["tools"],
    queryFn: () => api<Tool[]>("/tools"),
    refetchInterval: 5000,
  });

  const check = useMutation({
    mutationFn: () => api<Job>("/tools/health-check", { method: "POST" }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["tools"] }), 3000),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Tool Manager</h1>
        {can("tool.configure") && (
          <Button onClick={() => check.mutate()} disabled={check.isPending}>
            {check.isPending ? "Probing…" : "Run health check"}
          </Button>
        )}
      </div>
      {check.error && (
        <p className="text-xs text-critical">{String((check.error as any).message)}</p>
      )}

      {isLoading ? (
        <div className="flex h-40 items-center justify-center">
          <Spinner className="h-5 w-5" />
        </div>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {data?.map((t) => (
            <ToolCard key={t.id} tool={t} canEdit={can("tool.configure")} />
          ))}
        </div>
      )}
    </div>
  );
}

function ToolCard({ tool, canEdit }: { tool: Tool; canEdit: boolean }) {
  const qc = useQueryClient();
  const [apiKey, setApiKey] = useState("");
  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api(`/tools/${tool.name}`, { method: "PATCH", body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tools"] });
      setApiKey("");
    },
  });

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            {tool.display_name}
            <StatusBadge status={tool.health} />
          </span>
        }
        action={
          canEdit && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => patch.mutate({ enabled: !tool.enabled })}
            >
              {tool.enabled ? "Disable" : "Enable"}
            </Button>
          )
        }
      />
      <div className="space-y-2 p-4 text-[13px]">
        <div className="flex flex-wrap gap-1">
          {tool.capabilities.map((c) => (
            <Badge key={c}>{c.replace(/_/g, " ")}</Badge>
          ))}
          <Badge tone={tool.safety_class === "passive" ? "ok" : "warn"}>{tool.safety_class}</Badge>
        </div>
        <Line k="Installed" v={tool.installed_version || "—"} />
        <Line k="Tested against" v={tool.tested_version} />
        <Line k="Minimum" v={tool.min_version} />
        <Line k="Last checked" v={tool.last_checked_at ? timeAgo(tool.last_checked_at) : "never"} />
        {tool.health_detail && (
          <p className="rounded bg-surface-2 px-2 py-1 text-xs text-muted">{tool.health_detail}</p>
        )}
        {canEdit && tool.needs_api_key && (
          <div className="flex gap-2 pt-1">
            <Input
              type="password"
              placeholder={tool.has_api_key ? "API key set — enter to replace" : "API key"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <Button size="sm" onClick={() => patch.mutate({ api_key: apiKey })} disabled={!apiKey}>
              Save
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

function Line({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted">{k}</span>
      <span className="font-mono text-xs">{v}</span>
    </div>
  );
}
