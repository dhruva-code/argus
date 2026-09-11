"use client";

import { Badge, Button, Card, EmptyState, Input, Label, Select, Spinner, Textarea } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { Project } from "@/lib/types";
import { timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

export default function ProjectsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Project[]>("/projects"),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Projects</h1>
        {can("project.write") && (
          <Button onClick={() => setCreating((v) => !v)}>{creating ? "Cancel" : "New project"}</Button>
        )}
      </div>

      {creating && <CreateForm onDone={() => { setCreating(false); qc.invalidateQueries({ queryKey: ["projects"] }); }} />}

      {isLoading ? (
        <div className="flex h-40 items-center justify-center">
          <Spinner className="h-5 w-5" />
        </div>
      ) : !data || data.length === 0 ? (
        <Card>
          <EmptyState
            title="No projects"
            hint="A project holds an authorized scope, targets, scan profiles and findings."
          />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {data.map((p) => (
            <Link key={p.id} href={`/projects/${p.id}`}>
              <Card className="h-full p-4 transition hover:border-accent">
                <div className="flex items-start justify-between">
                  <h3 className="font-medium">{p.name}</h3>
                  <Badge tone={p.risk_profile === "critical" || p.risk_profile === "high" ? "danger" : "neutral"}>
                    {p.risk_profile}
                  </Badge>
                </div>
                {p.program_name && <p className="mt-0.5 text-xs text-muted">{p.program_name}</p>}
                <p className="mt-3 line-clamp-2 text-xs text-muted">
                  {p.description || "No description."}
                </p>
                <div className="mt-3 flex items-center justify-between text-[11px] text-muted">
                  <span>{p.scope_rule_count} scope rule(s)</span>
                  <span>updated {timeAgo(p.updated_at)}</span>
                </div>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function CreateForm({ onDone }: { onDone: () => void }) {
  const [form, setForm] = useState({
    name: "",
    program_name: "",
    client: "",
    program_url: "",
    description: "",
    rules_of_engagement: "",
    risk_profile: "moderate",
  });
  const m = useMutation({
    mutationFn: () => api<Project>("/projects", { method: "POST", body: form }),
    onSuccess: onDone,
  });
  const set = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <Card className="space-y-3 p-4">
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <Label>Project name *</Label>
          <Input value={form.name} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div>
          <Label>Program name</Label>
          <Input value={form.program_name} onChange={(e) => set("program_name", e.target.value)} />
        </div>
        <div>
          <Label>Client</Label>
          <Input value={form.client} onChange={(e) => set("client", e.target.value)} />
        </div>
        <div>
          <Label>Program URL</Label>
          <Input value={form.program_url} onChange={(e) => set("program_url", e.target.value)} />
        </div>
        <div>
          <Label>Risk profile</Label>
          <Select
            value={form.risk_profile}
            onChange={(e) => set("risk_profile", e.target.value)}
            className="w-full"
          >
            <option value="low">Low</option>
            <option value="moderate">Moderate</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </Select>
        </div>
      </div>
      <div>
        <Label>Description</Label>
        <Textarea rows={2} value={form.description} onChange={(e) => set("description", e.target.value)} />
      </div>
      <div>
        <Label>Rules of engagement</Label>
        <Textarea
          rows={3}
          value={form.rules_of_engagement}
          onChange={(e) => set("rules_of_engagement", e.target.value)}
        />
      </div>
      {m.error && <p className="text-xs text-critical">{String((m.error as any).message)}</p>}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button disabled={form.name.length < 2 || m.isPending} onClick={() => m.mutate()}>
          {m.isPending ? "Creating…" : "Create project"}
        </Button>
      </div>
    </Card>
  );
}
