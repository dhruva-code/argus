"use client";

import { api } from "@/lib/api";
import type { AuthProfile } from "@/lib/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Button, Card, CardHeader, EmptyState, Input, Select, Spinner } from "./ui";

interface InjectionOverview {
  total_points: number;
  tested_points: number;
  untested_points: number;
  coverage_pct: number;
  by_result: Record<string, number>;
  by_class: Record<string, { candidates: number; tested: number; coverage_pct: number }>;
}

interface InjectionPoint {
  id: string;
  method: string;
  url: string;
  host: string;
  param_name: string;
  location: string;
  param_type: string;
  context: string;
  technology: string;
  auth_state: string;
  candidate_classes: string[];
  tested_classes: string[];
  best_result: string;
  confidence: number;
  last_tested: string | null;
}

const RESULT_TONE: Record<string, "ok" | "warn" | "danger" | "neutral" | "accent"> = {
  untested: "neutral",
  none: "ok",
  potential: "neutral",
  likely: "warn",
  verified: "danger",
};

export function InjectionPanel({
  projectId,
  canRun,
  canManageAuth,
}: {
  projectId: string;
  canRun: boolean;
  canManageAuth: boolean;
}) {
  const [bestResult, setBestResult] = useState("");
  const [cls, setCls] = useState("");
  const qc = useQueryClient();

  const overview = useQuery({
    queryKey: ["injection-overview", projectId],
    queryFn: () => api<InjectionOverview>(`/projects/${projectId}/injection/overview`),
    refetchInterval: 10000,
  });

  const query = new URLSearchParams({ limit: "300" });
  if (bestResult) query.set("best_result", bestResult);
  if (cls) query.set("injection_class", cls);

  const points = useQuery({
    queryKey: ["injection-points", projectId, bestResult, cls],
    queryFn: () => api<InjectionPoint[]>(`/projects/${projectId}/injection-points?${query.toString()}`),
    refetchInterval: 10000,
  });

  const retest = useMutation({
    mutationFn: (pointId: string) =>
      api(`/projects/${projectId}/injection-points/${pointId}/retest`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["injection-points", projectId] }),
  });

  const o = overview.data;
  const classes = Object.keys(o?.by_class ?? {}).sort();

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Parameters classified" value={o?.total_points ?? 0} />
        <Stat label="Tested" value={o?.tested_points ?? 0} />
        <Stat label="Untested" value={o?.untested_points ?? 0} tone="warn" />
        <Stat label="Likely" value={o?.by_result?.likely ?? 0} tone="warn" />
        <Stat label="Verified" value={o?.by_result?.verified ?? 0} tone="danger" />
      </div>

      <Card className="p-3">
        <div className="mb-1 flex items-center justify-between">
          <div className="text-xs text-muted">Testing coverage</div>
          <div className="text-xs font-medium">
            {o ? `${o.coverage_pct}% of classified parameters tested` : "—"}
          </div>
        </div>
        {classes.length === 0 ? (
          <p className="text-xs text-muted">
            No parameters classified yet — run a scan profile with the injection_testing phase
            enabled (e.g. “Injection Discovery”) and confirm active testing is authorized.
          </p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {classes.map((c) => {
              const stat = o!.by_class[c];
              return (
                <button key={c} onClick={() => setCls(cls === c ? "" : c)}>
                  <Badge tone={cls === c ? "accent" : "neutral"}>
                    {c.replace(/_/g, " ")} · {stat.tested}/{stat.candidates} ({stat.coverage_pct}%)
                  </Badge>
                </button>
              );
            })}
          </div>
        )}
        <p className="mt-2 text-[11px] text-muted">
          Coverage reflects only what this project&apos;s scans have actually tested — never
          reported as complete unless every classified parameter in that class was tested.
        </p>
      </Card>

      <Card>
        <CardHeader
          title="Injection point explorer"
          action={
            <Select className="h-7" value={bestResult} onChange={(e) => setBestResult(e.target.value)}>
              <option value="">any result</option>
              {["untested", "none", "potential", "likely", "verified"].map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </Select>
          }
        />
        {points.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !points.data || points.data.length === 0 ? (
          <EmptyState
            title="No injection points yet"
            hint="Run a scan profile with the injection_testing phase enabled and confirm active testing is authorized when prompted."
          />
        ) : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Param</th>
                  <th className="p-2 text-left font-medium">Endpoint</th>
                  <th className="p-2 text-left font-medium">Candidate classes</th>
                  <th className="p-2 text-left font-medium">Result</th>
                  <th className="p-2 text-left font-medium">Confidence</th>
                  {canRun && <th className="p-2" />}
                </tr>
              </thead>
              <tbody>
                {points.data.map((p) => (
                  <tr key={p.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                    <td className="p-2">
                      <div className="font-mono text-xs">{p.param_name}</div>
                      <div className="text-[11px] text-muted">
                        {p.location}
                        {p.param_type ? ` · ${p.param_type}` : ""}
                      </div>
                    </td>
                    <td className="p-2">
                      <Badge>{p.method}</Badge> <span className="font-mono text-xs">{p.url}</span>
                    </td>
                    <td className="p-2">
                      <div className="flex flex-wrap gap-0.5">
                        {p.candidate_classes.map((c) => (
                          <Badge key={c}>{c.replace(/_/g, " ")}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="p-2">
                      <Badge tone={RESULT_TONE[p.best_result] ?? "neutral"}>{p.best_result}</Badge>
                    </td>
                    <td className="p-2 text-xs tabular-nums">{p.confidence}</td>
                    {canRun && (
                      <td className="p-2">
                        <Button
                          variant="outline"
                          className="h-6 px-2 text-[11px]"
                          disabled={retest.isPending}
                          onClick={() => retest.mutate(p.id)}
                        >
                          Re-test
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <AuthProfilesCard projectId={projectId} canManage={canManageAuth} />
    </div>
  );
}

function AuthProfilesCard({ projectId, canManage }: { projectId: string; canManage: boolean }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<AuthProfile["kind"]>("bearer");
  const [headerName, setHeaderName] = useState("");
  const [cookieName, setCookieName] = useState("");
  const [value, setValue] = useState("");

  const profiles = useQuery({
    queryKey: ["auth-profiles", projectId],
    queryFn: () => api<AuthProfile[]>(`/projects/${projectId}/auth-profiles`),
  });

  const reset = () => {
    setName("");
    setValue("");
    setHeaderName("");
    setCookieName("");
  };

  const create = useMutation({
    mutationFn: () =>
      api<AuthProfile>(`/projects/${projectId}/auth-profiles`, {
        method: "POST",
        body: {
          name,
          kind,
          header_name: headerName,
          cookie_name: cookieName,
          location: kind === "cookie" ? "cookie" : "header",
          value,
        },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["auth-profiles", projectId] });
      setOpen(false);
      reset();
    },
  });

  const del = useMutation({
    mutationFn: (id: string) => api(`/projects/${projectId}/auth-profiles/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["auth-profiles", projectId] }),
  });

  return (
    <Card>
      <CardHeader
        title="Authentication profiles"
        action={
          canManage && (
            <Button variant="outline" className="h-7" onClick={() => setOpen(true)}>
              + New
            </Button>
          )
        }
      />
      <div className="px-4 pt-3 text-[13px] text-muted">
        Attach one of these to a scan (Authenticated DAST) so the Injection Testing Engine tests
        behind a login. Secret values are encrypted at rest and never shown again after creation.
      </div>
      {!profiles.data || profiles.data.length === 0 ? (
        <div className="px-4 pb-4 pt-2">
          <EmptyState title="No authentication profiles yet" />
        </div>
      ) : (
        <div className="mt-2 divide-y divide-border">
          {profiles.data.map((p) => (
            <div key={p.id} className="flex items-center justify-between px-4 py-2 text-[13px]">
              <div>
                <span className="font-medium">{p.name}</span>{" "}
                <span className="text-xs text-muted">
                  {p.kind} · {p.location}
                  {p.header_name ? ` · ${p.header_name}` : ""}
                </span>
              </div>
              {canManage && (
                <Button
                  variant="outline"
                  className="h-6 px-2 text-[11px]"
                  onClick={() => del.mutate(p.id)}
                >
                  Delete
                </Button>
              )}
            </div>
          ))}
        </div>
      )}

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md p-5">
            <h3 className="text-sm font-semibold">New authentication profile</h3>
            <div className="mt-3 space-y-2">
              <div>
                <label className="mb-1 block text-xs text-muted">Name</label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. standard user" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted">Kind</label>
                <Select value={kind} onChange={(e) => setKind(e.target.value as AuthProfile["kind"])}>
                  <option value="bearer">Bearer token</option>
                  <option value="basic">Basic auth</option>
                  <option value="api_key">API key (custom header)</option>
                  <option value="cookie">Session cookie</option>
                  <option value="oauth_session">OAuth session token</option>
                </Select>
              </div>
              {kind === "api_key" && (
                <div>
                  <label className="mb-1 block text-xs text-muted">Header name</label>
                  <Input
                    value={headerName}
                    onChange={(e) => setHeaderName(e.target.value)}
                    placeholder="X-API-Key"
                  />
                </div>
              )}
              {kind === "cookie" && (
                <div>
                  <label className="mb-1 block text-xs text-muted">Cookie name</label>
                  <Input
                    value={cookieName}
                    onChange={(e) => setCookieName(e.target.value)}
                    placeholder="session"
                  />
                </div>
              )}
              <div>
                <label className="mb-1 block text-xs text-muted">
                  {kind === "basic" ? "Base64 user:pass" : kind === "cookie" ? "Cookie value" : "Token / key value"}
                </label>
                <Input value={value} onChange={(e) => setValue(e.target.value)} type="password" />
              </div>
            </div>
            {create.error && (
              <p className="mt-2 text-xs text-critical">{String((create.error as any).message)}</p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button disabled={create.isPending || !name || !value} onClick={() => create.mutate()}>
                {create.isPending ? "Saving…" : "Save"}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </Card>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "danger" | "warn" }) {
  const c = tone === "danger" ? "text-critical" : tone === "warn" ? "text-medium" : "text-fg";
  return (
    <Card className="p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${c}`}>{value}</div>
    </Card>
  );
}
