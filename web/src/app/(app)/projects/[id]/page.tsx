"use client";

import { AnalyticsPanel } from "@/components/AnalyticsPanel";
import { AssetsPanel } from "@/components/AssetsPanel";
import { EndpointsPanel } from "@/components/EndpointsPanel";
import { WaybackPanel } from "@/components/WaybackPanel";
import { FindingsPanel } from "@/components/FindingsPanel";
import { GraphPanel } from "@/components/GraphPanel";
import { InfraPanel } from "@/components/InfraPanel";
import { InjectionPanel } from "@/components/InjectionPanel";
import { ScopeEditor } from "@/components/ScopeEditor";
import { SecretsPanel } from "@/components/SecretsPanel";
import { SettingsPanel } from "@/components/SettingsPanel";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Select,
  Spinner,
  StatusBadge,
  Tabs,
} from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api, apiText } from "@/lib/api";
import type { AuthProfile, ExposureDelta, Job, Project, ScanProfile } from "@/lib/types";
import { fmtDate, timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const { can } = useAuth();
  const [tab, setTab] = useState("overview");

  const { data: project, isLoading } = useQuery({
    queryKey: ["project", id],
    queryFn: () => api<Project>(`/projects/${id}`),
  });

  if (isLoading || !project)
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner className="h-6 w-6" />
      </div>
    );

  return (
    <div className="space-y-4">
      <div>
        <Link href="/projects" className="text-xs text-muted hover:text-fg">
          ← Projects
        </Link>
        <div className="mt-1 flex items-center gap-2">
          <h1 className="text-lg font-semibold">{project.name}</h1>
          <Badge tone={["high", "critical"].includes(project.risk_profile) ? "danger" : "neutral"}>
            {project.risk_profile} risk
          </Badge>
        </div>
        {project.program_name && <p className="text-xs text-muted">{project.program_name}</p>}
      </div>

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { key: "overview", label: "Overview" },
          { key: "scope", label: `Scope (${project.scope_rule_count})` },
          { key: "assets", label: "Assets" },
          { key: "graph", label: "Graph" },
          { key: "infra", label: "Infrastructure" },
          { key: "endpoints", label: "Endpoints" },
          { key: "wayback", label: "Wayback URLs" },
          { key: "injection", label: "Injection Testing" },
          { key: "secrets", label: "Secrets & Source" },
          { key: "findings", label: "Findings" },
          { key: "analytics", label: "Analytics" },
          { key: "jobs", label: "Scan Jobs" },
          { key: "settings", label: "Settings" },
        ]}
      />

      {tab === "overview" && <Overview project={project} />}
      {tab === "scope" && <ScopeEditor projectId={id} canEdit={can("scope.write")} />}
      {tab === "assets" && <AssetsPanel projectId={id} />}
      {tab === "graph" && <GraphPanel projectId={id} />}
      {tab === "infra" && <InfraPanel projectId={id} />}
      {tab === "endpoints" && <EndpointsPanel projectId={id} />}
      {tab === "wayback" && <WaybackPanel projectId={id} />}
      {tab === "injection" && (
        <InjectionPanel
          projectId={id}
          canRun={can("scan.execute")}
          canManageAuth={can("auth_profile.manage")}
        />
      )}
      {tab === "secrets" && <SecretsPanel projectId={id} />}
      {tab === "findings" && <FindingsPanel projectId={id} canModify={can("finding.modify")} />}
      {tab === "analytics" && <AnalyticsPanel projectId={id} />}
      {tab === "jobs" && (
        <JobsTab
          projectId={id}
          canRun={can("scan.execute")}
          canDelete={can("scan.cancel")}
          canPurge={can("project.write")}
        />
      )}
      {tab === "settings" && (
        <SettingsPanel
          project={project}
          canDelete={can("project.write")}
          canPurgePermanently={can("settings.modify")}
        />
      )}
    </div>
  );
}

function Overview({ project }: { project: Project }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="Program" />
        <dl className="divide-y divide-border text-[13px]">
          <Row k="Client" v={project.client || "—"} />
          <Row k="Program URL" v={project.program_url || "—"} />
          <Row k="Risk profile" v={project.risk_profile} />
          <Row k="Schedule" v={project.schedule_cron || "not scheduled"} />
          <Row k="Created" v={fmtDate(project.created_at)} />
        </dl>
      </Card>
      <ReportCard projectId={project.id} />
      <ExposureDeltaCard projectId={project.id} />
      <Card>
        <CardHeader title="Description" />
        <p className="whitespace-pre-wrap p-4 text-[13px] text-muted">
          {project.description || "No description."}
        </p>
      </Card>
      <Card className="lg:col-span-2">
        <CardHeader title="Rules of engagement" />
        <p className="whitespace-pre-wrap p-4 text-[13px] text-muted">
          {project.rules_of_engagement || "Not documented."}
        </p>
      </Card>
    </div>
  );
}

function ReportCard({ projectId }: { projectId: string }) {
  const [busy, setBusy] = useState("");
  const get = async (fmt: string) => {
    setBusy(fmt);
    try {
      const { body, contentType, blob } = await apiText(
        `/projects/${projectId}/report?format=${fmt}`,
        fmt === "pdf",
      );
      const b = blob ?? new Blob([body], { type: contentType });
      const url = URL.createObjectURL(b);
      if (fmt === "html") {
        window.open(url, "_blank");
      } else {
        const a = document.createElement("a");
        a.href = url;
        a.download = `argus-report.${fmt}`;
        a.click();
      }
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } finally {
      setBusy("");
    }
  };
  return (
    <Card>
      <CardHeader title="Assessment report" />
      <div className="space-y-3 p-4 text-[13px]">
        <p className="text-muted">
          Rolls the current attack surface + priority-ranked findings into one document. Secret
          values are never included.
        </p>
        <div className="flex flex-wrap gap-2">
          {["html", "pdf", "md", "csv", "json"].map((f) => (
            <Button key={f} variant="outline" disabled={!!busy} onClick={() => get(f)}>
              {busy === f ? "…" : f === "html" ? "View HTML" : f.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>
    </Card>
  );
}

function ExposureDeltaCard({ projectId }: { projectId: string }) {
  const { data } = useQuery({
    queryKey: ["exposure-delta", projectId],
    queryFn: () => api<ExposureDelta>(`/projects/${projectId}/exposure-delta`),
    refetchInterval: 15000,
  });
  return (
    <Card>
      <CardHeader title="What changed since the last scan" />
      <div className="p-4 text-[13px]">
        {!data?.has_baseline ? (
          <p className="text-muted">Run at least two scans to see the exposure delta.</p>
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-x-5 gap-y-1">
              <Delta n={data.counts.new_findings} label="new findings" tone="danger" />
              <Delta n={data.counts.new_assets} label="new assets" />
              <Delta n={data.counts.new_ports} label="new ports" />
              <Delta n={data.counts.new_secrets} label="new secrets" tone="danger" />
              <Delta n={data.counts.resolved_findings} label="findings resolved" tone="ok" />
              <Delta n={data.counts.resolved_assets} label="assets gone" tone="ok" />
            </div>
            {(data.new.findings ?? []).slice(0, 5).map((f, i) => (
              <div key={i} className="text-xs text-muted">
                <span className="text-fg">+ {f.severity}</span> {f.name} · {f.host}
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

function Delta({ n, label, tone }: { n?: number; label: string; tone?: "danger" | "ok" }) {
  const c = !n ? "text-muted" : tone === "danger" ? "text-critical" : tone === "ok" ? "text-ok" : "text-fg";
  return (
    <span className="text-xs">
      <span className={`font-semibold tabular-nums ${c}`}>{n ?? 0}</span>{" "}
      <span className="text-muted">{label}</span>
    </span>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between px-4 py-2">
      <dt className="text-muted">{k}</dt>
      <dd className="font-medium">{v}</dd>
    </div>
  );
}

function AckRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 py-1.5">
      <dt className="shrink-0 text-muted">{k}</dt>
      <dd className="text-right font-medium">{v || "—"}</dd>
    </div>
  );
}

const TERMINAL = new Set(["completed", "failed", "cancelled", "partially_completed"]);

function JobsTab({
  projectId,
  canRun,
  canDelete,
  canPurge,
}: {
  projectId: string;
  canRun: boolean;
  canDelete: boolean;
  canPurge: boolean;
}) {
  const qc = useQueryClient();
  const router = useRouter();
  const { data: jobs } = useQuery({
    queryKey: ["project-jobs", projectId],
    queryFn: () => api<Job[]>(`/projects/${projectId}/jobs`),
    refetchInterval: 5000,
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [purge, setPurge] = useState(false);
  const [delOpen, setDelOpen] = useState(false);

  const del = useMutation({
    mutationFn: () =>
      api<{ deleted: number; purged: Record<string, number>; skipped: string[] }>(
        `/projects/${projectId}/scans/delete`,
        { method: "POST", body: { job_ids: [...selected], purge_data: purge } },
      ),
    onSuccess: () => {
      setSelected(new Set());
      setPurge(false);
      setDelOpen(false);
      qc.invalidateQueries();
    },
  });

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const deletableIds = (jobs ?? []).filter((j) => TERMINAL.has(j.status)).map((j) => j.id);
  const allSelected = deletableIds.length > 0 && deletableIds.every((id) => selected.has(id));
  const { data: profiles } = useQuery({
    queryKey: ["scan-profiles"],
    queryFn: () => api<ScanProfile[]>("/scan-profiles"),
  });

  const [type, setType] = useState("recon.scan");
  const [profileKey, setProfileKey] = useState("standard_bug_bounty");
  const [bruteforce, setBruteforce] = useState(true);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [injectionAck, setInjectionAck] = useState(false);
  const [ssrfAck, setSsrfAck] = useState(false);
  const [authProfileId, setAuthProfileId] = useState("");
  const activeProfile = profiles?.find((p) => p.key === profileKey);
  const isActive = type === "recon.scan";
  const needsInjectionAck = !!activeProfile?.phases.injection_testing;

  const { data: authProfiles } = useQuery({
    queryKey: ["auth-profiles", projectId],
    queryFn: () => api<AuthProfile[]>(`/projects/${projectId}/auth-profiles`),
    enabled: needsInjectionAck,
  });

  const run = useMutation({
    mutationFn: () => {
      let params: Record<string, unknown> = {};
      if (type === "scope.selftest")
        params = { targets: [{ host: "www.example.com" }, { host: "admin.example.com" }] };
      else if (type === "recon.scan") {
        params = { profile_key: profileKey, bruteforce };
        if (needsInjectionAck) {
          params.injection_ack = injectionAck;
          params.ssrf_ack = ssrfAck;
        }
        if (authProfileId) params.auth_profile_id = authProfileId;
      }
      return api<Job>(`/projects/${projectId}/jobs`, {
        method: "POST",
        body: { type, params, authorization_ack: true },
      });
    },
    onSuccess: (j) => {
      setConfirmOpen(false);
      qc.invalidateQueries({ queryKey: ["project-jobs", projectId] });
      router.push(`/jobs/${j.id}`);
    },
  });

  return (
    <div className="space-y-4">
      {canRun && (
        <Card className="space-y-3 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="mb-1 block text-xs text-muted">Job type</label>
              <Select value={type} onChange={(e) => setType(e.target.value)}>
                <option value="recon.scan">Reconnaissance scan</option>
                <option value="scope.selftest">Scope self-test (no network)</option>
                <option value="tool.health">Tool health check</option>
              </Select>
            </div>
            {isActive && (
              <>
                <div>
                  <label className="mb-1 block text-xs text-muted">Scan profile</label>
                  <Select value={profileKey} onChange={(e) => setProfileKey(e.target.value)}>
                    {(profiles ?? [])
                      .filter((p) => p.key !== "passive_only" || true)
                      .map((p) => (
                        <option key={p.key} value={p.key}>
                          {p.name}
                        </option>
                      ))}
                  </Select>
                </div>
                <label className="flex items-center gap-1 pb-1.5 text-xs text-muted">
                  <input
                    type="checkbox"
                    checked={bruteforce}
                    onChange={(e) => setBruteforce(e.target.checked)}
                  />
                  permutation bruteforce
                </label>
              </>
            )}
            <Button
              onClick={() => (isActive ? setConfirmOpen(true) : run.mutate())}
              disabled={run.isPending}
            >
              {run.isPending ? "Queuing…" : isActive ? "Review & run scan" : "Run job"}
            </Button>
          </div>
          {isActive && activeProfile && (
            <p className="text-xs text-muted">
              {activeProfile.description} Phases:{" "}
              {Object.entries(activeProfile.phases)
                .filter(([, v]) => v)
                .map(([k]) => k.replace(/_/g, " "))
                .join(", ") || "none"}
              .
            </p>
          )}
        </Card>
      )}

      {confirmOpen && activeProfile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-lg p-5">
            <h3 className="text-sm font-semibold">Authorize active reconnaissance</h3>
            <dl className="my-3 divide-y divide-border text-[13px]">
              <AckRow k="Target" v="project scope (root domains from allow rules)" />
              <AckRow k="Scan profile" v={activeProfile.name} />
              <AckRow
                k="Phases"
                v={Object.entries(activeProfile.phases)
                  .filter(([, v]) => v)
                  .map(([k]) => k.replace(/_/g, " "))
                  .join(", ") || "none"}
              />
              <AckRow
                k="Rate limits"
                v={`${activeProfile.rate_limits.requests_per_second ?? "?"} req/s · ${
                  activeProfile.rate_limits.dns_per_second ?? "?"
                } dns/s · max ${activeProfile.rate_limits.max_targets ?? "?"} targets`}
              />
              <AckRow k="Bruteforce" v={bruteforce ? "enabled (in-scope roots only)" : "disabled"} />
            </dl>
            <p className="rounded bg-surface-2 p-2 text-xs text-muted">
              Only hosts that pass the scope engine and the SSRF guard are actively probed.
              Passive enumeration may surface out-of-scope hosts; they are recorded but never
              contacted.
            </p>

            {needsInjectionAck && (
              <div className="mt-3 space-y-2 rounded border border-critical/40 bg-critical/5 p-3">
                <p className="text-xs text-critical">
                  The &quot;injection_testing&quot; phase actively tests discovered parameters for
                  SQLi / XSS / command injection / LFI / SSRF / other injection classes — this
                  sends live payloads to the target.
                </p>
                <label className="flex items-start gap-2 text-[13px]">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={injectionAck}
                    onChange={(e) => setInjectionAck(e.target.checked)}
                  />
                  <span>I confirm this target is authorized for active injection testing.</span>
                </label>
                <label className="flex items-start gap-2 text-[13px] text-muted">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={ssrfAck}
                    onChange={(e) => setSsrfAck(e.target.checked)}
                  />
                  <span>
                    Also test SSRF / RFI via out-of-band callback (requires an OAST collector
                    configured server-side; silently skipped otherwise).
                  </span>
                </label>
                <div>
                  <label className="mb-1 block text-xs text-muted">
                    Authentication profile (optional — tests behind a login)
                  </label>
                  <Select value={authProfileId} onChange={(e) => setAuthProfileId(e.target.value)}>
                    <option value="">unauthenticated</option>
                    {(authProfiles ?? []).map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.kind})
                      </option>
                    ))}
                  </Select>
                  {(!authProfiles || authProfiles.length === 0) && (
                    <p className="mt-1 text-[11px] text-muted">
                      No profiles yet — add one in the Injection Testing tab.
                    </p>
                  )}
                </div>
              </div>
            )}

            {run.error && (
              <p className="mt-2 text-xs text-critical">{String((run.error as any).message)}</p>
            )}
            <label className="mt-3 flex items-start gap-2 text-[13px]">
              <input type="checkbox" id="ack" className="mt-0.5" />
              <span>I confirm that these targets are authorized for active security testing.</span>
            </label>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setConfirmOpen(false)}>
                Cancel
              </Button>
              <Button
                disabled={run.isPending || (needsInjectionAck && !injectionAck)}
                onClick={() => {
                  const ack = document.getElementById("ack") as HTMLInputElement | null;
                  if (ack?.checked) run.mutate();
                }}
              >
                {run.isPending ? "Queuing…" : "Start scan"}
              </Button>
            </div>
          </Card>
        </div>
      )}

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
                  onChange={(e) =>
                    setSelected(e.target.checked ? new Set(deletableIds) : new Set())
                  }
                />
                select all finished
              </label>
            ) : undefined
          }
        />
        <div className="divide-y divide-border">
          {(!jobs || jobs.length === 0) && <EmptyState title="No jobs for this project" />}
          {jobs?.map((j) => {
            const canPick = canDelete && TERMINAL.has(j.status);
            return (
              <div
                key={j.id}
                className="flex items-center gap-3 px-4 py-2.5 text-[13px] hover:bg-surface-2"
              >
                <input
                  type="checkbox"
                  className="shrink-0"
                  disabled={!canPick}
                  checked={selected.has(j.id)}
                  onChange={() => toggle(j.id)}
                />
                <Link href={`/jobs/${j.id}`} className="flex flex-1 items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs">{j.type}</span>
                    <span className="text-xs text-muted">
                      {j.result_count} results · {j.error_count} errors
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted">{timeAgo(j.created_at)}</span>
                    <StatusBadge status={j.status} />
                  </div>
                </Link>
              </div>
            );
          })}
        </div>
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
            {del.error && (
              <p className="mt-2 text-xs text-critical">{String((del.error as any).message)}</p>
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
