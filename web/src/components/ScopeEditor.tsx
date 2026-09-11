"use client";

import { api } from "@/lib/api";
import type { ScopeMatcher, ScopeRule } from "@/lib/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Badge, Button, Card, CardHeader, Input, Select, Spinner } from "./ui";

const MATCHERS: ScopeMatcher[] = [
  "domain",
  "subdomain",
  "wildcard",
  "cidr",
  "ip",
  "asn",
  "url",
  "regex",
];

const BLANK: ScopeRule = {
  effect: "allow",
  matcher: "wildcard",
  value: "",
  ports: [],
  paths: [],
  note: "",
};

export function ScopeEditor({ projectId, canEdit }: { projectId: string; canEdit: boolean }) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["scope", projectId],
    queryFn: () => api<ScopeRule[]>(`/projects/${projectId}/scope`),
  });
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (data) {
      setRules(data.map((r) => ({ ...r, ports: r.ports ?? [], paths: r.paths ?? [] })));
      setDirty(false);
    }
  }, [data]);

  const save = useMutation({
    mutationFn: () =>
      api(`/projects/${projectId}/scope`, {
        method: "PUT",
        body: { rules: rules.map((r) => ({ ...r, note: r.note ?? "" })) },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scope", projectId] });
      qc.invalidateQueries({ queryKey: ["projects"] });
      setDirty(false);
    },
  });

  function update(i: number, patch: Partial<ScopeRule>) {
    setRules((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
    setDirty(true);
  }
  function remove(i: number) {
    setRules((rs) => rs.filter((_, j) => j !== i));
    setDirty(true);
  }
  function add() {
    setRules((rs) => [...rs, { ...BLANK }]);
    setDirty(true);
  }

  if (isLoading) return <Spinner className="h-5 w-5" />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Scope policy"
          action={
            canEdit && (
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={add}>
                  Add rule
                </Button>
                <Button size="sm" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
                  {save.isPending ? "Saving…" : "Save policy"}
                </Button>
              </div>
            )
          }
        />
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="text-xs text-muted">
              <tr className="border-b border-border">
                <th className="p-2 text-left font-medium">Effect</th>
                <th className="p-2 text-left font-medium">Matcher</th>
                <th className="p-2 text-left font-medium">Value</th>
                <th className="p-2 text-left font-medium">Ports</th>
                <th className="p-2 text-left font-medium">Paths</th>
                <th className="p-2 text-left font-medium">Note</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-xs text-muted">
                    No rules — the policy denies everything. Add an allow rule to define scope.
                  </td>
                </tr>
              )}
              {rules.map((r, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  <td className="p-2">
                    <Select
                      value={r.effect}
                      disabled={!canEdit}
                      onChange={(e) => update(i, { effect: e.target.value as "allow" | "deny" })}
                    >
                      <option value="allow">allow</option>
                      <option value="deny">deny</option>
                    </Select>
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.matcher}
                      disabled={!canEdit}
                      onChange={(e) => update(i, { matcher: e.target.value as ScopeMatcher })}
                    >
                      {MATCHERS.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </Select>
                  </td>
                  <td className="p-2">
                    <Input
                      value={r.value}
                      disabled={!canEdit}
                      placeholder="*.example.com"
                      onChange={(e) => update(i, { value: e.target.value })}
                    />
                  </td>
                  <td className="p-2">
                    <Input
                      className="w-24"
                      disabled={!canEdit}
                      value={(r.ports ?? []).join(",")}
                      placeholder="443,80"
                      onChange={(e) =>
                        update(i, {
                          ports: e.target.value
                            .split(",")
                            .map((s) => parseInt(s.trim(), 10))
                            .filter((n) => !isNaN(n)),
                        })
                      }
                    />
                  </td>
                  <td className="p-2">
                    <Input
                      className="w-28"
                      disabled={!canEdit}
                      value={(r.paths ?? []).join(",")}
                      placeholder="/api/"
                      onChange={(e) =>
                        update(i, {
                          paths: e.target.value
                            .split(",")
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                    />
                  </td>
                  <td className="p-2">
                    <Input
                      value={r.note ?? ""}
                      disabled={!canEdit}
                      onChange={(e) => update(i, { note: e.target.value })}
                    />
                  </td>
                  <td className="p-2">
                    {canEdit && (
                      <Button size="sm" variant="ghost" onClick={() => remove(i)}>
                        ✕
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {save.error && (
          <p className="border-t border-border px-4 py-2 text-xs text-critical">
            {String((save.error as any).message)}
          </p>
        )}
      </Card>

      <ScopeTester projectId={projectId} />
    </div>
  );
}

function ScopeTester({ projectId }: { projectId: string }) {
  const [t, setT] = useState({ host: "", ip: "", port: "", path: "", asn: "" });
  const m = useMutation({
    mutationFn: () =>
      api<{ allowed: boolean; rule_id: string; reason: string }>(
        `/projects/${projectId}/scope/test`,
        {
          method: "POST",
          body: {
            host: t.host,
            ip: t.ip,
            port: t.port ? parseInt(t.port, 10) : 0,
            path: t.path,
            asn: t.asn,
          },
        },
      ),
  });
  return (
    <Card>
      <CardHeader title="Test a target against the policy" />
      <div className="flex flex-wrap items-end gap-2 p-4">
        <Field label="Host" value={t.host} onChange={(v) => setT({ ...t, host: v })} />
        <Field label="IP" value={t.ip} onChange={(v) => setT({ ...t, ip: v })} />
        <Field label="Port" value={t.port} onChange={(v) => setT({ ...t, port: v })} w="w-20" />
        <Field label="Path" value={t.path} onChange={(v) => setT({ ...t, path: v })} />
        <Field label="ASN" value={t.asn} onChange={(v) => setT({ ...t, asn: v })} w="w-24" />
        <Button onClick={() => m.mutate()} disabled={m.isPending}>
          Evaluate
        </Button>
        {m.data && (
          <div className="flex items-center gap-2">
            <Badge tone={m.data.allowed ? "ok" : "danger"}>
              {m.data.allowed ? "IN SCOPE" : "OUT OF SCOPE"}
            </Badge>
            <span className="text-xs text-muted">{m.data.reason}</span>
          </div>
        )}
      </div>
    </Card>
  );
}

function Field({
  label,
  value,
  onChange,
  w = "w-44",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  w?: string;
}) {
  return (
    <div className={w}>
      <label className="mb-1 block text-xs text-muted">{label}</label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
