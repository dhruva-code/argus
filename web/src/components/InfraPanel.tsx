"use client";

import { api } from "@/lib/api";
import type { Asset, Port, VHost } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { Badge, Card, CardHeader, EmptyState, Spinner } from "./ui";

const VH_TONE: Record<string, "danger" | "warn" | "accent" | "neutral"> = {
  potential_internal: "danger",
  unusual_response: "warn",
  interesting: "accent",
  default: "neutral",
};

export function InfraPanel({ projectId }: { projectId: string }) {
  const ips = useQuery({
    queryKey: ["assets", projectId, "ip"],
    queryFn: () => api<Asset[]>(`/projects/${projectId}/assets?type=ip&limit=500&sort=value&order=asc`),
    refetchInterval: 6000,
  });
  const asns = useQuery({
    queryKey: ["assets", projectId, "asn"],
    queryFn: () => api<Asset[]>(`/projects/${projectId}/assets?type=asn&limit=200`),
  });
  const vhosts = useQuery({
    queryKey: ["vhosts", projectId],
    queryFn: () => api<VHost[]>(`/projects/${projectId}/vhosts`),
    refetchInterval: 6000,
  });
  const ports = useQuery({
    queryKey: ["ports", projectId],
    queryFn: () => api<Port[]>(`/projects/${projectId}/ports`),
    refetchInterval: 6000,
  });

  const cloudCounts: Record<string, number> = {};
  for (const ip of ips.data ?? []) {
    if (ip.cloud_provider) cloudCounts[ip.cloud_provider] = (cloudCounts[ip.cloud_provider] ?? 0) + 1;
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-4">
        <Card className="p-3">
          <div className="text-xs text-muted">IP addresses</div>
          <div className="mt-1 text-xl font-semibold tabular-nums">{ips.data?.length ?? 0}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs text-muted">Autonomous systems</div>
          <div className="mt-1 text-xl font-semibold tabular-nums">{asns.data?.length ?? 0}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs text-muted">Cloud footprint</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {Object.entries(cloudCounts).length === 0 && <span className="text-sm text-muted">—</span>}
            {Object.entries(cloudCounts).map(([k, v]) => (
              <Badge key={k} tone="accent">
                {k} · {v}
              </Badge>
            ))}
          </div>
        </Card>
        <Card className="p-3">
          <div className="text-xs text-muted">Open ports</div>
          <div className="mt-1 text-xl font-semibold tabular-nums">{ports.data?.length ?? 0}</div>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Open ports & services"
          action={<span className="text-xs text-muted">{ports.data?.length ?? 0} open</span>}
        />
        {!ports.data || ports.data.length === 0 ? (
          <EmptyState
            title="No port scan results"
            hint="The port_service_fingerprint phase runs a bounded naabu connect-scan of in-scope IPs, then nmap -sV for service/version detection."
          />
        ) : (
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">IP</th>
                  <th className="p-2 text-left font-medium">Port</th>
                  <th className="p-2 text-left font-medium">Service</th>
                  <th className="p-2 text-left font-medium">Product / version</th>
                  <th className="p-2 text-left font-medium">HTTP</th>
                  <th className="p-2 text-left font-medium">Hostnames</th>
                </tr>
              </thead>
              <tbody>
                {ports.data.map((p) => (
                  <tr key={p.id} className="border-b border-border last:border-0">
                    <td className="p-2 font-mono text-xs">{p.ip}</td>
                    <td className="p-2 font-mono text-xs">
                      {p.port}/{p.protocol}
                      {p.tls && <Badge tone="accent">TLS</Badge>}
                    </td>
                    <td className="p-2 text-xs">{p.service || "unknown"}</td>
                    <td className="p-2 text-xs text-muted">
                      {[p.product, p.version].filter(Boolean).join(" ") || "—"}
                    </td>
                    <td className="p-2 text-xs text-muted">
                      {p.http_status ? `${p.http_status} ${p.http_title}`.trim() : "—"}
                    </td>
                    <td className="max-w-[200px] truncate p-2 font-mono text-[11px] text-muted">
                      {p.hostnames.join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <CardHeader title="IP addresses & ASN mapping" />
        {ips.isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <Spinner className="h-5 w-5" />
          </div>
        ) : !ips.data || ips.data.length === 0 ? (
          <EmptyState
            title="No infrastructure yet"
            hint="Run a scan with the infrastructure_mapping phase (Deep Recon / Standard Bug Bounty profile)."
          />
        ) : (
          <div className="max-h-[420px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">IP</th>
                  <th className="p-2 text-left font-medium">ASN</th>
                  <th className="p-2 text-left font-medium">Netblock</th>
                  <th className="p-2 text-left font-medium">Cloud</th>
                  <th className="p-2 text-left font-medium">Geo</th>
                  <th className="p-2 text-left font-medium">PTR</th>
                </tr>
              </thead>
              <tbody>
                {ips.data.map((ip) => (
                  <tr key={ip.id} className="border-b border-border last:border-0">
                    <td className="p-2 font-mono text-xs">{ip.value}</td>
                    <td className="p-2 text-xs">
                      {ip.asn ? (
                        <span>
                          <span className="font-mono">{ip.asn}</span>{" "}
                          <span className="text-muted">{ip.asn_org}</span>
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="p-2 font-mono text-xs text-muted">{ip.netblock || "—"}</td>
                    <td className="p-2">
                      {ip.cloud_provider ? <Badge tone="accent">{ip.cloud_provider}</Badge> : "—"}
                    </td>
                    <td className="p-2 text-xs text-muted">{ip.geo_country || "—"}</td>
                    <td className="max-w-[220px] truncate p-2 font-mono text-[11px] text-muted">
                      {ip.ptr || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <CardHeader
          title="Virtual hosts"
          action={<span className="text-xs text-muted">{vhosts.data?.length ?? 0} discovered</span>}
        />
        {!vhosts.data || vhosts.data.length === 0 ? (
          <EmptyState
            title="No virtual hosts"
            hint="The vhost_enum phase compares Host-header responses against a random-Host baseline per IP."
          />
        ) : (
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full text-[13px]">
              <thead className="sticky top-0 bg-surface text-xs text-muted">
                <tr className="border-b border-border">
                  <th className="p-2 text-left font-medium">Hostname</th>
                  <th className="p-2 text-left font-medium">IP</th>
                  <th className="p-2 text-left font-medium">Class</th>
                  <th className="p-2 text-left font-medium">HTTP</th>
                  <th className="p-2 text-right font-medium">Δ baseline</th>
                  <th className="p-2 text-right font-medium">Similarity</th>
                </tr>
              </thead>
              <tbody>
                {vhosts.data.map((v) => (
                  <tr key={v.id} className="border-b border-border last:border-0">
                    <td className="p-2 font-mono text-xs">{v.hostname}</td>
                    <td className="p-2 font-mono text-xs text-muted">{v.ip}</td>
                    <td className="p-2">
                      <Badge tone={VH_TONE[v.classification]}>
                        {v.classification.replace(/_/g, " ")}
                      </Badge>
                    </td>
                    <td className="p-2 text-xs">
                      {v.status_code} · {v.server}
                    </td>
                    <td className="p-2 text-right text-xs text-muted">
                      {v.baseline_status}→{v.status_code} · {v.baseline_bytes}→{v.response_bytes}B
                    </td>
                    <td className="p-2 text-right tabular-nums">
                      {(v.similarity * 100).toFixed(0)}%
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
