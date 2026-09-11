"use client";

import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Badge, Button, Select } from "./ui";

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/projects", label: "Projects" },
  { href: "/jobs", label: "Scan Jobs" },
  { href: "/audit", label: "Audit Logs" },
];

// Kept visually separate from operational scan functionality above (§64) —
// system status and account configuration, not recon/scan work.
const NAV_SYSTEM = [
  { href: "/system", label: "System Health" },
  { href: "/tools", label: "Tools" },
  { href: "/settings", label: "Settings" },
];

function VersionFooter() {
  const { data } = useQuery({
    queryKey: ["version"],
    queryFn: () => api<{ version: string; env: string }>("/version"),
    staleTime: Infinity,
  });
  return (
    <div className="border-t border-border p-2 text-[11px] text-muted">
      {data ? `Argus v${data.version}${data.env !== "production" ? ` · ${data.env}` : ""}` : "Argus"}
    </div>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>("system");
  useEffect(() => {
    setTheme(localStorage.getItem("argus.theme") ?? "system");
  }, []);
  const apply = (t: string) => {
    setTheme(t);
    if (t === "system") {
      localStorage.removeItem("argus.theme");
      document.documentElement.removeAttribute("data-theme");
    } else {
      localStorage.setItem("argus.theme", t);
      document.documentElement.setAttribute("data-theme", t);
    }
  };
  return (
    <Select value={theme} onChange={(e) => apply(e.target.value)} className="h-7">
      <option value="system">System</option>
      <option value="light">Light</option>
      <option value="dark">Dark</option>
    </Select>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { me, logout, switchOrg, activeOrg } = useAuth();

  const activeJobs = useQuery({
    queryKey: ["jobs", "active-count"],
    queryFn: () => api<Job[]>("/jobs?limit=100"),
    refetchInterval: 8000,
  });
  const running = (activeJobs.data ?? []).filter((j) =>
    ["running", "queued", "paused"].includes(j.status),
  ).length;

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="flex w-52 shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex h-12 items-center gap-2 border-b border-border px-4">
          <div className="h-2.5 w-2.5 rounded-sm bg-accent" />
          <span className="font-semibold tracking-tight">Argus</span>
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map((n) => {
            const active = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                className={cn(
                  "flex items-center justify-between rounded-md px-2.5 py-1.5 text-[13px] transition",
                  active ? "bg-surface-2 font-medium text-fg" : "text-muted hover:bg-surface-2",
                )}
              >
                {n.label}
                {n.href === "/jobs" && running > 0 && (
                  <Badge tone="accent">{running}</Badge>
                )}
              </Link>
            );
          })}
          <div className="my-2 border-t border-border" />
          {NAV_SYSTEM.map((n) => {
            const active = pathname.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                className={cn(
                  "flex items-center justify-between rounded-md px-2.5 py-1.5 text-[13px] transition",
                  active ? "bg-surface-2 font-medium text-fg" : "text-muted hover:bg-surface-2",
                )}
              >
                {n.label}
              </Link>
            );
          })}
        </nav>
        <VersionFooter />
      </aside>

      <div className="flex flex-1 flex-col overflow-hidden">
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-border bg-surface px-4">
          <div className="flex items-center gap-3">
            {me && me.organizations.length > 0 && (
              <Select
                value={activeOrg ?? me.organizations[0].id}
                onChange={(e) => switchOrg(e.target.value)}
                className="h-7"
              >
                {me.organizations.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </Select>
            )}
            <span className="text-xs text-muted">
              {running > 0 ? `${running} scan job(s) active` : "No active scans"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            {me && (
              <span className="text-xs text-muted">
                {me.email} · <span className="uppercase">{me.role}</span>
              </span>
            )}
            <Button variant="outline" size="sm" onClick={logout}>
              Sign out
            </Button>
          </div>
        </header>
        <main className="flex-1 overflow-auto p-5">{children}</main>
      </div>
    </div>
  );
}
