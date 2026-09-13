"use client";

import { AiSettingsTab } from "@/components/AiSettingsTab";
import { ReportSettingsTab } from "@/components/ReportSettingsTab";
import { Badge, Button, Card, CardHeader, EmptyState, Input, Label, Select, Spinner, Tabs } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api, clearTokens } from "@/lib/api";
import type {
  NotificationPreference,
  SessionInfo,
  TelegramPairResponse,
  TelegramStatus,
  TestNotificationResult,
} from "@/lib/types";
import { fmtDate, timeAgo } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

interface SystemHealth {
  database: { healthy: boolean; latency_ms?: number; error?: string };
  redis: { healthy: boolean; queued: number | null; processing: number | null };
  orchestrator: { reachable: boolean };
}

const EVENT_LABELS: Record<string, string> = {
  scan_started: "Scan started",
  scan_completed: "Scan completed",
  scan_failed: "Scan failed",
  scan_partially_completed: "Scan partially completed",
  finding_critical: "Critical finding discovered",
  finding_high: "High finding discovered",
  new_asset: "New asset discovered",
  weekly_summary: "Weekly summary",
  system_error: "System error",
};

export default function SettingsPage() {
  const { me } = useAuth();
  const [tab, setTab] = useState("profile");

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Settings</h1>
      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { key: "profile", label: "Profile" },
          { key: "account", label: "Account" },
          { key: "security", label: "Security" },
          { key: "notifications", label: "Notifications" },
          { key: "ai", label: "AI & Analysis" },
          { key: "reports", label: "Reports" },
          { key: "system", label: "System" },
        ]}
      />
      {tab === "profile" && <ProfileTab />}
      {tab === "account" && <AccountTab email={me?.email ?? ""} />}
      {tab === "security" && (
        <div className="space-y-4">
          <MfaCard enabled={!!me?.mfa_enabled} />
          <PermissionsCard perms={me?.permissions ?? []} />
        </div>
      )}
      {tab === "notifications" && <NotificationsTab />}
      {tab === "ai" && <AiSettingsTab />}
      {tab === "reports" && <ReportSettingsTab />}
      {tab === "system" && <SystemHealthCard />}
    </div>
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

// ── Profile ──────────────────────────────────────────────────────────────

function ProfileTab() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const [fullName, setFullName] = useState(me?.full_name ?? "");
  const [timezone, setTimezone] = useState(me?.timezone ?? "UTC");
  const [theme, setTheme] = useState<string>(me?.theme ?? "system");

  const save = useMutation({
    mutationFn: () =>
      api("/auth/me", { method: "PATCH", body: { full_name: fullName, timezone, theme } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["me"] }),
  });

  if (!me) return <Spinner className="h-5 w-5" />;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="Profile" />
        <dl className="divide-y divide-border text-[13px]">
          <Row k="Email" v={me.email} />
          <Row
            k="Email verification"
            v={me.email_verified ? "verified" : "not verified"}
          />
          <Row k="Created" v={fmtDate(me.created_at)} />
          <Row k="Last login" v={me.last_login_at ? timeAgo(me.last_login_at) : "—"} />
        </dl>
      </Card>
      <Card>
        <CardHeader title="Edit profile" />
        <div className="space-y-3 p-4 text-[13px]">
          <div>
            <Label>Name</Label>
            <Input value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
          <div>
            <Label>Timezone</Label>
            <Input
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              placeholder="e.g. America/New_York, UTC"
            />
          </div>
          <div>
            <Label>Theme</Label>
            <Select value={theme} onChange={(e) => setTheme(e.target.value)}>
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </Select>
          </div>
          {save.error && (
            <p className="text-xs text-critical">{String((save.error as any).message)}</p>
          )}
          <Button disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save changes"}
          </Button>
        </div>
      </Card>
    </div>
  );
}

// ── Account ──────────────────────────────────────────────────────────────

function AccountTab({ email }: { email: string }) {
  return (
    <div className="space-y-4">
      <ChangePasswordCard />
      <SessionsCard />
      <DangerZoneCard email={email} />
    </div>
  );
}

function ChangePasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [ok, setOk] = useState(false);

  const change = useMutation({
    mutationFn: () =>
      api("/auth/change-password", {
        method: "POST",
        body: { current_password: current, new_password: next },
      }),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setOk(true);
      setTimeout(() => setOk(false), 4000);
    },
  });

  return (
    <Card>
      <CardHeader title="Change password" />
      <div className="space-y-3 p-4 text-[13px]">
        <div>
          <Label>Current password</Label>
          <Input value={current} onChange={(e) => setCurrent(e.target.value)} type="password" />
        </div>
        <div>
          <Label>New password</Label>
          <Input value={next} onChange={(e) => setNext(e.target.value)} type="password" minLength={12} />
        </div>
        {change.error && <p className="text-xs text-critical">{String((change.error as any).message)}</p>}
        {ok && <p className="text-xs text-ok">Password changed.</p>}
        <Button disabled={change.isPending || !current || next.length < 12} onClick={() => change.mutate()}>
          {change.isPending ? "Changing…" : "Change password"}
        </Button>
      </div>
    </Card>
  );
}

function SessionsCard() {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<SessionInfo[]>("/auth/sessions"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/auth/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });
  const revokeAll = useMutation({
    mutationFn: () => api("/auth/sessions/revoke-all", { method: "POST" }),
    onSuccess: () => {
      clearTokens();
      window.location.href = "/login";
    },
  });

  return (
    <Card>
      <CardHeader
        title="Active sessions"
        action={
          <Button variant="outline" className="h-7" onClick={() => revokeAll.mutate()}>
            Sign out everywhere
          </Button>
        }
      />
      {!data || data.length === 0 ? (
        <EmptyState title="No active sessions" />
      ) : (
        <div className="divide-y divide-border">
          {data.map((s) => (
            <div key={s.id} className="flex items-center justify-between px-4 py-2.5 text-[13px]">
              <div>
                <div className="font-mono text-xs">{s.ip || "unknown IP"}</div>
                <div className="text-[11px] text-muted">
                  {s.user_agent || "unknown client"} · created {timeAgo(s.created_at)}
                  {s.last_used_at ? ` · last used ${timeAgo(s.last_used_at)}` : ""}
                </div>
              </div>
              <Button variant="outline" className="h-6 px-2 text-[11px]" onClick={() => revoke.mutate(s.id)}>
                Revoke
              </Button>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function DangerZoneCard({ email }: { email: string }) {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const del = useMutation({
    mutationFn: () => api("/auth/account/delete", { method: "POST", body: { password, confirm } }),
    onSuccess: () => {
      clearTokens();
      window.location.href = "/login";
    },
  });

  const exportData = async () => {
    const data = await api("/auth/account/export");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "argus-account-export.json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  return (
    <Card className="border-critical/40">
      <CardHeader title="Danger zone" />
      <div className="space-y-3 p-4 text-[13px]">
        <div className="flex items-center justify-between">
          <p className="text-muted">Export a copy of your account data as JSON.</p>
          <Button variant="outline" onClick={exportData}>
            Export account data
          </Button>
        </div>
        <div className="flex items-center justify-between border-t border-border pt-3">
          <p className="text-muted">Permanently delete your account.</p>
          <Button variant="danger" onClick={() => setOpen(true)}>
            Delete account
          </Button>
        </div>
      </div>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md p-5">
            <h3 className="text-sm font-semibold text-critical">Delete your account?</h3>
            <p className="mt-2 text-xs text-muted">
              This cannot be undone. If you are the sole member of an organization, that
              organization and everything in it (projects, findings, evidence) is deleted too. If
              you share an organization with others, promote another admin first.
            </p>
            <label className="mb-1 mt-3 block text-xs text-muted">Password</label>
            <Input value={password} onChange={(e) => setPassword(e.target.value)} type="password" />
            <label className="mb-1 mt-3 block text-xs text-muted">
              Type <span className="font-mono text-fg">{email}</span> to confirm
            </label>
            <Input value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            {del.error && <p className="mt-2 text-xs text-critical">{String((del.error as any).message)}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                disabled={del.isPending || confirm !== email || !password}
                onClick={() => del.mutate()}
              >
                {del.isPending ? "Deleting…" : "Delete account"}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </Card>
  );
}

// ── Security ─────────────────────────────────────────────────────────────

function MfaCard({ enabled }: { enabled: boolean }) {
  const qc = useQueryClient();
  const [secret, setSecret] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [code, setCode] = useState("");

  const enroll = useMutation({
    mutationFn: () => api<{ secret: string; otpauth_uri: string }>("/auth/mfa/enroll", { method: "POST" }),
    onSuccess: (d) => {
      setSecret(d.secret);
      setUri(d.otpauth_uri);
    },
  });
  const verify = useMutation({
    mutationFn: () => api("/auth/mfa/verify", { method: "POST", body: { code } }),
    onSuccess: () => {
      setSecret(null);
      qc.invalidateQueries({ queryKey: ["me"] });
    },
  });
  const disable = useMutation({
    mutationFn: () => api("/auth/mfa/disable", { method: "POST", body: { code } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["me"] }),
  });

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            Two-factor authentication
            <Badge tone={enabled ? "ok" : "neutral"}>{enabled ? "enabled" : "off"}</Badge>
          </span>
        }
      />
      <div className="space-y-3 p-4 text-[13px]">
        {!enabled && !secret && (
          <Button onClick={() => enroll.mutate()} disabled={enroll.isPending}>
            Set up authenticator
          </Button>
        )}
        {secret && (
          <div className="space-y-2">
            <p className="text-xs text-muted">
              Add this secret to your authenticator app, then enter a code to confirm.
            </p>
            <code className="block break-all rounded bg-surface-2 p-2 font-mono text-xs">
              {secret}
            </code>
            <div className="flex gap-2">
              <Input
                placeholder="6-digit code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <Button onClick={() => verify.mutate()} disabled={verify.isPending}>
                Confirm
              </Button>
            </div>
          </div>
        )}
        {enabled && (
          <div className="flex gap-2">
            <Input placeholder="code to disable" value={code} onChange={(e) => setCode(e.target.value)} />
            <Button variant="danger" onClick={() => disable.mutate()}>
              Disable
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

function PermissionsCard({ perms }: { perms: string[] }) {
  return (
    <Card>
      <CardHeader title="Your permissions" />
      {perms.length === 0 ? (
        <EmptyState title="No permissions" />
      ) : (
        <div className="flex flex-wrap gap-1.5 p-4">
          {perms.map((p) => (
            <Badge key={p}>{p}</Badge>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Notifications ────────────────────────────────────────────────────────

function NotificationsTab() {
  const qc = useQueryClient();
  const { data: prefs } = useQuery({
    queryKey: ["notification-prefs"],
    queryFn: () => api<NotificationPreference>("/settings/notifications"),
  });
  const { data: telegramStatus } = useQuery({
    queryKey: ["telegram-status"],
    queryFn: () => api<TelegramStatus>("/settings/telegram/status"),
    refetchInterval: 5000,
  });

  const update = useMutation({
    mutationFn: (body: Partial<NotificationPreference>) =>
      api<NotificationPreference>("/settings/notifications", { method: "PUT", body }),
    onSuccess: (d) => qc.setQueryData(["notification-prefs"], d),
  });

  const pair = useMutation({
    mutationFn: () => api<TelegramPairResponse>("/settings/telegram/pair", { method: "POST" }),
  });
  const unlink = useMutation({
    mutationFn: () => api("/settings/telegram", { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["telegram-status"] }),
  });

  const [testEmailResult, setTestEmailResult] = useState<TestNotificationResult | null>(null);
  const [testTelegramResult, setTestTelegramResult] = useState<TestNotificationResult | null>(null);
  const testEmail = useMutation({
    mutationFn: () => api<TestNotificationResult>("/settings/notifications/test-email", { method: "POST" }),
    onSuccess: setTestEmailResult,
  });
  const testTelegram = useMutation({
    mutationFn: () => api<TestNotificationResult>("/settings/notifications/test-telegram", { method: "POST" }),
    onSuccess: setTestTelegramResult,
  });

  if (!prefs) return <Spinner className="h-5 w-5" />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title="Email notifications" />
        <div className="space-y-3 p-4 text-[13px]">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={prefs.email_enabled}
              onChange={(e) => update.mutate({ email_enabled: e.target.checked })}
            />
            Enable email notifications
          </label>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="h-7" disabled={testEmail.isPending} onClick={() => testEmail.mutate()}>
              Send test email
            </Button>
            {testEmailResult && (
              <span className={`text-xs ${testEmailResult.success ? "text-ok" : "text-critical"}`}>
                {testEmailResult.success ? "Sent — check your inbox." : testEmailResult.detail}
              </span>
            )}
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader title="Telegram notifications" />
        <div className="space-y-3 p-4 text-[13px]">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={prefs.telegram_enabled}
              onChange={(e) => update.mutate({ telegram_enabled: e.target.checked })}
            />
            Enable Telegram notifications
          </label>

          {telegramStatus?.linked ? (
            <div className="flex items-center justify-between rounded bg-surface-2 p-2">
              <span>
                Connected {telegramStatus.telegram_username && `as @${telegramStatus.telegram_username}`}
              </span>
              <Button variant="outline" className="h-6 px-2 text-[11px]" onClick={() => unlink.mutate()}>
                Disconnect
              </Button>
            </div>
          ) : pair.data ? (
            <div className="space-y-2 rounded bg-surface-2 p-3">
              {!pair.data.bot_configured && (
                <p className="text-xs text-critical">
                  No Telegram bot is configured on this server (TELEGRAM_BOT_TOKEN unset) — an
                  administrator needs to set it before pairing can work.
                </p>
              )}
              <p className="text-xs text-muted">
                Open the bot and send this code, or use the deep link:
              </p>
              <code className="block rounded bg-surface p-2 font-mono text-sm">{pair.data.pairing_code}</code>
              {pair.data.deep_link && (
                <a href={pair.data.deep_link} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">
                  Open in Telegram →
                </a>
              )}
              <p className="text-[11px] text-muted">Expires {fmtDate(pair.data.expires_at)}</p>
            </div>
          ) : (
            <Button variant="outline" onClick={() => pair.mutate()} disabled={pair.isPending}>
              Connect Telegram
            </Button>
          )}

          <div className="flex items-center gap-2 border-t border-border pt-3">
            <Button
              variant="outline"
              className="h-7"
              disabled={testTelegram.isPending}
              onClick={() => testTelegram.mutate()}
            >
              Send test Telegram message
            </Button>
            {testTelegramResult && (
              <span className={`text-xs ${testTelegramResult.success ? "text-ok" : "text-critical"}`}>
                {testTelegramResult.success ? "Sent." : testTelegramResult.detail}
              </span>
            )}
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader title="Notification types" />
        <div className="divide-y divide-border">
          {Object.entries(EVENT_LABELS).map(([key, label]) => (
            <label key={key} className="flex items-center justify-between px-4 py-2 text-[13px]">
              <span>{label}</span>
              <input
                type="checkbox"
                checked={prefs.events[key] ?? false}
                onChange={(e) => update.mutate({ events: { [key]: e.target.checked } })}
              />
            </label>
          ))}
        </div>
      </Card>

      <Card>
        <CardHeader title="Quiet hours" />
        <div className="space-y-3 p-4 text-[13px]">
          <div className="flex items-center gap-3">
            <div>
              <Label>Start hour (0-23)</Label>
              <Input
                type="number"
                min={0}
                max={23}
                value={prefs.quiet_hours_start ?? ""}
                onChange={(e) => update.mutate({ quiet_hours_start: e.target.value === "" ? undefined : Number(e.target.value) })}
                className="w-20"
              />
            </div>
            <div>
              <Label>End hour (0-23)</Label>
              <Input
                type="number"
                min={0}
                max={23}
                value={prefs.quiet_hours_end ?? ""}
                onChange={(e) => update.mutate({ quiet_hours_end: e.target.value === "" ? undefined : Number(e.target.value) })}
                className="w-20"
              />
            </div>
          </div>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={prefs.quiet_hours_override_critical}
              onChange={(e) => update.mutate({ quiet_hours_override_critical: e.target.checked })}
            />
            Still notify for critical findings during quiet hours
          </label>
          <p className="text-[11px] text-muted">Uses your profile timezone (Profile tab).</p>
        </div>
      </Card>
    </div>
  );
}

// ── System ───────────────────────────────────────────────────────────────

function SystemHealthCard() {
  const { data, isLoading } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => api<SystemHealth>("/system/health"),
    refetchInterval: 10000,
  });
  return (
    <Card>
      <CardHeader title="System Health" />
      {isLoading || !data ? (
        <div className="p-6">
          <Spinner className="h-5 w-5" />
        </div>
      ) : (
        <div className="grid gap-px bg-border sm:grid-cols-3">
          <HealthCell name="Database" ok={data.database.healthy} detail={`${data.database.latency_ms ?? "?"} ms`} />
          <HealthCell
            name="Redis"
            ok={data.redis.healthy}
            detail={`queued ${data.redis.queued ?? "?"} · processing ${data.redis.processing ?? "?"}`}
          />
          <HealthCell name="Orchestrator" ok={data.orchestrator.reachable} detail={data.orchestrator.reachable ? "worker alive" : "no heartbeat"} />
        </div>
      )}
    </Card>
  );
}

function HealthCell({ name, ok, detail }: { name: string; ok: boolean; detail: string }) {
  return (
    <div className="bg-surface p-4">
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${ok ? "bg-ok" : "bg-critical"}`} />
        <span className="text-[13px] font-medium">{name}</span>
      </div>
      <p className="mt-1 text-xs text-muted">{detail}</p>
    </div>
  );
}
