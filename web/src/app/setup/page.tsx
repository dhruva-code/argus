"use client";

import { Button, Card, Input, Label } from "@/components/ui";
import { api, setTokens } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const STEPS = ["Welcome", "Admin account", "Organization", "Review"];

export default function SetupPage() {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [org, setOrg] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ setup_required: boolean }>("/auth/setup-required")
      .then((r) => !r.setup_required && router.replace("/login"))
      .catch(() => {});
  }, [router]);

  async function finish() {
    setBusy(true);
    setErr(null);
    try {
      const res = await api<{ access_token: string; refresh_token: string }>("/auth/setup", {
        method: "POST",
        body: { org_name: org, admin_email: email, admin_password: password, admin_name: name },
      });
      setTokens(res.access_token, res.refresh_token);
      router.replace("/");
    } catch (e: any) {
      setErr(typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail));
      setBusy(false);
    }
  }

  const canNext =
    (step === 1 && email.includes("@") && password.length >= 12) ||
    (step === 2 && org.length >= 2) ||
    step === 0 ||
    step === 3;

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-lg p-6">
        <div className="mb-5 flex items-center gap-2">
          <div className="h-3 w-3 rounded-sm bg-accent" />
          <span className="text-base font-semibold">Argus · First-run setup</span>
        </div>

        <div className="mb-5 flex gap-1.5">
          {STEPS.map((s, i) => (
            <div
              key={s}
              className={cn(
                "h-1 flex-1 rounded-full",
                i <= step ? "bg-accent" : "bg-surface-2",
              )}
            />
          ))}
        </div>

        {step === 0 && (
          <div className="space-y-2 text-[13px] text-muted">
            <p className="text-sm font-medium text-fg">Welcome.</p>
            <p>
              This wizard creates the first administrator and your organization. Argus manages
              authorized bug-bounty and attack-surface engagements — every active operation is gated
              by an explicit scope policy.
            </p>
            <p>Database, Redis and object storage are configured via environment variables.</p>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-3">
            <div>
              <Label>Full name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            </div>
            <div>
              <Label>Email</Label>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" />
            </div>
            <div>
              <Label>Password (min 12 characters)</Label>
              <Input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
              />
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <Label>Organization name</Label>
            <Input value={org} onChange={(e) => setOrg(e.target.value)} autoFocus />
            <p className="mt-2 text-xs text-muted">
              The six built-in scan profiles (Passive Only → Continuous Monitoring) are created
              automatically.
            </p>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-1 text-[13px]">
            <Row k="Administrator" v={`${name || "—"} <${email}>`} />
            <Row k="Organization" v={org} />
            <Row k="Role" v="Organization Admin" />
            {err && <p className="pt-2 text-xs text-critical">{err}</p>}
          </div>
        )}

        <div className="mt-6 flex justify-between">
          <Button
            variant="outline"
            disabled={step === 0}
            onClick={() => setStep((s) => Math.max(0, s - 1))}
          >
            Back
          </Button>
          {step < 3 ? (
            <Button disabled={!canNext} onClick={() => setStep((s) => s + 1)}>
              Continue
            </Button>
          ) : (
            <Button disabled={busy} onClick={finish}>
              {busy ? "Creating…" : "Create & sign in"}
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between border-b border-border py-1.5">
      <span className="text-muted">{k}</span>
      <span className="font-medium">{v}</span>
    </div>
  );
}
