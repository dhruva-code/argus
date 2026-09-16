"use client";

import { Button, Card, Input, Label } from "@/components/ui";
import { api, setTokens } from "@/lib/api";
import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfa, setMfa] = useState("");
  const [needsMfa, setNeedsMfa] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const res = await api<{ access_token: string; refresh_token: string }>("/auth/login", {
        method: "POST",
        body: { email, password, mfa_code: mfa || undefined },
      });
      setTokens(res.access_token, res.refresh_token);
      router.replace("/");
    } catch (e: any) {
      if (typeof e.detail === "string" && e.detail.includes("mfa_code")) {
        setNeedsMfa(true);
        setErr("Enter your authenticator code.");
      } else {
        setErr(typeof e.detail === "string" ? e.detail : "Login failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-2">
          <div className="h-3 w-3 rounded-sm bg-accent" />
          <span className="text-base font-semibold">Argus</span>
        </div>
        <p className="mb-4 text-xs text-muted">Sign in to the attack-surface platform.</p>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <Label>Email</Label>
            <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required autoFocus />
          </div>
          <div>
            <Label>Password</Label>
            <Input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              required
            />
          </div>
          {needsMfa && (
            <div>
              <Label>Authenticator code</Label>
              <Input value={mfa} onChange={(e) => setMfa(e.target.value)} inputMode="numeric" />
            </div>
          )}
          {err && <p className="text-xs text-critical">{err}</p>}
          <Button className="w-full" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="mt-4 text-center text-[11px] text-muted">
          Single bootstrap admin account — see Settings → Security to change your password.
        </p>
      </Card>
    </div>
  );
}
