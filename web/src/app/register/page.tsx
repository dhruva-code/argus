"use client";

import { Button, Card, Input, Label } from "@/components/ui";
import { api } from "@/lib/api";
import { useState } from "react";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const res = await api<{ message: string; email: string }>("/auth/register", {
        method: "POST",
        body: { email, password, full_name: fullName, org_name: orgName },
      });
      setDone(res.message);
    } catch (e: any) {
      setErr(typeof e.detail === "string" ? e.detail : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm p-6 text-center">
          <div className="mb-3 flex items-center justify-center gap-2">
            <div className="h-3 w-3 rounded-sm bg-accent" />
            <span className="text-base font-semibold">Argus</span>
          </div>
          <p className="text-sm">{done}</p>
          <p className="mt-2 text-xs text-muted">
            Check your inbox (including @proton.me / @protonmail.com — any address works) for a
            verification link, then{" "}
            <a href="/login" className="text-accent hover:underline">
              sign in
            </a>
            .
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-2">
          <div className="h-3 w-3 rounded-sm bg-accent" />
          <span className="text-base font-semibold">Argus</span>
        </div>
        <p className="mb-4 text-xs text-muted">
          Create an account. Any email provider works, including Proton.
        </p>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <Label>Email</Label>
            <Input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type="email"
              placeholder="you@proton.me"
              required
              autoFocus
            />
          </div>
          <div>
            <Label>Full name</Label>
            <Input value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
          <div>
            <Label>Password</Label>
            <Input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              minLength={12}
              required
            />
            <p className="mt-1 text-[11px] text-muted">At least 12 characters.</p>
          </div>
          <div>
            <Label>Workspace name (optional)</Label>
            <Input
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              placeholder="Defaults to “yourname's workspace”"
            />
          </div>
          {err && <p className="text-xs text-critical">{err}</p>}
          <Button className="w-full" disabled={busy}>
            {busy ? "Creating account…" : "Create account"}
          </Button>
        </form>
        <div className="mt-4 text-center text-xs text-muted">
          Already have an account?{" "}
          <a href="/login" className="text-accent hover:underline">
            Sign in
          </a>
        </div>
      </Card>
    </div>
  );
}
