"use client";

import { Button, Card, Input, Label } from "@/components/ui";
import { api, setTokens } from "@/lib/api";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

function ResetPasswordInner() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const res = await api<{ access_token: string; refresh_token: string }>("/auth/reset-password", {
        method: "POST",
        body: { token, new_password: password },
      });
      setTokens(res.access_token, res.refresh_token);
      router.replace("/");
    } catch (e: any) {
      setErr(typeof e.detail === "string" ? e.detail : "Reset failed");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm p-6 text-center">
          <p className="text-sm text-critical">Missing reset token.</p>
          <a href="/forgot-password" className="mt-3 inline-block text-xs text-accent hover:underline">
            Request a new link
          </a>
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
        <p className="mb-4 text-xs text-muted">Choose a new password. This will sign out all other sessions.</p>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <Label>New password</Label>
            <Input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              minLength={12}
              required
              autoFocus
            />
          </div>
          {err && <p className="text-xs text-critical">{err}</p>}
          <Button className="w-full" disabled={busy}>
            {busy ? "Resetting…" : "Reset password"}
          </Button>
        </form>
      </Card>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={null}>
      <ResetPasswordInner />
    </Suspense>
  );
}
