"use client";

import { Button, Card, Input, Label } from "@/components/ui";
import { api } from "@/lib/api";
import { useState } from "react";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/auth/request-password-reset", { method: "POST", body: { email } });
    } catch {
      // Deliberately ignored — the endpoint never reveals whether the
      // address exists, so there's nothing meaningful to show differently.
    } finally {
      setBusy(false);
      setDone(true);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-2">
          <div className="h-3 w-3 rounded-sm bg-accent" />
          <span className="text-base font-semibold">Argus</span>
        </div>
        {done ? (
          <p className="text-sm">
            If that address has an account, a password reset link has been sent to it.
          </p>
        ) : (
          <>
            <p className="mb-4 text-xs text-muted">
              Enter your account email and we&apos;ll send a reset link.
            </p>
            <form onSubmit={submit} className="space-y-3">
              <div>
                <Label>Email</Label>
                <Input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  type="email"
                  required
                  autoFocus
                />
              </div>
              <Button className="w-full" disabled={busy}>
                {busy ? "Sending…" : "Send reset link"}
              </Button>
            </form>
          </>
        )}
        <div className="mt-4 text-center text-xs text-muted">
          <a href="/login" className="text-accent hover:underline">
            Back to sign in
          </a>
        </div>
      </Card>
    </div>
  );
}
