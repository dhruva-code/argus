"use client";

import { Button, Card, Spinner } from "@/components/ui";
import { api, setTokens } from "@/lib/api";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

function VerifyEmailInner() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!token) {
      setState("error");
      setErr("Missing verification token.");
      return;
    }
    api<{ access_token: string; refresh_token: string }>("/auth/verify-email", {
      method: "POST",
      body: { token },
    })
      .then((res) => {
        setTokens(res.access_token, res.refresh_token);
        setState("ok");
        setTimeout(() => router.replace("/"), 1500);
      })
      .catch((e: any) => {
        setState("error");
        setErr(typeof e.detail === "string" ? e.detail : "Verification failed");
      });
  }, [token, router]);

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6 text-center">
        <div className="mb-3 flex items-center justify-center gap-2">
          <div className="h-3 w-3 rounded-sm bg-accent" />
          <span className="text-base font-semibold">Argus</span>
        </div>
        {state === "working" && (
          <div className="flex flex-col items-center gap-2 py-4">
            <Spinner className="h-6 w-6" />
            <p className="text-xs text-muted">Verifying your email…</p>
          </div>
        )}
        {state === "ok" && <p className="text-sm">Email verified — signing you in…</p>}
        {state === "error" && (
          <>
            <p className="text-sm text-critical">{err}</p>
            <div className="mt-4 flex justify-center gap-2">
              <Button variant="outline" onClick={() => router.replace("/login")}>
                Back to sign in
              </Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={null}>
      <VerifyEmailInner />
    </Suspense>
  );
}
