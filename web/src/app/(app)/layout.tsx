"use client";

import { AppShell } from "@/components/AppShell";
import { Spinner } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { getToken } from "@/lib/api";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { me, loading, error } = useAuth();

  useEffect(() => {
    if (typeof window !== "undefined" && !getToken()) router.replace("/login");
  }, [router]);

  useEffect(() => {
    if (error) router.replace("/login");
  }, [error, router]);

  if (loading || !me) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  return <AppShell>{children}</AppShell>;
}
