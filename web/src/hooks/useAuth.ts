"use client";

import { api, clearTokens, getOrg, getToken, setOrg } from "@/lib/api";
import type { Me } from "@/lib/types";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useCallback } from "react";

export function useAuth() {
  const router = useRouter();
  const qc = useQueryClient();

  const query = useQuery<Me>({
    queryKey: ["me"],
    queryFn: () => api<Me>("/auth/me"),
    enabled: typeof window !== "undefined" && !!getToken(),
    retry: false,
  });

  const logout = useCallback(() => {
    clearTokens();
    qc.clear();
    router.push("/login");
  }, [qc, router]);

  const switchOrg = useCallback(
    (orgId: string) => {
      setOrg(orgId);
      qc.invalidateQueries();
    },
    [qc],
  );

  const can = useCallback(
    (perm: string) => !!query.data?.permissions.includes(perm),
    [query.data],
  );

  return {
    me: query.data,
    loading: query.isLoading,
    error: query.error,
    activeOrg: getOrg() ?? query.data?.active_org ?? null,
    logout,
    switchOrg,
    can,
  };
}
