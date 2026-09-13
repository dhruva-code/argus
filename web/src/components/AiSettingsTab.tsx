"use client";

import { api } from "@/lib/api";
import type { AiSettings, AiTestResult } from "@/lib/types";
import { fmtDate } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Button, Card, CardHeader, Input, Label, Select, Spinner } from "./ui";

const STATUS_TONE: Record<string, "ok" | "danger" | "neutral"> = {
  ok: "ok",
  failed: "danger",
  not_configured: "neutral",
};
const STATUS_LABEL: Record<string, string> = {
  ok: "Configured",
  failed: "Connection failed",
  not_configured: "Not configured",
};

export function AiSettingsTab() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["ai-settings"],
    queryFn: () => api<AiSettings>("/settings/ai"),
  });

  const [provider, setProvider] = useState<string | null>(null);
  const [model, setModel] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [testResult, setTestResult] = useState<AiTestResult | null>(null);

  const update = useMutation({
    mutationFn: (body: Partial<AiSettings> & { api_key?: string }) =>
      api<AiSettings>("/settings/ai", { method: "PUT", body }),
    onSuccess: (d) => {
      qc.setQueryData(["ai-settings"], d);
      setApiKey("");
      setTestResult(null);
    },
  });
  const test = useMutation({
    mutationFn: () => api<AiTestResult>("/settings/ai/test", { method: "POST" }),
    onSuccess: (d) => {
      setTestResult(d);
      qc.invalidateQueries({ queryKey: ["ai-settings"] });
    },
  });

  if (isLoading || !data) return <Spinner className="h-5 w-5" />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="AI-assisted analysis"
          action={<Badge tone={STATUS_TONE[data.status]}>{STATUS_LABEL[data.status]}</Badge>}
        />
        <div className="space-y-4 p-4 text-[13px]">
          <p className="text-xs text-muted">
            Optional. When enabled, findings can be summarized, classified, and given
            remediation guidance by an LLM. AI output is always kept separate from — and
            never overwrites — the original scanner evidence. Secrets, tokens, cookies and
            authorization headers are redacted before anything is sent to the provider.
            Without a key, the platform falls back to a deterministic heuristic summary and
            keeps working exactly as before.
          </p>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={data.enabled}
              onChange={(e) => update.mutate({ enabled: e.target.checked })}
            />
            Enable AI-assisted analysis
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label>Provider</Label>
              <Select
                value={provider ?? data.provider}
                onChange={(e) => setProvider(e.target.value)}
              >
                <option value="anthropic">Anthropic</option>
              </Select>
            </div>
            <div>
              <Label>Model</Label>
              <Input value={model ?? data.model} onChange={(e) => setModel(e.target.value)} />
            </div>
          </div>

          <div>
            <Label>API key</Label>
            <Input
              type="password"
              placeholder={data.api_key_masked || "not set"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              autoComplete="off"
            />
            <p className="mt-1 text-[11px] text-muted">
              {data.api_key_masked
                ? `Currently: ${data.api_key_masked} — leave blank to keep it, or enter a new key to replace it.`
                : "Never shown in full once saved — only a masked preview."}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button
              disabled={update.isPending}
              onClick={() =>
                update.mutate({
                  ...(provider !== null ? { provider } : {}),
                  ...(model !== null ? { model } : {}),
                  ...(apiKey ? { api_key: apiKey } : {}),
                })
              }
            >
              Save
            </Button>
            <Button
              variant="outline"
              disabled={test.isPending || !data.enabled}
              onClick={() => test.mutate()}
            >
              Test connection
            </Button>
            {data.api_key_masked && (
              <Button
                variant="outline"
                disabled={update.isPending}
                onClick={() => update.mutate({ api_key: "" })}
              >
                Clear key
              </Button>
            )}
            {testResult && (
              <span className={`text-xs ${testResult.success ? "text-ok" : "text-critical"}`}>
                {testResult.detail}
              </span>
            )}
          </div>
          {data.last_test_at && (
            <p className="text-[11px] text-muted">Last tested {fmtDate(data.last_test_at)}</p>
          )}
        </div>
      </Card>
    </div>
  );
}
