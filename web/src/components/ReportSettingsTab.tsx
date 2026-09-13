"use client";

import { api } from "@/lib/api";
import type { ReportSettings } from "@/lib/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Button, Card, CardHeader, Input, Label, Spinner } from "./ui";

const MAX_LOGO_BYTES = 300_000;
const ALLOWED_LOGO_TYPES = ["image/png", "image/jpeg", "image/webp"];

export function ReportSettingsTab() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["report-settings"],
    queryFn: () => api<ReportSettings>("/settings/reports"),
  });
  const fileRef = useRef<HTMLInputElement>(null);
  const [logoError, setLogoError] = useState("");
  const [pendingLogoPreview, setPendingLogoPreview] = useState<string | null>(null);

  const update = useMutation({
    mutationFn: (body: Partial<ReportSettings> & { logo_data_uri?: string }) =>
      api<ReportSettings>("/settings/reports", { method: "PUT", body }),
    onSuccess: (d) => qc.setQueryData(["report-settings"], d),
  });

  function onLogoPicked(file: File) {
    setLogoError("");
    if (!ALLOWED_LOGO_TYPES.includes(file.type)) {
      setLogoError("Logo must be PNG, JPEG, or WebP (SVG is rejected — it can embed scripts).");
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setLogoError(`Logo too large — max ${Math.round(MAX_LOGO_BYTES / 1000)}KB.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const dataUri = reader.result as string;
      setPendingLogoPreview(dataUri);
      update.mutate({ logo_data_uri: dataUri });
    };
    reader.readAsDataURL(file);
  }

  if (isLoading || !data) return <Spinner className="h-5 w-5" />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title="Report branding" />
        <div className="space-y-4 p-4 text-[13px]">
          <p className="text-xs text-muted">
            Applied to every generated PDF report — cover page, header/footer, and
            confidentiality label. Purely cosmetic; never affects finding data.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label>Company name</Label>
              <Input
                defaultValue={data.company_name}
                onBlur={(e) => e.target.value !== data.company_name && update.mutate({ company_name: e.target.value })}
              />
            </div>
            <div>
              <Label>Report title</Label>
              <Input
                defaultValue={data.report_title}
                onBlur={(e) => e.target.value !== data.report_title && update.mutate({ report_title: e.target.value })}
              />
            </div>
            <div>
              <Label>Author</Label>
              <Input
                defaultValue={data.author}
                onBlur={(e) => e.target.value !== data.author && update.mutate({ author: e.target.value })}
              />
            </div>
            <div>
              <Label>Contact email</Label>
              <Input
                type="email"
                defaultValue={data.contact_email}
                onBlur={(e) => e.target.value !== data.contact_email && update.mutate({ contact_email: e.target.value })}
              />
            </div>
            <div>
              <Label>Confidentiality label</Label>
              <Input
                defaultValue={data.confidentiality_label}
                onBlur={(e) =>
                  e.target.value !== data.confidentiality_label &&
                  update.mutate({ confidentiality_label: e.target.value })
                }
              />
            </div>
            <div>
              <Label>Accent color</Label>
              <div className="flex items-center gap-2">
                <input
                  type="color"
                  defaultValue={data.accent_color}
                  className="h-8 w-10 rounded border border-border bg-transparent"
                  onChange={(e) => update.mutate({ accent_color: e.target.value })}
                />
                <span className="font-mono text-xs text-muted">{data.accent_color}</span>
              </div>
            </div>
          </div>

          <div>
            <Label>Logo</Label>
            <div className="flex items-center gap-3">
              {(pendingLogoPreview || data.has_logo) && (
                <div className="flex h-12 w-24 items-center justify-center rounded border border-border bg-surface-2">
                  {pendingLogoPreview ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={pendingLogoPreview} alt="Report logo preview" className="max-h-10 max-w-20" />
                  ) : (
                    <span className="text-[11px] text-muted">logo set</span>
                  )}
                </div>
              )}
              <Button variant="outline" onClick={() => fileRef.current?.click()}>
                {data.has_logo ? "Replace logo" : "Upload logo"}
              </Button>
              {data.has_logo && (
                <Button
                  variant="outline"
                  onClick={() => {
                    setPendingLogoPreview(null);
                    update.mutate({ logo_data_uri: "" });
                  }}
                >
                  Remove
                </Button>
              )}
              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && onLogoPicked(e.target.files[0])}
              />
            </div>
            {logoError && <p className="mt-1 text-xs text-critical">{logoError}</p>}
            <p className="mt-1 text-[11px] text-muted">
              PNG, JPEG, or WebP only, up to {Math.round(MAX_LOGO_BYTES / 1000)}KB.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}
