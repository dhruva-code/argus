"use client";

import { api } from "@/lib/api";
import type { Project, ProjectDeletePreview } from "@/lib/types";
import { fmtDate } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge, Button, Card, CardHeader, Input } from "./ui";

export function SettingsPanel({
  project,
  canDelete,
  canPurgePermanently,
}: {
  project: Project;
  canDelete: boolean;
  canPurgePermanently: boolean;
}) {
  const qc = useQueryClient();
  const router = useRouter();

  const restore = useMutation({
    mutationFn: () => api<Project>(`/projects/${project.id}/restore`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["project", project.id] }),
  });

  if (project.deleted_at) {
    return (
      <Card className="border-critical/40">
        <CardHeader title="Danger zone" action={<Badge tone="danger">soft-deleted</Badge>} />
        <div className="space-y-3 p-4 text-[13px]">
          <p className="text-muted">
            This project was deleted on <span className="text-fg">{fmtDate(project.deleted_at)}</span>.
            Its data still exists — nothing was permanently removed. Scans are stopped and it no
            longer appears in the project list.
          </p>
          <div className="flex gap-2">
            {canDelete && (
              <Button variant="outline" disabled={restore.isPending} onClick={() => restore.mutate()}>
                {restore.isPending ? "Restoring…" : "Restore project"}
              </Button>
            )}
            {canPurgePermanently && <PermanentDeleteButton project={project} onDone={() => router.push("/projects")} />}
          </div>
          {!canPurgePermanently && (
            <p className="text-xs text-muted">
              Permanently deleting this project requires organization-admin rights.
            </p>
          )}
        </div>
      </Card>
    );
  }

  return (
    <Card className="border-critical/40">
      <CardHeader title="Danger zone" />
      <div className="space-y-3 p-4 text-[13px]">
        <p className="text-muted">
          Deleting a project stops any running scans and archives it immediately. It is
          reversible — the project and everything it discovered stay in the database until you
          (or an org admin) choose to permanently delete it.
        </p>
        {canDelete && <SoftDeleteButton project={project} />}
      </div>
    </Card>
  );
}

function SoftDeleteButton({ project }: { project: Project }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [confirmName, setConfirmName] = useState("");

  const preview = useQuery({
    queryKey: ["deletion-preview", project.id],
    queryFn: () => api<ProjectDeletePreview>(`/projects/${project.id}/deletion-preview`),
    enabled: open,
  });

  const del = useMutation({
    mutationFn: () =>
      api<Project>(`/projects/${project.id}/delete`, {
        method: "POST",
        body: { confirm_name: confirmName },
      }),
    onSuccess: () => {
      setOpen(false);
      qc.invalidateQueries({ queryKey: ["project", project.id] });
      qc.invalidateQueries({ queryKey: ["projects"] });
    },
  });

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        Delete project
      </Button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md p-5">
            <h3 className="text-sm font-semibold">Delete “{project.name}”?</h3>
            <p className="mt-2 text-xs text-muted">
              This will be deleted (reversible until permanently purged):
            </p>
            <ul className="my-2 grid grid-cols-2 gap-1 text-xs text-muted">
              {preview.data &&
                Object.entries(preview.data.counts).map(([k, v]) => (
                  <li key={k}>
                    <span className="text-fg tabular-nums">{v}</span> {k.replace(/_/g, " ")}
                  </li>
                ))}
            </ul>
            <label className="mb-1 mt-3 block text-xs text-muted">
              Type <span className="font-mono text-fg">{project.name}</span> to confirm
            </label>
            <Input value={confirmName} onChange={(e) => setConfirmName(e.target.value)} />
            {del.error && <p className="mt-2 text-xs text-critical">{String((del.error as any).message)}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                disabled={del.isPending || confirmName !== project.name}
                onClick={() => del.mutate()}
              >
                {del.isPending ? "Deleting…" : "Delete project"}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}

function PermanentDeleteButton({ project, onDone }: { project: Project; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [confirmName, setConfirmName] = useState("");
  const [understood, setUnderstood] = useState(false);

  const preview = useQuery({
    queryKey: ["deletion-preview", project.id],
    queryFn: () => api<ProjectDeletePreview>(`/projects/${project.id}/deletion-preview`),
    enabled: open,
  });

  const del = useMutation({
    mutationFn: () =>
      api(`/projects/${project.id}/delete/permanent`, {
        method: "POST",
        body: { confirm_name: confirmName },
      }),
    onSuccess: onDone,
  });

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        Permanently delete forever
      </Button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md p-5">
            <h3 className="text-sm font-semibold text-critical">
              Permanently delete “{project.name}”?
            </h3>
            <p className="mt-2 text-xs text-muted">
              This cannot be undone. Every row this project ever produced is removed in one
              transaction:
            </p>
            <ul className="my-2 grid grid-cols-2 gap-1 text-xs text-muted">
              {preview.data &&
                Object.entries(preview.data.counts).map(([k, v]) => (
                  <li key={k}>
                    <span className="text-fg tabular-nums">{v}</span> {k.replace(/_/g, " ")}
                  </li>
                ))}
            </ul>
            <label className="mb-1 mt-3 block text-xs text-muted">
              Type <span className="font-mono text-fg">{project.name}</span> to confirm
            </label>
            <Input value={confirmName} onChange={(e) => setConfirmName(e.target.value)} />
            <label className="mt-3 flex items-start gap-2 text-[13px]">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={understood}
                onChange={(e) => setUnderstood(e.target.checked)}
              />
              <span>I understand this permanently destroys all data above and cannot be undone.</span>
            </label>
            {del.error && <p className="mt-2 text-xs text-critical">{String((del.error as any).message)}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                disabled={del.isPending || confirmName !== project.name || !understood}
                onClick={() => del.mutate()}
              >
                {del.isPending ? "Deleting…" : "Delete forever"}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
