"use client";

// Thin REST client. Same API the `argus` CLI uses. Tokens live in localStorage;
// the access token is refreshed transparently on a 401.

const ACCESS = "argus.access";
const REFRESH = "argus.refresh";
const ORG = "argus.org";

export function getToken() {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS);
}
export function getOrg() {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ORG);
}
export function setOrg(id: string) {
  localStorage.setItem(ORG, id);
}
export function setTokens(access: string, refresh: string) {
  localStorage.setItem(ACCESS, access);
  localStorage.setItem(REFRESH, refresh);
}
export function clearTokens() {
  localStorage.removeItem(ACCESS);
  localStorage.removeItem(REFRESH);
  localStorage.removeItem(ORG);
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `request failed (${status})`);
    this.status = status;
    this.detail = detail;
  }
}

async function refreshAccess(): Promise<boolean> {
  const refresh = localStorage.getItem(REFRESH);
  if (!refresh) return false;
  const res = await fetch("/api/auth/refresh", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  setTokens(data.access_token, data.refresh_token);
  return true;
}

type Options = Omit<RequestInit, "body"> & { body?: unknown; retry?: boolean };

export async function api<T = unknown>(path: string, opts: Options = {}): Promise<T> {
  const headers = new Headers(opts.headers);
  headers.set("content-type", "application/json");
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const org = getOrg();
  if (org) headers.set("x-org-id", org);

  const res = await fetch(`/api${path}`, {
    ...opts,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (res.status === 401 && opts.retry !== false && token) {
    if (await refreshAccess()) return api<T>(path, { ...opts, retry: false });
    clearTokens();
    if (typeof window !== "undefined") window.location.href = "/login";
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail = data?.detail ?? data;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

// Fetch a non-JSON response (e.g. a generated report) with auth. Pass
// `binary` for content that must not go through text decoding (PDF).
export async function apiText(
  path: string,
  binary = false,
): Promise<{ body: string; contentType: string; blob?: Blob }> {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const org = getOrg();
  if (org) headers.set("x-org-id", org);
  let res = await fetch(`/api${path}`, { headers });
  if (res.status === 401 && token && (await refreshAccess())) {
    const t = getToken();
    if (t) headers.set("authorization", `Bearer ${t}`);
    res = await fetch(`/api${path}`, { headers });
  }
  if (!res.ok) throw new ApiError(res.status, await res.text());
  const contentType = res.headers.get("content-type") ?? "text/plain";
  if (binary) return { body: "", contentType, blob: await res.blob() };
  return { body: await res.text(), contentType };
}

// Server-sent events over fetch (so we can send the Authorization header, which
// the native EventSource cannot). Calls onEvent for each `data:` line.
export async function streamEvents(
  path: string,
  onEvent: (ev: { event: string; data: any }) => void,
  signal: AbortSignal,
): Promise<void> {
  const headers = new Headers({ accept: "text/event-stream" });
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const org = getOrg();
  if (org) headers.set("x-org-id", org);

  const res = await fetch(`/api${path}`, { headers, signal });
  if (!res.ok || !res.body) throw new ApiError(res.status, "stream failed");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      let event = "message";
      let data = "";
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (!data) continue;
      try {
        onEvent({ event, data: JSON.parse(data) });
      } catch {
        /* ignore keep-alive */
      }
    }
  }
}
