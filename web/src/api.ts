import { useCallback, useEffect, useState } from "react";

let csrf = "";
export function setCSRF(value: string) {
  csrf = value;
}
export class APIError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T = unknown>(
  path: string,
  method = "GET",
  body?: unknown,
  signal?: AbortSignal,
  headers?: Record<string, string>,
): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    signal,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && !path.includes("/auth/login"))
      window.dispatchEvent(new Event("session-expired"));
    throw new APIError(
      response.status,
      result.error?.message || `请求失败 (${response.status})`,
    );
  }
  return result as T;
}
export function useData<T>(path: string) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setData(undefined);
    api<T>(path, "GET", undefined, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setData(value);
      })
      .catch((e: Error) => {
        if (!controller.signal.aborted && e.name !== "AbortError")
          setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, version]);
  return { data, error, loading, reload };
}
export interface Workspace {
  id: string;
  name: string;
}
export interface Tag {
  id: string;
  name: string;
}
export interface KeyItem {
  id: string;
  path: string;
  workspace_id: string;
  disabled: boolean;
  tags: Tag[];
  version: number;
  active_version_id: string | null;
  expires_at: number | null;
}
export interface Version {
  id: string;
  number: number;
  expires_at: number | null;
  created_at: number;
  active: number;
}
export interface Rule {
  key_ids?: string[];
  tag_ids?: string[];
  repository_owner_id: string;
  repository_id?: string;
  workflow_path?: string;
  workflow_sha?: string;
  refs?: string[];
  environments?: string[];
  events?: string[];
  runner_environments?: string[];
}
export interface Policy {
  id: string;
  name: string;
  version: number;
  disabled: boolean;
  rule: Rule;
}
export interface Settings {
  revision: number;
  public_url: string;
  owner_email: string;
  github_enabled: boolean;
  github_client_id: string;
  github_secret_configured: boolean;
  github_id: string;
  email_provider: "resend" | "agentmail";
  agentmail_inbox_id: string;
  agentmail_key_configured: boolean;
  resend_enabled: boolean;
  resend_from: string;
  resend_key_configured: boolean;
  reminder_days: number[];
  notify_on_expiry: boolean;
  log_level: string;
  audit_retention_days: number;
}
export const wsBase = (id: string) =>
  `/v1/admin/workspaces/${encodeURIComponent(id)}`;
export const formatDate = (n: number | null) =>
  n ? new Date(n * 1000).toLocaleString("zh-CN", { hour12: false }) : "未设置";
export const localDate = (n: number | null) => {
  if (!n) return "";
  const d = new Date(n * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
};
export const isoDate = (s: string) => (s ? new Date(s).toISOString() : null);
export function downloadJSON(name: string, data: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
