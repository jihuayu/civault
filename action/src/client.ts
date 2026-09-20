export class ActionError extends Error {}
export const reserved = [
  "__PROTO__",
  "CONSTRUCTOR",
  "PROTOTYPE",
  "NODE_OPTIONS",
  "PATH",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "BASH_ENV",
  "ENV",
  "COMSPEC",
  "SHELLOPTS",
];
export function validName(name: string): boolean {
  const upper = name.toUpperCase();
  return (
    name.length <= 200 &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) &&
    !/^(GITHUB_|RUNNER_|ACTIONS_)/.test(upper) &&
    !reserved.includes(upper)
  );
}
export function references(
  env: NodeJS.ProcessEnv,
  workspace: string,
): Record<string, string> {
  const result: Record<string, string> = Object.create(null);
  const seen = new Set<string>();
  for (const [name, value] of Object.entries(env)) {
    if (!value?.startsWith("cv://")) continue;
    if (!validName(name) || seen.has(name.toUpperCase()))
      throw new ActionError(
        "Invalid, reserved, or case-colliding key variable name.",
      );
    seen.add(name.toUpperCase());
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new ActionError("Invalid cv:// key reference.");
    }
    let path: string;
    try {
      path = decodeURIComponent(url.pathname);
    } catch {
      throw new ActionError("Invalid encoded key path.");
    }
    if (
      url.protocol !== "cv:" ||
      url.host !== workspace ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !path.startsWith("/") ||
      path
        .slice(1)
        .split("/")
        .some((x) => !x || x === "." || x === "..") ||
      /[\0\r\n?#\\]/.test(path)
    )
      throw new ActionError(
        "All key references must be exact paths in the selected workspace.",
      );
    result[name] = value;
  }
  if (!Object.keys(result).length || Object.keys(result).length > 32)
    throw new ActionError("Specify 1–32 cv:// references in this step’s env.");
  return result;
}
export function serverOrigin(server: string): string {
  let u: URL;
  try {
    u = new URL(server);
  } catch {
    throw new ActionError("server must be an HTTPS origin.");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    u.pathname !== "/" ||
    (u.protocol !== "https:" && !(u.protocol === "http:" && local))
  )
    throw new ActionError(
      "server must be an HTTPS origin (HTTP loopback is allowed).",
    );
  return u.origin;
}
export async function resolveKeys(
  server: string,
  workspace: string,
  refs: Record<string, string>,
  token: string,
  fetcher: typeof fetch = fetch,
  wait: (ms: number) => Promise<void> = (ms) =>
    new Promise((resolve) => setTimeout(resolve, ms)),
): Promise<Record<string, string>> {
  const origin = serverOrigin(server);
  const body = JSON.stringify({ workspace_id: workspace, references: refs });
  for (let attempt = 0; attempt < 3; attempt++) {
    let response: Response;
    try {
      response = await fetcher(origin + "/v1/runtime/github-actions/resolve", {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body,
        signal: AbortSignal.timeout(15000),
      });
    } catch {
      if (attempt === 2)
        throw new ActionError("CIVault request failed after network retries.");
      await wait(500 * 2 ** attempt);
      continue;
    }
    if (response.status === 429 || response.status >= 500) {
      await response.body?.cancel();
      if (attempt === 2)
        throw new ActionError(
          `CIVault temporarily unavailable (HTTP ${response.status}).`,
        );
      const delay = Math.min(
        2000,
        Math.max(
          500 * 2 ** attempt,
          Number(response.headers.get("Retry-After") || 0) * 1000,
        ),
      );
      await wait(delay);
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new ActionError(
        `CIVault refused the request (HTTP ${response.status}). Check its audit log.`,
      );
    }
    const reader = response.body?.getReader();
    if (!reader) throw new ActionError("CIVault returned an empty response.");
    let size = 0;
    const chunks: Uint8Array[] = [];
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 2 * 1024 * 1024) {
          await reader.cancel();
          throw new ActionError("CIVault response exceeds the size limit.");
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof ActionError) throw error;
      if (attempt === 2)
        throw new ActionError(
          "CIVault response interrupted after network retries.",
        );
      await wait(500 * 2 ** attempt);
      continue;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw new ActionError("CIVault returned invalid JSON.");
    }
    const values = (decoded as { values?: unknown })?.values;
    if (!values || typeof values !== "object" || Array.isArray(values))
      throw new ActionError("CIVault returned an invalid values object.");
    const result = values as Record<string, unknown>;
    if (
      Object.keys(result).length !== Object.keys(refs).length ||
      Object.keys(refs).some((name) => !Object.hasOwn(result, name)) ||
      Object.entries(result).some(
        ([name, value]) =>
          !validName(name) ||
          typeof value !== "string" ||
          !value ||
          value.includes("\0") ||
          Buffer.byteLength(value) > 32768,
      )
    )
      throw new ActionError(
        "CIVault returned unexpected or invalid key values.",
      );
    return result as Record<string, string>;
  }
  throw new ActionError("CIVault request failed.");
}
