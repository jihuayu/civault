// Real GitHub OIDC acceptance fixture. Only synthetic credentials are created.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile, appendFile, open } from "node:fs/promises";
import { resolve } from "node:path";
import assert from "node:assert/strict";

const origin = "http://127.0.0.1:18082";
// A reusable workflow's OIDC workflow_ref identifies the caller workflow.
const workflowPrefix = `${process.env.GITHUB_REPOSITORY}/`;
assert.ok(process.env.GITHUB_WORKFLOW_REF?.startsWith(workflowPrefix));
const workflowPath = process.env.GITHUB_WORKFLOW_REF.slice(workflowPrefix.length).split("@")[0];
assert.ok(workflowPath.startsWith(".github/workflows/"));
assert.ok(process.env.GITHUB_EVENT_NAME);
await mkdir(".dev/oidc", { recursive: true });
const log = await open(".dev/oidc/server.log", "a");
const child = spawn(
  resolve("bin/civault-server" + (process.platform === "win32" ? ".exe" : "")),
  ["-data-dir", ".dev/oidc/data", "-listen", "127.0.0.1:18082"],
  {
    env: {
      ...process.env,
      CIVAULT_MASTER_KEY: randomBytes(32).toString("base64"),
    },
    detached: true,
    stdio: ["ignore", log.fd, log.fd],
    windowsHide: true,
  },
);
child.unref();
await writeFile(".dev/oidc/pid", String(child.pid));
let ready = false;
for (let n = 0; n < 60; n++) {
  try {
    if ((await fetch(origin + "/healthz")).ok) {
      ready = true;
      break;
    }
  } catch {
    /* Starting. */
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
}
assert.ok(ready, "Server did not start");
const password = randomBytes(32).toString("hex");
const code = await readFile(".dev/oidc/data/setup-token", "utf8");
async function request(path, body, headers = {}) {
  const r = await fetch(origin + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  assert.ok(r.ok, `Fixture HTTP ${r.status}`);
  return r;
}
await request("/v1/setup", {
  code,
  email: "ci@example.com",
  password,
  public_url: origin,
});
const login = await request("/v1/auth/login", {
  email: "ci@example.com",
  password,
});
const cookie = login.headers
  .getSetCookie()
  .find((x) => x.startsWith("civault_session="))
  .split(";")[0];
const headers = {
  Cookie: cookie,
  "X-CSRF-Token": (await login.json()).csrf_token,
};
const value = "civault-smoke\nsecond line % : 🥇";
const key = await (
  await request(
    "/v1/admin/workspaces/ws_default/keys",
    { path: "smoke/token", value },
    headers,
  )
).json();
await request(
  "/v1/admin/workspaces/ws_default/policies",
  {
    name: "smoke-workflow-only",
    rule: {
      key_ids: [key.id],
      repository_owner_id: process.env.OWNER_ID,
      repository_id: process.env.REPO_ID,
      workflow_path: workflowPath,
      refs: [process.env.GITHUB_REF],
      events: [process.env.GITHUB_EVENT_NAME],
      runner_environments: ["github-hosted"],
    },
  },
  headers,
);
await appendFile(process.env.GITHUB_ENV, `CIVAULT_SMOKE_SERVER=${origin}\n`);
await log.close();
console.log("Synthetic key and exact workflow authorization created.");
