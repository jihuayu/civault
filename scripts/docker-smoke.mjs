import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";

const suffix = randomBytes(6).toString("hex");
const name = `civault-test-${suffix}`,
  restored = `${name}-restored`;
const volume = `${name}-data`,
  restoredVolume = `${name}-restore-data`;
const master = randomBytes(32).toString("base64");
const env = { ...process.env, CIVAULT_MASTER_KEY: master };
const image = process.env.CIVAULT_TEST_IMAGE || "civault:ci";
function logsFor(container) {
  const result = spawnSync("docker", ["logs", container], {
    encoding: "utf8", windowsHide: true, timeout: 10_000,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, "Could not read container logs");
  return result.stdout + result.stderr;
}
function docker(args, customEnv = env) {
  return execFileSync("docker", args, {
    env: customEnv,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    timeout: 120_000,
  }).trim();
}
function start(container, dataVolume) {
  docker([
    "run",
    "-d",
    "--name",
    container,
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=16m",
    "-e",
    "CIVAULT_MASTER_KEY",
    "-v",
    `${dataVolume}:/data`,
    "-p",
    "127.0.0.1::8080",
    image,
  ]);
  return originFor(container);
}
function originFor(container) {
  return `http://${docker(["port", container, "8080/tcp"]).split("\n")[0]}`;
}
async function healthy(origin) {
  for (let i = 0; i < 60; i++) {
    try {
      if (
        (
          await fetch(origin + "/healthz", {
            signal: AbortSignal.timeout(1000),
          })
        ).ok
      )
        return;
    } catch {
      /* Starting. */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Container health check failed");
}
try {
  docker(["volume", "create", volume]);
  docker(["volume", "create", restoredVolume]);
  let origin = start(name, volume);
  await healthy(origin);
  assert.equal(docker(["exec", name, "id", "-u"]), "10001");
  assert.match(await (await fetch(origin + "/")).text(), /<html/i);
  assert.equal((await fetch(origin + "/v1/admin/workspaces")).status, 401);
  const code = docker(["exec", name, "cat", "/data/setup-token"]);
  async function request(url, path, method = "GET", body, headers = {}) {
    const r = await fetch(url + path, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.ok(r.ok, `Unexpected HTTP ${r.status} on ${path}`);
    return r;
  }
  await request(origin, "/v1/setup", "POST", {
    code,
    email: "container@example.com",
    password: "Synthetic-container-password",
    public_url: origin,
  });
  const login = await request(origin, "/v1/auth/login", "POST", {
    email: "container@example.com",
    password: "Synthetic-container-password",
  });
  const cookie = login.headers
    .getSetCookie()
    .find((x) => x.startsWith("civault_session="))
    .split(";")[0];
  const csrf = (await login.json()).csrf_token;
  const headers = { Cookie: cookie, "X-CSRF-Token": csrf };
  await request(
    origin,
    "/v1/admin/workspaces/ws_default/keys",
    "POST",
    { path: "test/persistent", value: "synthetic-container-key" },
    headers,
  );
  docker(["restart", name]);
  // Docker may assign a different ephemeral host port when restarting.
  const previousOrigin = origin;
  origin = originFor(name);
  console.log(`Container restart address: ${previousOrigin} -> ${origin}`);
  await healthy(origin);
  assert.equal(
    (
      await (
        await request(
          origin,
          "/v1/admin/workspaces/ws_default/keys",
          "GET",
          undefined,
          headers,
        )
      ).json()
    ).length,
    1,
  );
  assert.throws(() => docker(["exec", name, "cat", "/data/setup-token"]));
  docker(["exec", name, "civault-server", "-backup", "/data/backup.db"]);
  const logs = logsFor(name);
  for (const sensitive of [
    master,
    code,
    csrf,
    "synthetic-container-key",
    "Synthetic-container-password",
  ])
    assert.equal(
      logs.includes(sensitive),
      false,
      "Sensitive value in runtime logs",
    );
  docker(["stop", name]);
  assert.throws(() =>
    docker(
      [
        "run",
        "--rm",
        "-e",
        "CIVAULT_MASTER_KEY",
        "-v",
        `${volume}:/data`,
        image,
      ],
      { ...env, CIVAULT_MASTER_KEY: randomBytes(32).toString("base64") },
    ),
    (error) => error.status === 1 &&
      String(error.stderr).includes("master key does not match database"),
  );
  // Restore only into a newly created test volume. The source is mounted read-only.
  docker([
    "run",
    "--rm",
    "--user",
    "0",
    "--entrypoint",
    "sh",
    "-v",
    `${volume}:/source:ro`,
    "-v",
    `${restoredVolume}:/data`,
    image,
    "-c",
    "cp /source/backup.db /data/civault.db && chown 10001:10001 /data/civault.db && chmod 600 /data/civault.db",
  ]);
  const restoredOrigin = start(restored, restoredVolume);
  await healthy(restoredOrigin);
  const keys = await (
    await request(
      restoredOrigin,
      "/v1/admin/workspaces/ws_default/keys",
      "GET",
      undefined,
      headers,
    )
  ).json();
  assert.equal(keys[0].path, "test/persistent");
  assert.equal(
    (await (await request(restoredOrigin, "/v1/status")).json()).initialized,
    true,
  );
  console.log(
    "Container restart, encrypted persistence, wrong-master rejection and backup/restore passed.",
  );
} catch (error) {
  // Only synthetic test containers are inspected; never dump Config.Env.
  for (const container of [name, restored]) {
    try {
      console.error(docker(["inspect", "--format", "{{json .State}}", container]));
      console.error(logsFor(container).replaceAll(master, "[REDACTED]"));
    } catch { /* The container may not have been created. */ }
  }
  throw error;
} finally {
  // All names above are task-specific constants containing a fresh random suffix.
  for (const container of [name, restored]) {
    try {
      docker(["rm", "-f", container]);
    } catch {
      /* Not created. */
    }
  }
  for (const dataVolume of [volume, restoredVolume]) {
    try {
      docker(["volume", "rm", dataVolume]);
    } catch {
      /* Not created. */
    }
  }
}
