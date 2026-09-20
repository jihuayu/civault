import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

describe("compiled GitHub Actions", () => {
  let server: Server;
  let origin: string;
  const secret = "synthetic-action-key\nsecond-line";
  beforeAll(async () => {
    server = createServer((req, res) => {
      res.setHeader("Content-Type", "application/json");
      if (req.url?.startsWith("/oidc")) {
        res.end(JSON.stringify({ value: "synthetic-oidc-jwt" }));
        return;
      }
      if (req.url === "/v1/runtime/github-actions/resolve") {
        let body = "";
        req.on("data", (b) => (body += b));
        req.on("end", () => {
          const input = JSON.parse(body);
          if (
            input.workspace_id !== "ws_default" ||
            req.headers.authorization !== "Bearer synthetic-oidc-jwt"
          ) {
            res.writeHead(403);
            res.end("{}");
            return;
          }
          res.end(
            JSON.stringify({
              request_id: "req_test",
              values: { TEST_SECRET: secret },
            }),
          );
        });
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  async function run(
    entry: string,
    extra: Record<string, string> = {},
    cancel = false,
  ) {
    const dir = await mkdtemp(join(tmpdir(), "civault-action-"));
    const envFile = join(dir, "env");
    const outputFile = join(dir, "output");
    await writeFile(envFile, "");
    await writeFile(outputFile, "");
    const env = {
      ...process.env,
      ACTIONS_ID_TOKEN_REQUEST_URL: origin + "/oidc",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "synthetic-request-token",
      INPUT_SERVER: origin,
      INPUT_WORKSPACE: "ws_default",
      "INPUT_EXPORT-ENV": "false",
      GITHUB_ENV: envFile,
      GITHUB_OUTPUT: outputFile,
      TEST_SECRET: "cv://ws_default/key",
      ...extra,
    };
    // Windows kill(SIGTERM) forcibly terminates Node without delivering a signal.
    // A test-only IPC bridge exercises the real signal handler and taskkill tree cleanup.
    const bridge = join(dir, "signal.cjs");
    await writeFile(
      bridge,
      'process.once("message",()=>{process.emit("SIGTERM");process.disconnect();});',
    );
    const bridged = cancel && process.platform === "win32";
    const args = [
      ...(bridged ? ["--require", bridge] : []),
      resolve("dist/" + entry + ".cjs"),
    ];
    try {
      const result = await new Promise<{
        code: number | null;
        stdout: string;
        stderr: string;
      }>((resolveResult, reject) => {
        const child = spawn(process.execPath, args, {
          env,
          stdio: [
            "ignore",
            "pipe",
            "pipe",
            ...(bridged ? ["ipc" as const] : []),
          ],
          windowsHide: true,
        });
        let stdout = "",
          stderr = "",
          cancelled = false;
        child.stdout!.on("data", (b) => {
          stdout += b;
          if (cancel && !cancelled && stdout.includes("CHILD_READY")) {
            cancelled = true;
            if (bridged) child.send("cancel");
            else child.kill("SIGTERM");
          }
        });
        child.stderr!.on("data", (b) => (stderr += b));
        child.on("error", reject);
        child.on("close", (code) => resolveResult({ code, stdout, stderr }));
      });
      return {
        ...result,
        environment: await readFile(envFile, "utf8"),
        outputs: await readFile(outputFile, "utf8"),
      };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
  it("masks multiline values and writes outputs without exporting by default", async () => {
    const r = await run("load");
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain(
      "::add-mask::synthetic-action-key%0Asecond-line",
    );
    expect(r.outputs).toContain(secret);
    expect(r.environment).toBe("");
  });
  it("exports through GITHUB_ENV when explicitly requested", async () => {
    const r = await run("load", { "INPUT_EXPORT-ENV": "true" });
    expect(r.code, r.stderr).toBe(0);
    expect(r.environment).toContain(secret);
    expect(r.environment).toMatch(/TEST_SECRET<<ghadelimiter_/);
  });
  it("injects into child command only and propagates its exit code", async () => {
    const script = `if(process.env.TEST_SECRET!==${JSON.stringify(secret)})process.exit(99);process.exit(7)`;
    const command =
      process.platform === "win32"
        ? `& '${process.execPath.replaceAll("'", "''")}' -e '${script.replaceAll("'", "''")}'`
        : `'${process.execPath.replaceAll("'", "'\\''")}' -e '${script.replaceAll("'", "'\\''")}'`;
    const r = await run("exec", { INPUT_COMMAND: command });
    expect(r.code, r.stderr).toBe(7);
    expect(r.environment).toBe("");
    expect(r.outputs).toBe("");
  });
  it("propagates cancellation and terminates the child process tree", async () => {
    const script =
      'process.on("SIGTERM",()=>process.exit(0));console.log("CHILD_READY");setInterval(()=>{},1000)';
    const command =
      process.platform === "win32"
        ? `& '${process.execPath.replaceAll("'", "''")}' -e '${script}'`
        : `'${process.execPath.replaceAll("'", "'\\''")}' -e '${script}'`;
    const r = await run("exec", { INPUT_COMMAND: command }, true);
    expect(r.code, r.stderr).toBe(130);
    expect(r.outputs).toBe("");
    expect(r.environment).toBe("");
  });
});
