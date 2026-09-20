import * as core from "@actions/core";
import { spawn } from "node:child_process";
import { ActionError } from "./client";
import { loadValues } from "./shared";

async function main() {
  const command = core.getInput("command", { required: true });
  const shell =
    core.getInput("shell") || (process.platform === "win32" ? "pwsh" : "bash");
  if (!["bash", "pwsh"].includes(shell))
    throw new ActionError("shell must be bash or pwsh.");
  const values = await loadValues();
  const env = { ...process.env };
  const names = new Set(Object.keys(values).map((x) => x.toUpperCase()));
  for (const name of Object.keys(env))
    if (names.has(name.toUpperCase())) delete env[name];
  Object.assign(env, values);
  const args =
    shell === "bash"
      ? ["--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command]
      : [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `$ErrorActionPreference='Stop'; ${command}; if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }`,
        ];
  try {
    const code = await new Promise<number>((resolve, reject) => {
      const child = spawn(shell, args, {
        env,
        cwd: core.getInput("working-directory") || undefined,
        stdio: "inherit",
        shell: false,
        windowsHide: true,
        detached: process.platform !== "win32",
      });
      let timer: NodeJS.Timeout | undefined;
      let cancelled = false;
      const kill = (force = false) => {
        if (!child.pid) return;
        if (process.platform === "win32") {
          spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
            stdio: "ignore",
            windowsHide: true,
          }).on("error", () => {
            child.kill();
          });
        } else {
          try {
            process.kill(-child.pid, force ? "SIGKILL" : "SIGTERM");
          } catch {
            /* Already exited. */
          }
        }
      };
      const cancel = () => {
        if (cancelled) return;
        cancelled = true;
        kill();
        timer = setTimeout(() => kill(true), 5000);
        timer.unref();
      };
      const cleanup = () => {
        process.off("SIGINT", cancel);
        process.off("SIGTERM", cancel);
        if (timer) clearTimeout(timer);
      };
      process.on("SIGINT", cancel);
      process.on("SIGTERM", cancel);
      child.once("error", () => {
        cleanup();
        reject(new ActionError("Unable to start the selected shell."));
      });
      child.once("close", (code, signal) => {
        cleanup();
        resolve(cancelled ? 130 : (code ?? (signal ? 130 : 1)));
      });
    });
    process.exitCode = code;
  } finally {
    for (const name of Object.keys(values)) {
      delete env[name];
      delete values[name];
    }
  }
}
main().catch((error) =>
  core.setFailed(
    error instanceof ActionError
      ? error.message
      : "Unable to execute command with CIVault keys. Check OIDC permissions and audit logs.",
  ),
);
