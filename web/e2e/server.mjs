import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve("..");
await mkdir(resolve(root, ".dev"), { recursive: true });
const data = await mkdtemp(resolve(root, ".dev/e2e-"));
await writeFile(resolve(root, ".dev/e2e-current"), data);
// Temporary test data only. No external credentials or authentication bypass.
const child = spawn(
  resolve(
    root,
    "bin/civault-server" + (process.platform === "win32" ? ".exe" : ""),
  ),
  ["-data-dir", data, "-listen", "127.0.0.1:18081"],
  {
    env: {
      ...process.env,
      CIVAULT_MASTER_KEY: randomBytes(32).toString("base64"),
    },
    stdio: "inherit",
    windowsHide: true,
  },
);
process.on("SIGTERM", () => child.kill());
process.on("SIGINT", () => child.kill());
child.on("exit", (code) => process.exit(code ?? 1));
child.on("error", () => {
  console.error("Build bin/civault-server before running browser tests.");
  process.exit(1);
});
