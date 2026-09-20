import * as core from "@actions/core";
import { ActionError } from "./client";
import { loadValues } from "./shared";

async function main() {
  const exportEnv = core.getBooleanInput("export-env");
  const values = await loadValues();
  try {
    for (const [name, value] of Object.entries(values)) {
      core.setOutput(name, value);
      if (exportEnv) core.exportVariable(name, value);
    }
  } finally {
    for (const name of Object.keys(values)) delete values[name];
  }
}
main().catch((error) =>
  core.setFailed(
    error instanceof ActionError
      ? error.message
      : "Unable to load keys. Check OIDC permissions and CIVault audit logs.",
  ),
);
