import * as core from "@actions/core";
import { references, resolveKeys, serverOrigin } from "./client";

export async function loadValues(): Promise<Record<string, string>> {
  const workspace = core.getInput("workspace", { required: true });
  const server = serverOrigin(core.getInput("server", { required: true }));
  const refs = references(process.env, workspace);
  const token = await core.getIDToken(`urn:civault:workspace:${workspace}`);
  core.setSecret(token);
  const values = await resolveKeys(server, workspace, refs, token);
  // Register every mask before emitting any value into outputs or environment files.
  for (const value of Object.values(values)) core.setSecret(value);
  return values;
}
