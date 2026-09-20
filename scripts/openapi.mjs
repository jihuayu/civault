// Canonical HTTP contract. Regenerate with node scripts/openapi.mjs.
import { readFile, writeFile, mkdir } from "node:fs/promises";

const str = (description = "") => ({
  type: "string",
  ...(description ? { description } : {}),
});
const boolean = { type: "boolean" };
const integer = { type: "integer" };
const timestamp = {
  type: ["integer", "null"],
  description: "Unix seconds, UTC; null means no expiry.",
};
const inputTime = {
  type: ["string", "null"],
  format: "date-time",
  description: "RFC3339 timestamp or explicit null to clear expiry.",
};
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const array = (items) => ({ type: "array", items });
const object = (properties, required = Object.keys(properties)) => ({
  type: "object",
  additionalProperties: false,
  properties,
  required,
});
const fields = {
  public_url: str("HTTPS origin; HTTP only on localhost, 127.0.0.1 or ::1."),
  owner_email: { type: "string", format: "email" },
  github_enabled: boolean,
  github_client_id: str(),
  email_provider: {
    type: "string",
    enum: ["resend", "agentmail"],
    default: "resend",
  },
  agentmail_inbox_id: str("Existing AgentMail inbox ID."),
  resend_enabled: {
    ...boolean,
    description:
      "Email notifications enabled for the selected provider; legacy field name retained for compatibility.",
  },
  resend_from: str("Verified Resend sender."),
  reminder_days: {
    type: "array",
    maxItems: 12,
    uniqueItems: true,
    items: { type: "integer", minimum: 1, maximum: 365 },
    default: [7, 3, 1],
  },
  notify_on_expiry: { ...boolean, default: true },
  log_level: { enum: ["debug", "info", "warn", "error"] },
  audit_retention_days: {
    type: "integer",
    minimum: 1,
    maximum: 3650,
    default: 180,
  },
};
const targetIDs = {
  ...array(str()),
  minItems: 1,
  maxItems: 100,
  uniqueItems: true,
};
const exactValues = {
  ...array(str("Exact value; no wildcards. Empty array means unrestricted.")),
  uniqueItems: true,
};
const schemas = {
  OK: object({ ok: boolean }),
  Error: object({
    error: object({ code: str(), message: str() }),
    request_id: str(),
  }),
  Status: object({ initialized: boolean, github_enabled: boolean }),
  Setup: object({
    code: {
      ...str("One-time code read from /data/setup-token."),
      writeOnly: true,
    },
    email: str(),
    password: { ...str(), minLength: 12, maxLength: 256, writeOnly: true },
    public_url: str(),
  }),
  Login: object({ email: str(), password: { ...str(), writeOnly: true } }),
  LoginResult: object({
    email: str(),
    csrf_token: str("Send X-CSRF-Token on cookie-authenticated mutations."),
  }),
  Session: object({ email: str(), csrf_token: str(), github_id: str() }),
  Settings: object({
    ...fields,
    revision: integer,
    github_secret_configured: boolean,
    resend_key_configured: boolean,
    agentmail_key_configured: boolean,
    github_id: str(),
  }),
  SettingsUpdate: object(
    {
      ...fields,
      revision: integer,
      github_secret: {
        ...str("Omit to preserve. Empty/masked replacements are rejected."),
        writeOnly: true,
      },
      resend_key: { ...str("Omit to preserve."), writeOnly: true },
      clear_github_secret: boolean,
      clear_resend_key: boolean,
      agentmail_key: { ...str("Omit to preserve."), writeOnly: true },
      clear_agentmail_key: boolean,
    },
    [
      ...Object.keys(fields).filter(
        (key) => !["email_provider", "agentmail_inbox_id"].includes(key),
      ),
      "revision",
    ],
  ),
  PasswordChange: object({
    current_password: { ...str(), writeOnly: true },
    new_password: {
      ...str("Revokes all web sessions and admin tokens."),
      minLength: 12,
      maxLength: 256,
      writeOnly: true,
    },
  }),
  Password: object({ password: { ...str(), writeOnly: true } }),
  Name: object({ name: { ...str(), minLength: 1, maxLength: 200 } }),
  Workspace: object({ id: str(), name: str(), created_at: integer }, [
    "id",
    "name",
  ]),
  Tag: object({ id: str(), name: str() }),
  Key: object({
    id: str(),
    workspace_id: str(),
    path: str(),
    active_version_id: { type: ["string", "null"] },
    disabled: boolean,
    created_at: integer,
    tags: array(ref("Tag")),
    expires_at: timestamp,
    version: integer,
  }),
  KeyWrite: object(
    {
      path: str(
        "Unique slash-separated path, <=200 UTF-8 bytes. Deleted paths cannot be reused.",
      ),
      value: {
        ...str(
          "1–32768 UTF-8 bytes; no NUL. Whitespace is preserved. Never returned to admin callers.",
        ),
        writeOnly: true,
      },
      expires_at: inputTime,
    },
    ["path", "value"],
  ),
  KeyWriteResult: object({
    id: str(),
    version_id: str(),
    number: integer,
    path: str(),
  }),
  State: object({ disabled: boolean }),
  KeyTags: object({ tag_ids: { ...array(str()), uniqueItems: true } }),
  Version: object({
    id: str(),
    number: integer,
    expires_at: timestamp,
    expiry_revision: integer,
    created_at: integer,
    active: { type: "integer", enum: [0, 1] },
  }),
  Expiry: object({ expires_at: inputTime }),
  Rule: {
    ...object(
      {
        key_ids: targetIDs,
        tag_ids: targetIDs,
        repository_owner_id: { type: "string", pattern: "^[0-9]+$" },
        repository_id: { type: "string", pattern: "^([0-9]+)?$" },
        workflow_path: str(
          "Exact .github/workflows/name.yml or .yaml, requires repository_id. Checks workflow_ref, not job_workflow_ref or a uses step.",
        ),
        workflow_sha: { type: "string", pattern: "^([0-9a-fA-F]{40})?$" },
        refs: exactValues,
        environments: exactValues,
        events: exactValues,
        runner_environments: {
          type: "array",
          items: { enum: ["github-hosted", "self-hosted"] },
          uniqueItems: true,
        },
      },
      ["repository_owner_id"],
    ),
    oneOf: [
      { required: ["key_ids"], properties: { tag_ids: false } },
      { required: ["tag_ids"], properties: { key_ids: false } },
    ],
    description:
      "Exactly one target selector. Tag IDs match ANY current tag. Target and every nonempty workload condition are AND; values and complete policies are OR. No override/deny rules.",
  },
  PolicyInput: object({ name: str(), rule: ref("Rule") }),
  Policy: object({
    id: str(),
    name: str(),
    version: integer,
    disabled: boolean,
    rule: ref("Rule"),
  }),
  PolicyResult: object({ id: str(), version: integer }),
  PolicyVersion: object({
    version: integer,
    spec: ref("Rule"),
    created_at: integer,
  }),
  TokenInput: object(
    {
      name: str(),
      days: { type: "integer", minimum: 1, maximum: 365, default: 30 },
    },
    ["name"],
  ),
  Token: object({
    id: str(),
    name: str(),
    created_at: integer,
    expires_at: integer,
    revoked: { type: "integer", enum: [0, 1] },
  }),
  TokenCreated: object({
    id: str(),
    token: str("Shown once; only its SHA-256 digest is stored."),
    expires_at: integer,
  }),
  Audit: object({
    id: str(),
    created_at: integer,
    request_id: str(),
    actor: str(),
    event: str(),
    decision: { enum: ["allow", "deny"] },
    workspace_id: str(),
    details: { type: "object", additionalProperties: true },
  }),
  Notification: object({
    id: str(),
    path: str(),
    workspace_id: str(),
    version_id: str(),
    expiry_revision: integer,
    threshold: integer,
    status: {
      enum: [
        "pending",
        "sending",
        "retry",
        "sent",
        "cancelled",
        "failed",
        "needs_attention",
      ],
    },
    attempts: integer,
    created_at: integer,
    sent_at: timestamp,
    provider_id: str(),
    last_error: str(),
  }),
  TestEmailResult: object({ provider_id: str() }),
  Resolve: object({
    workspace_id: str(),
    references: {
      type: "object",
      minProperties: 1,
      maxProperties: 32,
      additionalProperties: str(
        "cv://<workspace_id>/<key-path>; all references must belong to workspace_id. Percent-encode path segments. Case-colliding and reserved names are rejected.",
      ),
    },
  }),
  Resolved: object({
    request_id: str(),
    values: {
      type: "object",
      additionalProperties: str(
        "Plaintext UTF-8 value. All requested keys succeed atomically or none are returned.",
      ),
    },
  }),
};
const spec = {
  openapi: "3.1.0",
  info: {
    title: "CIVault API",
    version: "1.0.0",
    description:
      "Single Owner CI Secrets Manager. JSON requests <=64 KiB; timestamps in responses use Unix seconds, inputs use RFC3339. Responses are no-store. Management APIs never return Key plaintext or configured provider credentials. Unpaginated resource lists suit a single-owner instance.",
  },
  servers: [{ url: "/", description: "Same origin as the console." }],
  security: [{ AdminToken: [] }, { OwnerSession: [] }],
  paths: {},
  components: {
    schemas,
    securitySchemes: {
      AdminToken: {
        type: "http",
        scheme: "bearer",
        description:
          "Owner admin token (30 days by default); not a GitHub token.",
      },
      OwnerSession: {
        type: "apiKey",
        in: "cookie",
        name: "civault_session",
        description:
          "8 hours. HttpOnly, SameSite=Lax, Secure on HTTPS. Mutation requires X-CSRF-Token from login/me and same-origin Origin when present.",
      },
      GithubOIDC: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        description:
          "GitHub issuer, RS256, official JWKS. Single audience urn:civault:workspace:<workspace_id>. Same JWT can deliver the identical request at most 3 times within 60 seconds; retries pin initial versions and recheck live permissions, tags, expiry and key state.",
      },
    },
  },
};
const response = (schema) => ({
  description: "Success",
  content: {
    "application/json": {
      schema: typeof schema === "string" ? ref(schema) : schema,
    },
  },
});
function op(
  method,
  path,
  summary,
  input,
  output = "OK",
  status = 200,
  extra = {},
) {
  const parameters = [...path.matchAll(/\{(\w+)\}/g)].map((m) => ({
    name: m[1],
    in: "path",
    required: true,
    schema: str(),
  }));
  if (!["get", "head"].includes(method) && !extra.security)
    parameters.push({
      name: "X-CSRF-Token",
      in: "header",
      schema: str(),
      description:
        "Required for cookie authentication; omitted for Bearer admin token.",
    });
  const operation = {
    summary,
    operationId: method + path.replace(/[^a-z0-9]/gi, "_"),
    parameters,
    responses: {
      [status]: response(output),
      default: {
        description:
          "400 invalid request, 401 authentication required, 403 denied, 404 not found, 409 conflict, 429 rate limited, or 500 unavailable; no partial secret results.",
        content: { "application/json": { schema: ref("Error") } },
      },
    },
    ...extra,
  };
  if (input)
    operation.requestBody = {
      required: true,
      content: {
        "application/json": {
          schema: typeof input === "string" ? ref(input) : input,
        },
      },
    };
  (spec.paths[path] ||= {})[method] = operation;
  return operation;
}
const anon = { security: [] };
op("get", "/healthz", "SQLite health", null, "OK", 200, anon);
op(
  "get",
  "/v1/status",
  "Initialization and public login availability",
  null,
  "Status",
  200,
  anon,
);
op(
  "post",
  "/v1/setup",
  "One-time setup; permanently closes after initialization",
  "Setup",
  object({ initialized: boolean }),
  201,
  anon,
);
op(
  "post",
  "/v1/auth/login",
  "Password login; 5 attempts/IP/minute",
  "Login",
  "LoginResult",
  200,
  anon,
);
op("get", "/v1/auth/me", "Current Owner and CSRF token", null, "Session");
op("post", "/v1/auth/logout", "Delete current web session", null);
op(
  "get",
  "/v1/auth/github",
  "Start GitHub Authorization Code flow with state and PKCE",
  null,
  {},
  302,
  {
    ...anon,
    responses: {
      302: {
        description: "Redirects to GitHub. Sets browser-bound OAuth cookie.",
      },
      default: response("Error"),
    },
  },
);
op(
  "get",
  "/v1/auth/github/callback",
  "Consume OAuth code and log in/bind verified Owner",
  null,
  {},
  303,
  {
    ...anon,
    parameters: ["state", "code"].map((name) => ({
      name,
      in: "query",
      required: true,
      schema: str(),
    })),
    responses: {
      303: { description: "Session created; redirects to console." },
      default: response("Error"),
    },
  },
);
op(
  "get",
  "/v1/admin/settings",
  "Current configuration; sensitive fields return only configured flags",
  null,
  "Settings",
);
op(
  "put",
  "/v1/admin/settings",
  "Atomically replace settings; revision conflict returns 409",
  "SettingsUpdate",
  "Settings",
);
op(
  "post",
  "/v1/admin/password",
  "Change password and revoke ALL sessions and admin tokens",
  "PasswordChange",
);
op(
  "delete",
  "/v1/admin/github-binding",
  "Unlink bound GitHub ID using local password",
  "Password",
);
op(
  "get",
  "/v1/admin/workspaces",
  "List workspaces",
  null,
  array(ref("Workspace")),
);
op(
  "post",
  "/v1/admin/workspaces",
  "Create workspace",
  "Name",
  "Workspace",
  201,
);
const ws = "/v1/admin/workspaces/{ws}";
op(
  "get",
  ws + "/keys",
  "List key metadata (never values)",
  null,
  array(ref("Key")),
);
op(
  "post",
  ws + "/keys",
  "Create key or append and activate an immutable encrypted version",
  "KeyWrite",
  "KeyWriteResult",
  201,
).parameters.push({
  name: "Idempotency-Key",
  in: "header",
  schema: { type: "string", maxLength: 200 },
  description:
    "Optional. Scoped to actor and workspace for 24h. Same key/body replays metadata response; changed body returns 409. Keep the same key when retrying a write.",
});
op(
  "patch",
  ws + "/keys/{key}",
  "Enable/disable a key and cancel obsolete notifications",
  "State",
);
op(
  "delete",
  ws + "/keys/{key}",
  "Soft-delete a key; no further issuance",
  null,
);
op(
  "put",
  ws + "/keys/{key}/tags",
  "Replace all tags; live OR authorization applies immediately",
  "KeyTags",
);
op(
  "get",
  ws + "/keys/{key}/versions",
  "List version metadata; ciphertext and plaintext omitted",
  null,
  array(ref("Version")),
);
op(
  "post",
  ws + "/keys/{key}/versions/{version}/activate",
  "Activate/roll back to a nonexpired version",
  null,
);
op(
  "patch",
  ws + "/keys/{key}/versions/{version}",
  "Change lifecycle metadata, never ciphertext",
  "Expiry",
);
op("get", ws + "/tags", "List tags", null, array(ref("Tag")));
op("post", ws + "/tags", "Create a stable tag ID", "Name", "Tag");
op(
  "patch",
  ws + "/tags/{tag}",
  "Rename without changing policy targets",
  "Name",
  "Tag",
);
op(
  "delete",
  ws + "/tags/{tag}",
  "Delete unused tag; any historical rule reference blocks deletion",
  null,
);
op(
  "get",
  ws + "/policies",
  "List active policy revisions",
  null,
  array(ref("Policy")),
);
op(
  "post",
  ws + "/policies",
  "Create policy or append immutable revision by name",
  "PolicyInput",
  "PolicyResult",
  201,
);
op("patch", ws + "/policies/{policy}", "Enable/disable policy", "State");
op(
  "get",
  ws + "/policies/{policy}/versions",
  "List immutable policy versions",
  null,
  array(ref("PolicyVersion")),
);
op(
  "post",
  ws + "/policy-preview",
  "Preview current key coverage by a rule target",
  "Rule",
  array(ref("Key")),
);
op(
  "get",
  "/v1/admin/tokens",
  "List token metadata; no plaintext/digests",
  null,
  array(ref("Token")),
);
op(
  "post",
  "/v1/admin/tokens",
  "Create one-time displayed Owner management token",
  "TokenInput",
  "TokenCreated",
  201,
);
op(
  "delete",
  "/v1/admin/tokens/{token}",
  "Revoke management token immediately",
  null,
);
const audit = op(
  "get",
  "/v1/admin/audit-events",
  "Query/filter/export audit events",
  null,
  array(ref("Audit")),
);
for (const name of [
  "decision",
  "event",
  "workspace_id",
  "repository_id",
  "request_id",
  "from",
  "to",
])
  audit.parameters.push({
    name,
    in: "query",
    schema: ["from", "to"].includes(name)
      ? { type: "string", format: "date-time" }
      : str(),
  });
const notifications = op(
  "get",
  "/v1/admin/notifications",
  "View durable notification outcomes; unknown sends are never automatically replayed",
  null,
  array(ref("Notification")),
);
notifications.parameters.push({ name: "status", in: "query", schema: str() });
for (const operation of [audit, notifications])
  for (const [name, def, max] of [
    ["limit", 100, 1000],
    ["offset", 0, 1000000],
  ])
    operation.parameters.push({
      name,
      in: "query",
      schema: { type: "integer", minimum: 0, maximum: max, default: def },
    });
op(
  "post",
  "/v1/admin/notifications/test",
  "Send test email to saved Owner address; 3/IP/minute",
  null,
  "TestEmailResult",
);
op(
  "post",
  "/v1/runtime/github-actions/resolve",
  "Resolve explicit references atomically, using live GitHub workload authorization",
  "Resolve",
  "Resolved",
  200,
  { security: [{ GithubOIDC: [] }] },
);
op(
  "get",
  "/openapi.json",
  "This OpenAPI document",
  null,
  { type: "object" },
  200,
  anon,
);

const routes = await readFile("internal/vault/http.go", "utf8");
for (const match of routes.matchAll(
  /(?:HandleFunc|reg)\("(GET|POST|PUT|PATCH|DELETE) ([^" ]+)"/g,
)) {
  if (!spec.paths[match[2]]?.[match[1].toLowerCase()])
    throw new Error(`Undocumented route ${match[1]} ${match[2]}`);
}
const output = JSON.stringify(spec, null, 2) + "\n";
if (process.argv.includes("--check")) {
  if ((await readFile("docs/openapi.json", "utf8")) !== output)
    throw new Error("OpenAPI stale: run node scripts/openapi.mjs");
} else {
  await mkdir("docs", { recursive: true });
  await writeFile("docs/openapi.json", output);
}
