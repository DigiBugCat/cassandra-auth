import { Hono } from "hono";
import { pushMetrics, counter } from "cassandra-observability";
import { Enforcer } from "./enforcer";
import { buildPolicies, DEFAULT_CONFIG, loadConfigFromKV, saveConfigToKV } from "./policy";
import type { AclConfig, AclUser, AclGroup, AclDomain, CheckRequest } from "./types";

const app = new Hono<{ Bindings: Env }>();

// ── Mutable enforcer — loaded from KV on first request, rebuilt on policy changes ──

let enforcer: Enforcer | null = null;
let currentConfig: AclConfig | null = null;

async function getEnforcer(kv: KVNamespace): Promise<Enforcer> {
  if (enforcer && currentConfig) return enforcer;
  const config = (await loadConfigFromKV(kv)) ?? DEFAULT_CONFIG;
  currentConfig = config;
  enforcer = new Enforcer(buildPolicies(config));
  return enforcer;
}

async function getConfig(kv: KVNamespace): Promise<AclConfig> {
  if (currentConfig) return currentConfig;
  const config = (await loadConfigFromKV(kv)) ?? DEFAULT_CONFIG;
  currentConfig = config;
  return config;
}

function rebuildEnforcer(config: AclConfig) {
  currentConfig = config;
  enforcer = new Enforcer(buildPolicies(config));
}

// ── Auth helpers ──

function requireAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }): boolean {
  const secret = c.req.header("X-Auth-Secret");
  if (secret && secret === c.env.AUTH_SECRET) return true;

  const cfClientId = c.req.header("CF-Access-Client-Id");
  if (cfClientId && c.env.CF_ACCESS_CLIENT_ID && cfClientId === c.env.CF_ACCESS_CLIENT_ID) return true;

  return false;
}

function getAdminEmail(c: { req: { header: (name: string) => string | undefined } }): string {
  return c.req.header("X-Admin-Email")?.trim().toLowerCase() || "";
}

function isAdminUser(config: AclConfig, email: string): boolean {
  if (!email) return false;
  return config.users?.[email]?.role === "admin";
}

// ── Metrics middleware ──

app.use("*", async (c, next) => {
  const start = Date.now();
  await next();
  c.executionCtx.waitUntil(
    pushMetrics(c.env, [
      counter("mcp_requests_total", 1, {
        service: "auth",
        status: String(c.res.status),
        path: new URL(c.req.url).pathname,
      }),
      counter("mcp_request_duration_ms_total", Date.now() - start, {
        service: "auth",
        path: new URL(c.req.url).pathname,
      }),
    ]),
  );
});

// ── Health check ──

app.get("/health", (c) => c.json({ ok: true }));

// ── POST /check — ACL enforcement (unchanged) ──

app.post("/check", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const body = await c.req.json<CheckRequest>();
  if (!body.email || !body.service || !body.tool) {
    return c.json({ error: "email, service, and tool are required" }, 400);
  }

  const e = await getEnforcer(c.env.AUTH_CREDENTIALS);
  const result = e.enforce(body.email, body.service, body.tool);
  return c.json(result);
});

// ── GET /policy — return current policy (unchanged behavior, now from KV) ──

app.get("/policy", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const e = await getEnforcer(c.env.AUTH_CREDENTIALS);
  return c.json({ policies: buildPolicies(currentConfig!) });
});

// ── Credentials endpoints (unchanged) ──

app.post("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const credentials = await c.req.json<Record<string, string>>();

  const key = `cred:${email}:${service}`;
  await c.env.AUTH_CREDENTIALS.put(key, JSON.stringify(credentials));

  return c.json({ ok: true });
});

app.get("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const key = `cred:${email}:${service}`;
  const value = await c.env.AUTH_CREDENTIALS.get(key, "json");

  if (!value) return c.json({ credentials: null });
  return c.json({ credentials: value });
});

app.delete("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const key = `cred:${email}:${service}`;
  await c.env.AUTH_CREDENTIALS.delete(key);

  return c.json({ ok: true });
});

// ── POST /keys/validate — validate MCP API key (unchanged) ──

app.post("/keys/validate", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { key } = await c.req.json<{ key: string }>();
  if (!key) return c.json({ error: "key is required" }, 400);

  const raw = await c.env.MCP_KEYS.get(key);
  if (!raw) return c.json({ valid: false }, 404);

  let meta: Record<string, unknown>;
  try {
    meta = JSON.parse(raw);
  } catch {
    return c.json({ valid: false }, 500);
  }

  return c.json({
    valid: true,
    email: meta.created_by || meta.email,
    service: meta.service,
    credentials: meta.credentials || null,
  });
});

// ═══════════════════════════════════════════════════════
// ── ACL Admin CRUD endpoints (new)
// ═══════════════════════════════════════════════════════

// GET /acl/whoami — returns the caller's role (does NOT require admin)
app.get("/acl/whoami", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const email = getAdminEmail(c);
  if (!email) return c.json({ error: "X-Admin-Email header required" }, 400);

  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  const user = config.users?.[email];

  return c.json({
    email,
    role: user?.role || "user",
    groups: user?.groups || [],
    isAdmin: user?.role === "admin",
  });
});

// ── All remaining /acl/* endpoints require admin ──

// GET /acl/policy
app.get("/acl/policy", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  return c.json(config);
});

// PUT /acl/policy — replace full policy
app.put("/acl/policy", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const newConfig = await c.req.json<AclConfig>();
  if (!newConfig.default) return c.json({ error: "default field is required" }, 400);

  await saveConfigToKV(c.env.AUTH_CREDENTIALS, newConfig);
  rebuildEnforcer(newConfig);
  return c.json({ ok: true });
});

// GET /acl/users
app.get("/acl/users", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  return c.json(config.users || {});
});

// PUT /acl/users/:email
app.put("/acl/users/:email", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  const adminEmail = getAdminEmail(c);
  if (!isAdminUser(config, adminEmail)) return c.json({ error: "admin required" }, 403);

  const email = c.req.param("email").toLowerCase();
  const userData = await c.req.json<AclUser>();

  const updated: AclConfig = { ...config, users: { ...config.users, [email]: userData } };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// DELETE /acl/users/:email
app.delete("/acl/users/:email", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  const adminEmail = getAdminEmail(c);
  if (!isAdminUser(config, adminEmail)) return c.json({ error: "admin required" }, 403);

  const email = c.req.param("email").toLowerCase();

  // Prevent deleting yourself
  if (email === adminEmail) return c.json({ error: "cannot delete yourself" }, 400);

  const users = { ...config.users };
  delete users[email];
  const updated: AclConfig = { ...config, users };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// GET /acl/groups
app.get("/acl/groups", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  return c.json(config.groups || {});
});

// PUT /acl/groups/:name
app.put("/acl/groups/:name", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const name = c.req.param("name");
  const groupData = await c.req.json<AclGroup>();

  if (!groupData.services || typeof groupData.services !== "object") {
    return c.json({ error: "services field is required" }, 400);
  }

  const updated: AclConfig = { ...config, groups: { ...config.groups, [name]: groupData } };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// DELETE /acl/groups/:name
app.delete("/acl/groups/:name", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const name = c.req.param("name");
  const groups = { ...config.groups };
  delete groups[name];
  const updated: AclConfig = { ...config, groups };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// GET /acl/domains
app.get("/acl/domains", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  return c.json(config.domains || {});
});

// PUT /acl/domains/:domain
app.put("/acl/domains/:domain", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const domain = c.req.param("domain").toLowerCase();
  const domainData = await c.req.json<AclDomain>();

  const updated: AclConfig = { ...config, domains: { ...config.domains, [domain]: domainData } };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// DELETE /acl/domains/:domain
app.delete("/acl/domains/:domain", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const domain = c.req.param("domain").toLowerCase();
  const domains = { ...config.domains };
  delete domains[domain];
  const updated: AclConfig = { ...config, domains };
  await saveConfigToKV(c.env.AUTH_CREDENTIALS, updated);
  rebuildEnforcer(updated);
  return c.json({ ok: true });
});

// POST /acl/test — dry-run access check (admin only)
app.post("/acl/test", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  const config = await getConfig(c.env.AUTH_CREDENTIALS);
  if (!isAdminUser(config, getAdminEmail(c))) return c.json({ error: "admin required" }, 403);

  const body = await c.req.json<CheckRequest>();
  if (!body.email || !body.service || !body.tool) {
    return c.json({ error: "email, service, and tool are required" }, 400);
  }

  const e = await getEnforcer(c.env.AUTH_CREDENTIALS);
  const result = e.enforce(body.email, body.service, body.tool);
  return c.json(result);
});

export default app;
