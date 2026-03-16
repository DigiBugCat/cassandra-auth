# CLAUDE.md — Cassandra Auth

## What This Is

Shared auth package + centralized ACL service for the Cassandra platform. Two parts:

1. **Shared auth library** — TypeScript (CF Workers) and Python (FastMCP servers) packages for MCP API key resolution, WorkOS OAuth, ACL enforcement, and metrics middleware.
2. **ACL Worker** — CF Worker providing centralized access control, MCP key validation, and per-user credential storage.

## Repo Structure

```
cassandra-auth/
├── src/                           # TypeScript package (CF Workers)
│   ├── index.ts                   # Public API: createMcpWorker + types + advanced escape hatch
│   ├── advanced.ts                # Lower-level exports for custom integrations
│   ├── types.ts                   # McpAuthEnv, ResolvedAuth, McpWorkerConfig
│   ├── auth.ts                    # resolveExternalToken (mcp_ key + WorkOS JWT)
│   ├── worker.ts                  # createMcpWorker() factory
│   ├── workos-handler.ts          # WorkOS OAuth handler (Hono)
│   ├── workers-oauth-utils.ts     # CSRF, state, session utils
│   └── utils.ts                   # WorkOS token exchange
├── python/                        # Python package (FastMCP servers)
│   └── src/cassandra_mcp_auth/
│       ├── __init__.py            # Public API exports
│       ├── auth.py                # McpKeyAuthProvider — validates mcp_ keys via ACL /keys/validate
│       └── acl.py                 # Enforcer — local YAML-based ACL policy enforcement
├── worker/                        # ACL CF Worker
│   ├── src/
│   │   ├── index.ts               # Hono app with all endpoints
│   │   ├── enforcer.ts            # Casbin-compatible enforcer (lightweight, no Node.js deps)
│   │   ├── policy.ts              # Parses env/acl.yaml at build time → policy lines
│   │   └── types.ts               # Request/response types
│   ├── wrangler.jsonc.example
│   ├── package.json
│   └── tsconfig.json
├── infra/
│   └── modules/auth-worker/          # Terraform: KV, DNS
├── tests/                         # TypeScript tests
├── package.json                   # TS package config
├── tsconfig.json
├── .woodpecker.yaml
└── CLAUDE.md
```

## TypeScript Package (CF Workers)

Consumed via `github:DigiBugCat/cassandra-auth` in Worker `package.json` files.

### Usage

```ts
import { createMcpWorker } from "cassandra-mcp-auth";

const { default: worker, McpAgentClass } = createMcpWorker<Env, MyCredentials>({
  serviceId: "my-service",
  name: "My MCP Service",
  registerTools(server, env, auth) {
    server.registerTool("my_tool", { ... }, async (args) => { ... });
  },
});

export { McpAgentClass as MyServiceMCP };
export default worker;
```

### Consumer Requirements

Each Worker using this package needs:

#### Bindings (wrangler.jsonc)
- `MCP_OBJECT` — Durable Object (MUST be this name)
- `OAUTH_KV` — Per-service KV for OAuth state
- `MCP_KEYS` — Shared KV for API key auth

#### Secrets (wrangler secret put)
- `WORKOS_CLIENT_ID` — Shared WorkOS app
- `WORKOS_CLIENT_SECRET` — Shared WorkOS app
- `COOKIE_ENCRYPTION_KEY` — Session encryption
- `VM_PUSH_URL` — VictoriaMetrics push endpoint
- `VM_PUSH_CLIENT_ID` — CF Access service token for metrics
- `VM_PUSH_CLIENT_SECRET` — CF Access service token for metrics

## Python Package (FastMCP servers)

For Python/FastMCP MCP servers that run as k8s sidecar containers (not CF Workers).

### McpKeyAuthProvider

Validates `Bearer mcp_...` tokens by calling the ACL service's `POST /keys/validate` endpoint. Returns user email, service scope, and optional per-key credentials. Requires `AUTH_URL` and `AUTH_SECRET` env vars.

### Enforcer

Lightweight local ACL enforcement from a YAML policy file (same format as `env/acl.yaml`). Loaded from `AUTH_YAML_PATH` env var. Supports user/group/domain policies with deny-wins semantics. Wraps MCP tools to check `(email, service, tool) → allow/deny` before execution.

### Usage

```python
from cassandra_mcp_auth import McpKeyAuthProvider, Enforcer

auth = McpKeyAuthProvider(acl_url="https://acl.example.com", auth_secret="...")
result = await auth.validate("mcp_abc123")

enforcer = Enforcer.from_yaml("/app/acl.yaml")
enforcer.check("user@example.com", "yt-mcp", "transcribe")
```

## ACL Worker

### Endpoints

All endpoints (except `/health`) require `X-Auth-Secret` header or CF Access service token.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| POST | `/check` | `{email, service, tool}` → `{allowed, reason}` |
| GET | `/policy` | Return current baked-in policy |
| POST | `/credentials/:email/:service` | Store per-user credentials |
| GET | `/credentials/:email/:service` | Retrieve per-user credentials |
| DELETE | `/credentials/:email/:service` | Remove per-user credentials |
| POST | `/keys/validate` | `{key}` → `{valid, email, service, credentials}` — validates MCP API key from shared `MCP_KEYS` KV |

### Bindings

- `AUTH_CREDENTIALS` — KV namespace for per-user credentials (keyed by `cred:{email}:{service}`)
- `MCP_KEYS` — Shared KV namespace for MCP API key validation (shared with portal + all MCP workers)

### Deploy

Worker auto-deploys on push to main via Woodpecker CI (`.woodpecker.yaml`).

```bash
# Wrangler secrets
cd worker
wrangler secret put AUTH_SECRET
wrangler secret put VM_PUSH_URL
wrangler secret put VM_PUSH_CLIENT_ID
wrangler secret put VM_PUSH_CLIENT_SECRET
```

### Policy

Policy is baked into the worker bundle from `env/acl.yaml` (gitignored). To update policy:
1. Edit `env/acl.yaml`
2. Push to main — Woodpecker injects the YAML content from a secret and redeploys

## Advanced API (TypeScript)

`createMcpWorker()` is the blessed path for normal CF Worker services.

If a service really does need lower-level control, import the `advanced` namespace from the package root and reach for `advanced.createTokenResolver`, `advanced.createWorkOSHandler`, or the OAuth helpers explicitly.
