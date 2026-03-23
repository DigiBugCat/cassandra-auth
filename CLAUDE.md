# CLAUDE.md — Cassandra Auth

## What This Is

Centralized auth service + Python auth library for the Cassandra platform. Two parts:

1. **Auth service** (`service/`) — FastAPI app with Casbin RBAC, MCP key validation, per-user + service-level credential storage. Runs in k8s, uses SQLite.
2. **Python auth library** (`python/`) — `McpKeyAuthProvider` (validates mcp_ API keys) + `Enforcer` (per-tool ACL) for FastMCP sidecars in k8s.

## Repo Structure

```
cassandra-auth/
├── service/                       # Auth service (FastAPI + SQLite)
│   ├── src/cassandra_auth_service/
│   │   ├── app.py                 # FastAPI app — all endpoints
│   │   ├── db.py                  # Async SQLite (WAL mode)
│   │   ├── policy.py              # Casbin enforcer + config load/save
│   │   └── main.py                # CLI entrypoint (uvicorn)
│   ├── tests/
│   │   └── test_app.py            # Full endpoint tests
│   ├── schema.sql                 # DB schema
│   ├── model.conf                 # Casbin RBAC model
│   └── pyproject.toml
├── python/                        # Python package (FastMCP sidecars)
│   └── src/cassandra_mcp_auth/
│       ├── __init__.py            # Public API exports
│       ├── auth.py                # McpKeyAuthProvider — validates mcp_ keys via /keys/validate
│       └── acl.py                 # Enforcer — local YAML-based ACL enforcement
├── env/                           # acl.yaml (gitignored)
├── .woodpecker.yaml               # CI: test → build → push → restart
└── CLAUDE.md
```

## Auth Service

### Endpoints

All endpoints (except `/health`) require `X-Auth-Secret` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| POST | `/check` | `{email, service, tool}` → `{allowed, reason}` |
| POST/GET/DELETE | `/credentials/{email}/{service}` | Per-user credential CRUD |
| POST/GET/DELETE | `/service-credentials/{service}` | Service-level credential CRUD |
| POST | `/keys/validate` | `{key}` → `{valid, email, service, credentials, serviceCredentials}` |
| PUT/DELETE | `/keys/{key_id}` | MCP key CRUD (written by portal) |
| PATCH | `/keys/{key_id}/credentials` | Update credentials on existing key |
| GET | `/acl/whoami` | Caller's role + groups |
| POST | `/acl/register` | Auto-register user on first sign-in |
| GET/PUT | `/acl/policy` | Full policy CRUD (admin) |
| GET/PUT/DELETE | `/acl/users/{email}` | User CRUD (admin) |
| GET/PUT/DELETE | `/acl/groups/{name}` | Group CRUD (admin) |
| GET/PUT/DELETE | `/acl/domains/{domain}` | Domain CRUD (admin) |
| POST | `/acl/test` | Dry-run access check (admin) |

### Env Vars

- `AUTH_SECRET` — shared secret for service-to-service auth
- `DB_PATH` — SQLite database path (default: `/data/auth.db`)
- `ACL_YAML_PATH` — initial ACL policy YAML (loaded into DB on first run)
- `HOST` / `PORT` — bind address (default: `0.0.0.0:8080`)

### Run

```bash
cd service
uv run cassandra-auth          # or: uv run uvicorn cassandra_auth_service.app:create_app --factory
uv run pytest -v               # tests
```

### Policy

ACL config is stored in SQLite (`acl_config` table) and managed via `/acl/*` CRUD endpoints. On first startup, loads from `ACL_YAML_PATH` if DB is empty. The `default` field controls behavior when no policy matches (`allow` or `deny`).

## Python Package (FastMCP sidecars)

### McpKeyAuthProvider

Validates `Bearer mcp_...` tokens by calling the auth service's `POST /keys/validate`. Returns user email, service scope, and optional per-key + service-level credentials.

### Enforcer

Lightweight local ACL enforcement from a YAML policy file. Supports user/group/domain policies with deny-wins semantics. Wraps MCP tools to check `(email, service, tool) → allow/deny` before execution.

### Usage

```python
from cassandra_mcp_auth import McpKeyAuthProvider, Enforcer

auth = McpKeyAuthProvider(acl_url="https://auth.internal:8080", auth_secret="...")
result = await auth.validate("mcp_abc123")

enforcer = Enforcer.from_yaml("/app/acl.yaml")
enforcer.check("user@example.com", "yt-mcp", "transcribe")
```
