"""Auth service — Casbin RBAC, MCP key validation, credential storage."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import casbin
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from cassandra_auth_service.db import Database
from cassandra_auth_service.policy import (
    create_enforcer,
    load_config,
    load_policies_into_enforcer,
    save_config,
)

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(os.environ.get("SCHEMA_PATH", "/app/schema.sql"))


# ── State ──

class AuthState:
    def __init__(self, db: Database, enforcer: casbin.Enforcer, acl_config: dict) -> None:
        self.db = db
        self.enforcer = enforcer
        self.acl_config = acl_config

    def reload_policy(self, config: dict) -> None:
        self.acl_config = config
        load_policies_into_enforcer(self.enforcer, config)

    def check_access(self, sub: str, svc: str, tool: str) -> bool:
        """Enforce access check with domain-based role fallback."""
        try:
            if self.enforcer.enforce(sub, svc, tool):
                return True
            if "@" in sub:
                return self.enforcer.enforce(f"domain:{sub.split('@')[1]}", svc, tool)
        except Exception:
            logger.exception("Casbin enforce error for (%s, %s, %s)", sub, svc, tool)
        return False


def get_state(request: Request) -> AuthState:
    return request.app.state.auth


def require_auth(x_auth_secret: str | None = Header(None)) -> None:
    expected = os.environ.get("AUTH_SECRET", "")
    if not expected or x_auth_secret != expected:
        raise HTTPException(401, "unauthorized")


# ── App ──

def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db_path = os.environ.get("DB_PATH", "/data/auth.db")
        acl_yaml = os.environ.get("ACL_YAML_PATH", "")

        db = Database(db_path)
        await db.open()
        await db.execute_script(SCHEMA_PATH.read_text())

        config = await load_config(db, acl_yaml)
        enforcer = create_enforcer(config)
        app.state.auth = AuthState(db, enforcer, config)

        logger.info("Auth service ready (db=%s)", db_path)
        yield
        await db.close()

    app = FastAPI(title="cassandra-auth", lifespan=lifespan)

    # ── Health ──

    @app.get("/health")
    async def health():
        return {"ok": True}

    # ── ACL check ──

    @app.post("/check", dependencies=[Depends(require_auth)])
    async def check(request: Request, state: AuthState = Depends(get_state)):
        body = await request.json()
        sub, svc, tool = body.get("email", ""), body.get("service", ""), body.get("tool", "")
        if not all([sub, svc, tool]):
            raise HTTPException(400, "email, service, and tool are required")
        allowed = state.check_access(sub, svc, tool)
        return {"allowed": allowed, "reason": "allowed by policy" if allowed else "denied"}

    # ── Service credentials CRUD ──

    @app.post("/service-credentials/{service}", dependencies=[Depends(require_auth)])
    async def set_service_creds(service: str, request: Request, state: AuthState = Depends(get_state)):
        creds = await request.json()
        await state.db.execute(
            "INSERT INTO service_credentials (service, credentials_json) VALUES (?, ?)"
            " ON CONFLICT(service) DO UPDATE SET credentials_json=excluded.credentials_json,"
            " updated_at=datetime('now')",
            (service, json.dumps(creds)),
        )
        await state.db.commit()
        return {"ok": True}

    @app.get("/service-credentials/{service}", dependencies=[Depends(require_auth)])
    async def get_service_creds(service: str, state: AuthState = Depends(get_state)):
        row = await state.db.fetchone(
            "SELECT credentials_json FROM service_credentials WHERE service = ?", (service,)
        )
        return {"credentials": json.loads(row["credentials_json"]) if row else None}

    @app.delete("/service-credentials/{service}", dependencies=[Depends(require_auth)])
    async def delete_service_creds(service: str, state: AuthState = Depends(get_state)):
        await state.db.execute("DELETE FROM service_credentials WHERE service = ?", (service,))
        await state.db.commit()
        return {"ok": True}

    # ── Per-user credentials CRUD ──

    @app.post("/credentials/{email}/{service}", dependencies=[Depends(require_auth)])
    async def set_user_creds(email: str, service: str, request: Request, state: AuthState = Depends(get_state)):
        creds = await request.json()
        await state.db.execute(
            "INSERT INTO user_credentials (email, service, credentials_json) VALUES (?, ?, ?)"
            " ON CONFLICT(email, service) DO UPDATE SET credentials_json=excluded.credentials_json,"
            " updated_at=datetime('now')",
            (email, service, json.dumps(creds)),
        )
        await state.db.commit()
        return {"ok": True}

    @app.get("/credentials/{email}/{service}", dependencies=[Depends(require_auth)])
    async def get_user_creds(email: str, service: str, state: AuthState = Depends(get_state)):
        row = await state.db.fetchone(
            "SELECT credentials_json FROM user_credentials WHERE email = ? AND service = ?",
            (email, service),
        )
        return {"credentials": json.loads(row["credentials_json"]) if row else None}

    @app.delete("/credentials/{email}/{service}", dependencies=[Depends(require_auth)])
    async def delete_user_creds(email: str, service: str, state: AuthState = Depends(get_state)):
        await state.db.execute(
            "DELETE FROM user_credentials WHERE email = ? AND service = ?", (email, service)
        )
        await state.db.commit()
        return {"ok": True}

    # ── MCP keys (proper columns, no JSON blob) ──

    @app.post("/keys/validate", dependencies=[Depends(require_auth)])
    async def validate_key(request: Request, state: AuthState = Depends(get_state)):
        body = await request.json()
        key = body.get("key")
        if not key:
            raise HTTPException(400, "key is required")

        row = await state.db.fetchone(
            "SELECT service, name, created_by, project_id, credentials_json"
            " FROM mcp_keys WHERE key_id = ?",
            (key,),
        )
        if not row:
            return JSONResponse({"valid": False}, status_code=404)

        svc_row = await state.db.fetchone(
            "SELECT credentials_json FROM service_credentials WHERE service = ?",
            (row["service"],),
        )
        return {
            "valid": True,
            "email": row["created_by"],
            "service": row["service"],
            "credentials": json.loads(row["credentials_json"]) if row["credentials_json"] else None,
            "serviceCredentials": json.loads(svc_row["credentials_json"]) if svc_row else None,
        }

    @app.put("/keys/{key_id}", dependencies=[Depends(require_auth)])
    async def put_key(key_id: str, request: Request, state: AuthState = Depends(get_state)):
        body = await request.json()
        service = body.get("service", "")
        name = body.get("name", "")
        created_by = body.get("created_by", "")
        project_id = body.get("project_id", "")
        credentials = body.get("credentials")

        await state.db.execute(
            "INSERT INTO mcp_keys (key_id, service, name, created_by, project_id, credentials_json)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(key_id) DO UPDATE SET"
            " service=excluded.service, name=excluded.name,"
            " created_by=excluded.created_by, project_id=excluded.project_id,"
            " credentials_json=excluded.credentials_json",
            (key_id, service, name, created_by, project_id,
             json.dumps(credentials) if credentials else None),
        )
        await state.db.commit()
        return {"ok": True}

    @app.patch("/keys/{key_id}/credentials", dependencies=[Depends(require_auth)])
    async def patch_key_credentials(key_id: str, request: Request, state: AuthState = Depends(get_state)):
        """Update just the credentials on an existing key (used by portal credential sync)."""
        body = await request.json()
        credentials = body.get("credentials")
        await state.db.execute(
            "UPDATE mcp_keys SET credentials_json = ? WHERE key_id = ?",
            (json.dumps(credentials) if credentials else None, key_id),
        )
        await state.db.commit()
        return {"ok": True}

    @app.delete("/keys/{key_id}", dependencies=[Depends(require_auth)])
    async def delete_key(key_id: str, state: AuthState = Depends(get_state)):
        await state.db.execute("DELETE FROM mcp_keys WHERE key_id = ?", (key_id,))
        await state.db.commit()
        return {"ok": True}

    # ── ACL admin CRUD ──

    def _admin_email(x_admin_email: str) -> str:
        return x_admin_email.strip().lower()

    def _require_admin(state: AuthState, email: str) -> None:
        if not email:
            raise HTTPException(400, "X-Admin-Email header required")
        if (state.acl_config.get("users") or {}).get(email, {}).get("role") != "admin":
            raise HTTPException(403, "admin required")

    async def _update_config(state: AuthState, config: dict) -> None:
        await save_config(state.db, config)
        state.reload_policy(config)

    @app.get("/acl/whoami", dependencies=[Depends(require_auth)])
    async def acl_whoami(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        email = _admin_email(x_admin_email)
        if not email:
            raise HTTPException(400, "X-Admin-Email header required")
        user = (state.acl_config.get("users") or {}).get(email)
        return {
            "email": email,
            "role": (user or {}).get("role", "user"),
            "groups": (user or {}).get("groups", []),
            "isAdmin": (user or {}).get("role") == "admin",
        }

    @app.post("/acl/register", dependencies=[Depends(require_auth)])
    async def acl_register(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        email = _admin_email(x_admin_email)
        if not email:
            raise HTTPException(400, "X-Admin-Email header required")

        existing = (state.acl_config.get("users") or {}).get(email)
        if existing:
            return {"email": email, "user": existing, "created": False}

        domain = email.split("@")[1] if "@" in email else ""
        groups = (state.acl_config.get("domains") or {}).get(domain, {}).get("groups", [])
        new_user: dict = {"role": "user"}
        if groups:
            new_user["groups"] = list(groups)

        config = {**state.acl_config, "users": {**(state.acl_config.get("users") or {}), email: new_user}}
        await _update_config(state, config)
        return {"email": email, "user": new_user, "created": True}

    @app.get("/acl/policy", dependencies=[Depends(require_auth)])
    async def acl_get_policy(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        return state.acl_config

    @app.put("/acl/policy", dependencies=[Depends(require_auth)])
    async def acl_put_policy(request: Request, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        config = await request.json()
        if not config.get("default"):
            raise HTTPException(400, "default field is required")
        await _update_config(state, config)
        return {"ok": True}

    @app.get("/acl/users", dependencies=[Depends(require_auth)])
    async def acl_get_users(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        return state.acl_config.get("users") or {}

    @app.put("/acl/users/{target_email}", dependencies=[Depends(require_auth)])
    async def acl_put_user(target_email: str, request: Request, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        user_data = await request.json()
        config = {**state.acl_config, "users": {**(state.acl_config.get("users") or {}), target_email.lower(): user_data}}
        await _update_config(state, config)
        return {"ok": True}

    @app.delete("/acl/users/{target_email}", dependencies=[Depends(require_auth)])
    async def acl_delete_user(target_email: str, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        admin = _admin_email(x_admin_email)
        _require_admin(state, admin)
        if target_email.lower() == admin:
            raise HTTPException(400, "cannot delete yourself")
        users = {**(state.acl_config.get("users") or {})}
        users.pop(target_email.lower(), None)
        await _update_config(state, {**state.acl_config, "users": users})
        return {"ok": True}

    @app.get("/acl/groups", dependencies=[Depends(require_auth)])
    async def acl_get_groups(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        return state.acl_config.get("groups") or {}

    @app.put("/acl/groups/{name}", dependencies=[Depends(require_auth)])
    async def acl_put_group(name: str, request: Request, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        group_data = await request.json()
        if not group_data.get("services") or not isinstance(group_data["services"], dict):
            raise HTTPException(400, "services field is required")
        config = {**state.acl_config, "groups": {**(state.acl_config.get("groups") or {}), name: group_data}}
        await _update_config(state, config)
        return {"ok": True}

    @app.delete("/acl/groups/{name}", dependencies=[Depends(require_auth)])
    async def acl_delete_group(name: str, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        groups = {**(state.acl_config.get("groups") or {})}
        groups.pop(name, None)
        await _update_config(state, {**state.acl_config, "groups": groups})
        return {"ok": True}

    @app.get("/acl/domains", dependencies=[Depends(require_auth)])
    async def acl_get_domains(state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        return state.acl_config.get("domains") or {}

    @app.put("/acl/domains/{domain}", dependencies=[Depends(require_auth)])
    async def acl_put_domain(domain: str, request: Request, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        domain_data = await request.json()
        config = {**state.acl_config, "domains": {**(state.acl_config.get("domains") or {}), domain.lower(): domain_data}}
        await _update_config(state, config)
        return {"ok": True}

    @app.delete("/acl/domains/{domain}", dependencies=[Depends(require_auth)])
    async def acl_delete_domain(domain: str, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        domains = {**(state.acl_config.get("domains") or {})}
        domains.pop(domain.lower(), None)
        await _update_config(state, {**state.acl_config, "domains": domains})
        return {"ok": True}

    @app.post("/acl/test", dependencies=[Depends(require_auth)])
    async def acl_test(request: Request, state: AuthState = Depends(get_state), x_admin_email: str = Header("")):
        _require_admin(state, _admin_email(x_admin_email))
        body = await request.json()
        sub, svc, tool = body.get("email", ""), body.get("service", ""), body.get("tool", "")
        if not all([sub, svc, tool]):
            raise HTTPException(400, "email, service, and tool are required")
        allowed = state.check_access(sub, svc, tool)
        return {"allowed": allowed, "reason": "allowed by policy" if allowed else "denied"}

    return app
