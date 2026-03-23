"""Load ACL config into a Casbin enforcer."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import casbin

from cassandra_auth_service.db import Database

logger = logging.getLogger(__name__)

MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/app/model.conf"))


def load_policies_into_enforcer(enforcer: casbin.Enforcer, config: dict) -> None:
    """Populate a Casbin enforcer from an ACL config dict."""
    enforcer.clear_policy()

    # Groups
    for group, gdef in (config.get("groups") or {}).items():
        for svc, svc_def in (gdef.get("services") or {}).items():
            if svc_def.get("access") == "allow":
                enforcer.add_named_policy("p", group, svc, "*", "allow")
            for tool in (svc_def.get("tools") or {}).get("deny") or []:
                enforcer.add_named_policy("p", group, svc, tool, "deny")
            for tool in (svc_def.get("tools") or {}).get("allow") or []:
                enforcer.add_named_policy("p", group, svc, tool, "allow")

    # Users
    for email, user in (config.get("users") or {}).items():
        if user.get("role") == "admin":
            enforcer.add_named_policy("p", email, "*", "*", "allow")
        for grp in user.get("groups") or []:
            enforcer.add_named_grouping_policy("g", email, grp)

    # Domains
    for domain, ddef in (config.get("domains") or {}).items():
        for grp in ddef.get("groups") or []:
            enforcer.add_named_grouping_policy("g", f"domain:{domain}", grp)


def create_enforcer(config: dict | None = None) -> casbin.Enforcer:
    """Create a Casbin enforcer with our RBAC model."""
    enforcer = casbin.Enforcer(str(MODEL_PATH))
    if config:
        load_policies_into_enforcer(enforcer, config)
    return enforcer


async def load_config(db: Database, acl_yaml_path: str) -> dict:
    """Load ACL config from DB, falling back to YAML file."""
    row = await db.fetchone("SELECT config_json FROM acl_config WHERE id = 1")
    if row:
        return json.loads(row["config_json"])

    if acl_yaml_path and Path(acl_yaml_path).exists():
        import yaml  # noqa: PLC0415

        config = yaml.safe_load(Path(acl_yaml_path).read_text())
        await db.execute(
            "INSERT INTO acl_config (id, config_json) VALUES (1, ?)",
            (json.dumps(config),),
        )
        await db.commit()
        logger.info("Loaded ACL config from YAML and persisted to DB")
        return config

    logger.warning("No ACL config found — using empty default")
    return {"default": "deny"}


async def save_config(db: Database, config: dict) -> None:
    """Save config to DB."""
    await db.execute(
        "INSERT INTO acl_config (id, config_json) VALUES (1, ?)"
        " ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json,"
        " updated_at=datetime('now')",
        (json.dumps(config),),
    )
    await db.commit()
