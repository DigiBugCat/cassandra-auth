"""Tests for the auth service."""

from __future__ import annotations

import json
import os

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("AUTH_SECRET", "test-secret")

from cassandra_auth_service.app import create_app


@pytest.fixture
async def client(tmp_path):
    acl_yaml = tmp_path / "acl.yaml"
    acl_yaml.write_text(
        """
default: deny
users:
  admin@test.com:
    role: admin
  user@test.com:
    role: user
    groups:
      - testers
groups:
  testers:
    services:
      yt-mcp:
        access: allow
        tools:
          deny:
            - dangerous_tool
domains:
  test.com:
    groups:
      - testers
"""
    )

    os.environ["DB_PATH"] = str(tmp_path / "auth.db")
    os.environ["ACL_YAML_PATH"] = str(acl_yaml)

    app = create_app()
    ctx = app.router.lifespan_context(app)
    await ctx.__aenter__()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    await ctx.__aexit__(None, None, None)


AUTH = {"X-Auth-Secret": "test-secret"}
ADMIN = {**AUTH, "X-Admin-Email": "admin@test.com"}


async def test_health(client):
    resp = await client.get("/health")
    assert resp.json() == {"ok": True}


async def test_check_requires_auth(client):
    resp = await client.post("/check", json={"email": "a", "service": "b", "tool": "c"})
    assert resp.status_code == 401


async def test_check_admin_allowed(client):
    resp = await client.post(
        "/check",
        json={"email": "admin@test.com", "service": "any", "tool": "any"},
        headers=AUTH,
    )
    assert resp.json()["allowed"] is True


async def test_check_user_allowed(client):
    resp = await client.post(
        "/check",
        json={"email": "user@test.com", "service": "yt-mcp", "tool": "transcribe"},
        headers=AUTH,
    )
    assert resp.json()["allowed"] is True


async def test_check_user_denied(client):
    resp = await client.post(
        "/check",
        json={"email": "user@test.com", "service": "yt-mcp", "tool": "dangerous_tool"},
        headers=AUTH,
    )
    assert resp.json()["allowed"] is False


async def test_check_unknown_user_domain_match(client):
    """A user with no explicit entry but matching domain gets group access."""
    resp = await client.post(
        "/check",
        json={"email": "newguy@test.com", "service": "yt-mcp", "tool": "transcribe"},
        headers=AUTH,
    )
    assert resp.json()["allowed"] is True


async def test_check_unknown_domain(client):
    resp = await client.post(
        "/check",
        json={"email": "nobody@other.com", "service": "yt-mcp", "tool": "transcribe"},
        headers=AUTH,
    )
    assert resp.json()["allowed"] is False


# ── Credentials ──

async def test_service_credentials_crud(client):
    svc = "fmp"
    creds = {"FMP_API_KEY": "key123"}

    await client.post(f"/service-credentials/{svc}", json=creds, headers=AUTH)
    resp = await client.get(f"/service-credentials/{svc}", headers=AUTH)
    assert resp.json()["credentials"] == creds

    await client.delete(f"/service-credentials/{svc}", headers=AUTH)
    resp = await client.get(f"/service-credentials/{svc}", headers=AUTH)
    assert resp.json()["credentials"] is None


async def test_user_credentials_crud(client):
    email, svc = "user@test.com", "runner"
    creds = {"OBSIDIAN_AUTH_TOKEN": "tok123"}

    await client.post(f"/credentials/{email}/{svc}", json=creds, headers=AUTH)
    resp = await client.get(f"/credentials/{email}/{svc}", headers=AUTH)
    assert resp.json()["credentials"] == creds

    await client.delete(f"/credentials/{email}/{svc}", headers=AUTH)
    resp = await client.get(f"/credentials/{email}/{svc}", headers=AUTH)
    assert resp.json()["credentials"] is None


# ── MCP keys ──

async def test_validate_key_not_found(client):
    resp = await client.post("/keys/validate", json={"key": "mcp_x"}, headers=AUTH)
    assert resp.status_code == 404


async def test_key_put_validate_delete(client):
    meta = {"name": "test", "service": "yt-mcp", "created_by": "user@test.com", "project_id": "proj1"}
    await client.put("/keys/mcp_abc", json=meta, headers=AUTH)

    resp = await client.post("/keys/validate", json={"key": "mcp_abc"}, headers=AUTH)
    assert resp.json()["valid"] is True
    assert resp.json()["email"] == "user@test.com"

    await client.delete("/keys/mcp_abc", headers=AUTH)
    resp = await client.post("/keys/validate", json={"key": "mcp_abc"}, headers=AUTH)
    assert resp.json()["valid"] is False


async def test_key_patch_credentials(client):
    meta = {"name": "test", "service": "yt-mcp", "created_by": "u@t.com", "project_id": "p1"}
    await client.put("/keys/mcp_cred", json=meta, headers=AUTH)

    # Patch credentials onto existing key
    await client.patch(
        "/keys/mcp_cred/credentials",
        json={"credentials": {"youtube_cookies": "abc123"}},
        headers=AUTH,
    )

    resp = await client.post("/keys/validate", json={"key": "mcp_cred"}, headers=AUTH)
    assert resp.json()["credentials"] == {"youtube_cookies": "abc123"}

    # Clear credentials
    await client.patch(
        "/keys/mcp_cred/credentials",
        json={"credentials": None},
        headers=AUTH,
    )
    resp = await client.post("/keys/validate", json={"key": "mcp_cred"}, headers=AUTH)
    assert resp.json()["credentials"] is None


# ── ACL admin ──

async def test_acl_whoami(client):
    resp = await client.get("/acl/whoami", headers=ADMIN)
    assert resp.json()["isAdmin"] is True


async def test_acl_register_new(client):
    resp = await client.post("/acl/register", headers={**AUTH, "X-Admin-Email": "new@test.com"})
    assert resp.json()["created"] is True
    assert "testers" in resp.json()["user"].get("groups", [])


async def test_acl_users_requires_admin(client):
    resp = await client.get("/acl/users", headers={**AUTH, "X-Admin-Email": "user@test.com"})
    assert resp.status_code == 403


async def test_acl_groups_crud(client):
    group = {"services": {"fmp": {"access": "allow"}}}
    await client.put("/acl/groups/analysts", json=group, headers=ADMIN)
    assert "analysts" in (await client.get("/acl/groups", headers=ADMIN)).json()

    await client.delete("/acl/groups/analysts", headers=ADMIN)
    assert "analysts" not in (await client.get("/acl/groups", headers=ADMIN)).json()


async def test_acl_domains_crud(client):
    await client.put("/acl/domains/example.com", json={"groups": ["testers"]}, headers=ADMIN)
    assert "example.com" in (await client.get("/acl/domains", headers=ADMIN)).json()

    await client.delete("/acl/domains/example.com", headers=ADMIN)
    assert "example.com" not in (await client.get("/acl/domains", headers=ADMIN)).json()


async def test_acl_cannot_delete_self(client):
    resp = await client.delete("/acl/users/admin@test.com", headers=ADMIN)
    assert resp.status_code == 400
