"""Custom FastMCP auth: MCP API key validation + WorkOS AuthKit DCR via MultiAuth."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from fastmcp.server.auth import AccessToken, AuthProvider, JWTVerifier, MultiAuth, TokenVerifier
from fastmcp.server.auth.providers.workos import AuthKitProvider

logger = logging.getLogger(__name__)


class UserInfoEnrichingVerifier(TokenVerifier):
    """Wraps a TokenVerifier and enriches the AccessToken with email from the userinfo endpoint.

    WorkOS AuthKit access token JWTs don't include the user's email in claims.
    This wrapper calls the OIDC userinfo endpoint after JWT verification to
    resolve the email, which is needed for per-tool ACL enforcement.
    """

    def __init__(
        self,
        *,
        inner: TokenVerifier,
        workos_api_key: str,
        base_url: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url)
        self._inner = inner
        self._workos_api_key = workos_api_key
        self._client = httpx.AsyncClient(timeout=10)
        self._cache: dict[str, str] = {}  # sub → email

    async def verify_token(self, token: str) -> AccessToken | None:
        result = await self._inner.verify_token(token)
        if result is None:
            return None

        # Already has email (e.g. from MCP key path) — skip lookup
        if result.claims.get("email"):
            return result

        sub = result.claims.get("sub", "")
        if not sub:
            return result

        # Resolve email from cache or WorkOS Management API
        email = self._cache.get(sub)
        if not email:
            try:
                resp = await self._client.get(
                    f"https://api.workos.com/user_management/users/{sub}",
                    headers={"Authorization": f"Bearer {self._workos_api_key}"},
                )
                if resp.status_code != 200:
                    logger.warning("WorkOS user lookup failed: %d %s", resp.status_code, resp.text[:200])
                    return result
                user_data = resp.json()
                email = user_data.get("email", "")
                if email:
                    self._cache[sub] = email
                    logger.info("Resolved WorkOS user %s → %s", sub, email)
                else:
                    logger.warning("WorkOS user %s has no email", sub)
                    return result
            except httpx.HTTPError:
                logger.exception("Failed to look up WorkOS user %s", sub)
                return result

        enriched_claims = {**result.claims, "email": email}
        return AccessToken(
            token=result.token,
            client_id=result.client_id,
            scopes=result.scopes,
            expires_at=result.expires_at,
            claims=enriched_claims,
        )

    def close(self) -> None:
        pass


@dataclass(slots=True)
class McpKeyInfo:
    """Resolved info from a validated MCP API key."""

    email: str
    service: str
    credentials: dict[str, str] | None


class McpKeyAuthProvider(TokenVerifier):
    """Validates `mcp_` bearer tokens by calling the auth service's /keys/validate endpoint.

    Returns an AccessToken with the user's email in claims so tools can access it
    via CurrentAccessToken().
    """

    def __init__(
        self,
        *,
        acl_url: str,
        acl_secret: str,
        service_id: str = "yt-mcp",
        base_url: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url)
        self._auth_url = acl_url.rstrip("/")
        self._auth_secret = acl_secret
        self._service_id = service_id
        self._client = httpx.Client(timeout=10)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a bearer token. Only accepts mcp_ prefixed keys."""
        if not token.startswith("mcp_"):
            logger.debug("Rejecting non-mcp_ token")
            return None

        try:
            resp = self._client.post(
                f"{self._auth_url}/keys/validate",
                json={"key": token},
                headers={
                    "X-Auth-Secret": self._auth_secret,
                    "Content-Type": "application/json",
                },
            )

            if resp.status_code != 200:
                logger.warning("Key validation failed: status %d", resp.status_code)
                return None

            data = resp.json()
            if not data.get("valid"):
                return None

            # Enforce service scope — a yt-mcp key shouldn't work on other services
            if data.get("service") != self._service_id:
                logger.warning(
                    "Key service mismatch: expected %s, got %s",
                    self._service_id,
                    data.get("service"),
                )
                return None

            email = data.get("email", "")
            credentials = data.get("credentials") or {}

            return AccessToken(
                token=token,
                client_id=email,
                scopes=["openid", "profile", "email", "mcp"],
                expires_at=None,
                claims={
                    "email": email,
                    "service": self._service_id,
                    "credentials": credentials,
                },
            )

        except httpx.HTTPError:
            logger.exception("Failed to validate MCP key against auth service")
            return None

    def close(self) -> None:
        self._client.close()


def build_auth(
    *,
    acl_url: str,
    acl_secret: str,
    service_id: str,
    base_url: str,
    workos_client_id: str,
    workos_authkit_domain: str,
    workos_api_key: str = "",
    # Deprecated — ignored, kept for call-site compat during rollout
    workos_client_secret: str = "",
) -> tuple[AuthProvider, McpKeyAuthProvider]:
    """Build a MultiAuth provider combining WorkOS AuthKit DCR (for claude.ai) and MCP key auth.

    Uses AuthKitProvider (Remote OAuth / DCR) instead of OAuthProxy. WorkOS handles
    the full OAuth flow directly — no proxy state, no storage, no token refresh on
    our side. Tokens are WorkOS-issued JWTs verified via JWKS.

    Returns (auth_provider, mcp_key_provider) — caller needs mcp_key_provider
    to call .close() on shutdown.
    """
    mcp_key_provider = McpKeyAuthProvider(
        acl_url=acl_url,
        acl_secret=acl_secret,
        service_id=service_id,
    )

    # Ensure domain has https:// prefix (AuthKitProvider doesn't auto-prepend)
    domain = workos_authkit_domain
    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"

    # Don't pass client_id — in DCR, WorkOS issues JWTs with aud set to the
    # dynamically registered client ID, not the project-level client ID.
    # Passing client_id here causes audience mismatch → 401 for claude.ai.
    #
    # Wrap with UserInfoEnrichingVerifier so OAuth tokens get the user's email
    # resolved via the OIDC userinfo endpoint. WorkOS access token JWTs don't
    # include email in claims — ACL enforcement needs it.
    # Build token verifier — if WorkOS API key is available, wrap with
    # enricher that resolves email from WorkOS Management API.
    jwt_verifier = JWTVerifier(
        jwks_uri=f"{domain}/oauth2/jwks",
        issuer=domain,
        algorithm="RS256",
    )
    token_verifier: TokenVerifier = jwt_verifier
    if workos_api_key:
        token_verifier = UserInfoEnrichingVerifier(
            inner=jwt_verifier,
            workos_api_key=workos_api_key,
            base_url=base_url,
        )

    authkit_provider = AuthKitProvider(
        authkit_domain=domain,
        base_url=base_url,
        token_verifier=token_verifier,
    )

    auth = MultiAuth(
        server=authkit_provider,
        verifiers=[mcp_key_provider],
    )

    return auth, mcp_key_provider
