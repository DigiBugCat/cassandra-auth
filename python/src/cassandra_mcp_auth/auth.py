"""Custom FastMCP auth: MCP API key validation + WorkOS OAuth proxy via MultiAuth."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from fastmcp.server.auth import AccessToken, AuthProvider, MultiAuth, TokenVerifier
from fastmcp.server.auth.providers.workos import WorkOSProvider

logger = logging.getLogger(__name__)


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
                scopes=["mcp"],
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
    workos_client_secret: str,
    workos_authkit_domain: str,
) -> tuple[AuthProvider, McpKeyAuthProvider]:
    """Build a MultiAuth provider combining WorkOS OAuth (for claude.ai) and MCP key auth.

    Returns (auth_provider, mcp_key_provider) — caller needs mcp_key_provider
    to call .close() on shutdown.
    """
    mcp_key_provider = McpKeyAuthProvider(
        acl_url=acl_url,
        acl_secret=acl_secret,
        service_id=service_id,
    )

    workos_provider = WorkOSProvider(
        client_id=workos_client_id,
        client_secret=workos_client_secret,
        authkit_domain=workos_authkit_domain,
        base_url=base_url,
        required_scopes=["openid", "profile", "email"],
        require_authorization_consent=False,
        allowed_client_redirect_uris=["http://localhost:*", "http://127.0.0.1:*", "https://claude.ai/*"],
    )

    auth = MultiAuth(
        server=workos_provider,
        verifiers=[mcp_key_provider],
    )

    return auth, mcp_key_provider
