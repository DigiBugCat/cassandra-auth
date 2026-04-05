"""ACL enforcement middleware for FastMCP servers.

Drop-in middleware that enforces per-tool access control. Hooks into
on_call_tool (block unauthorized calls) and on_list_tools (filter tools
the user can't see — critical for Code Mode).

Usage — single service:

    from cassandra_mcp_auth import AclMiddleware

    mcp = FastMCP(
        ...,
        middleware=[AclMiddleware(service_id="market-research", acl_path="/app/acl.yaml")],
    )

Usage — gateway with namespaced tools:

    mcp = FastMCP(
        ...,
        middleware=[AclMiddleware(
            acl_path="/app/acl.yaml",
            namespace_map={"market": "market-research", "discord": "discord-mcp", ...},
        )],
    )

The middleware extracts the authenticated user's email from the FastMCP
access token (set by McpKeyAuthProvider or WorkOS). If no token is present
(e.g. auth disabled), enforcement is skipped.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cassandra_mcp_auth.acl import Enforcer, load_enforcer
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext

logger = logging.getLogger(__name__)


class AclMiddleware(Middleware):
    """FastMCP middleware that enforces ACL on tool calls and filters tool lists.

    Args:
        service_id: ACL service name for single-service mode (e.g. "market-research").
            Mutually exclusive with namespace_map.
        namespace_map: Dict mapping tool name prefixes to ACL service IDs.
            E.g. {"market": "market-research", "discord": "discord-mcp"}.
            Tool "market_stock_brief" → service "market-research", tool "stock_brief".
        acl_path: Path to acl.yaml file. If the file doesn't exist, enforcement is disabled.
        enforcer: Pre-built Enforcer instance. If provided, acl_path is ignored.
    """

    def __init__(
        self,
        *,
        service_id: str = "",
        namespace_map: dict[str, str] | None = None,
        acl_path: str = "/app/acl.yaml",
        enforcer: Enforcer | None = None,
    ) -> None:
        if service_id and namespace_map:
            raise ValueError("Provide either service_id or namespace_map, not both")

        self._service_id = service_id
        self._namespace_map = namespace_map or {}
        self._enforcer = enforcer
        self._enabled = enforcer is not None

        if not self._enabled:
            path = Path(acl_path)
            if path.exists():
                self._enforcer = load_enforcer(path)
                self._enabled = True
                logger.info("ACL middleware loaded policy from %s", acl_path)
            else:
                logger.warning("ACL policy not found at %s — enforcement disabled", acl_path)

    def _resolve_tool(self, namespaced_name: str) -> tuple[str, str]:
        """Resolve a (possibly namespaced) tool name to (acl_service_id, original_tool_name).

        Single-service mode: ("market-research", "stock_brief") — tool name passed through.
        Namespace mode: "market_stock_brief" → ("market-research", "stock_brief").
        """
        if self._service_id:
            return self._service_id, namespaced_name

        for prefix, svc_id in self._namespace_map.items():
            if namespaced_name.startswith(prefix + "_"):
                return svc_id, namespaced_name[len(prefix) + 1:]

        # No matching prefix — use tool name as-is with empty service
        return "", namespaced_name

    @staticmethod
    def _get_email() -> str:
        """Extract email from the current request's access token."""
        try:
            token = get_access_token()
            if token and token.claims:
                return token.claims.get("email", "")
        except Exception:
            pass
        return ""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Block tool calls the user isn't allowed to make."""
        if not self._enabled:
            return await call_next(context)

        tool_name = ""
        if hasattr(context.message, "params") and isinstance(context.message.params, dict):
            tool_name = context.message.params.get("name", "")
        if not tool_name:
            tool_name = getattr(context.message, "name", "")

        email = self._get_email()

        if email and tool_name:
            service_id, original_name = self._resolve_tool(tool_name)
            if service_id:
                result = self._enforcer.enforce(email, service_id, original_name)
                if not result.allowed:
                    logger.warning(
                        "ACL denied: user=%s service=%s tool=%s reason=%s",
                        email, service_id, original_name, result.reason,
                    )
                    raise ToolError(f"Access denied: {result.reason}")

        return await call_next(context)

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        """Filter tool list to only include tools the user can access."""
        result = await call_next(context)

        if not self._enabled:
            return result

        email = self._get_email()
        if not email:
            return result

        if hasattr(result, "tools") and result.tools:
            original_count = len(result.tools)
            filtered = []
            for tool in result.tools:
                service_id, original_name = self._resolve_tool(tool.name)
                if not service_id:
                    filtered.append(tool)
                    continue
                check = self._enforcer.enforce(email, service_id, original_name)
                if check.allowed:
                    filtered.append(tool)
            result.tools = filtered
            if len(filtered) < original_count:
                logger.debug(
                    "ACL filtered tools for %s: %d → %d",
                    email, original_count, len(filtered),
                )

        return result
