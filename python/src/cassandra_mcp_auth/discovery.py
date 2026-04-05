"""Discovery-only transform for MCP services.

Exposes search, get_schema, and tags — no execute. Execution is the
gateway's job. Services are browsable catalogs, not execution endpoints.

Tool names are prefixed with the service ID so each service's discovery
tools are unique (e.g. market_search, twitter_search). This prevents
clients from hallucinating a matching `execute` tool per namespace.

Usage:
    from cassandra_mcp_auth import DiscoveryTransform

    mcp = FastMCP(
        ...,
        transforms=[DiscoveryTransform(service_id="market-research")],
    )

Clients connecting directly see 3 tools with service-prefixed names:
  - <service>_tags        — browse tools by category
  - <service>_search      — find tools by query
  - <service>_get_schema  — get parameter details for specific tools
"""

from __future__ import annotations

from collections.abc import Sequence

from fastmcp.experimental.transforms.code_mode import (
    GetSchemas,
    GetTags,
    Search,
)
from fastmcp.server.transforms.catalog import CatalogTransform
from fastmcp.tools.base import Tool
from fastmcp.utilities.versions import VersionSpec


def _sanitize(service_id: str) -> str:
    """Convert service_id to a valid tool name suffix (underscore-separated)."""
    # Strip common suffixes so we don't end up with cass_twitter_mcp_search
    cleaned = service_id.replace("-", "_").lower()
    for suffix in ("_mcp", "_research"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    return cleaned


class DiscoveryTransform(CatalogTransform):
    """Transform that replaces all tools with namespaced discovery tools.

    Discovery tools are prefixed with `cass_<short_id>_` where short_id is
    derived from the service_id with common suffixes stripped. Examples:
        market-research → cass_market_tags, cass_market_search, cass_market_get_schema
        twitter-mcp     → cass_twitter_tags, cass_twitter_search, ...
        yt-mcp          → cass_yt_tags, cass_yt_search, ...
    """

    def __init__(self, service_id: str) -> None:
        super().__init__()
        self._prefix = f"cass_{_sanitize(service_id)}"
        self._discovery_tools: list[Tool] | None = None

    def _build_discovery_tools(self) -> list[Tool]:
        if self._discovery_tools is None:
            self._discovery_tools = [
                GetTags(name=f"{self._prefix}_tags")(self.get_tool_catalog),
                Search(name=f"{self._prefix}_search")(self.get_tool_catalog),
                GetSchemas(name=f"{self._prefix}_get_schema")(self.get_tool_catalog),
            ]
        return self._discovery_tools

    async def transform_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return self._build_discovery_tools()

    async def get_tool(
        self, name: str, call_next, *, version: VersionSpec | None = None,
    ) -> Tool | None:
        for tool in self._build_discovery_tools():
            if tool.name == name:
                return tool
        # Don't fall through to raw tools — they're not exposed
        return None
