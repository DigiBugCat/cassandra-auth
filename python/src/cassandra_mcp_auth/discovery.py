"""Discovery-only transform for MCP services.

Exposes search, get_schema, and tags — no execute. Execution is the
gateway's job. Services are browsable catalogs, not execution endpoints.

Usage:
    from cassandra_mcp_auth import DiscoveryTransform

    mcp = FastMCP(
        ...,
        transforms=[DiscoveryTransform()],
    )

Clients connecting directly to the service see 3 tools:
  - tags()       — browse tools by category
  - search()     — find tools by query
  - get_schema() — get parameter details for specific tools
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


class DiscoveryTransform(CatalogTransform):
    """Transform that replaces all tools with discovery-only tools.

    No execute tool. The underlying tools are still accessible via
    get_tool_catalog() for the discovery tools to browse, but they
    are never exposed directly to clients.
    """

    def __init__(self) -> None:
        super().__init__()
        self._discovery_tools: list[Tool] | None = None

    def _build_discovery_tools(self) -> list[Tool]:
        if self._discovery_tools is None:
            self._discovery_tools = [
                GetTags()(self.get_tool_catalog),
                Search()(self.get_tool_catalog),
                GetSchemas()(self.get_tool_catalog),
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
