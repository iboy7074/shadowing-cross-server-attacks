"""A minimal multi-server MCP client.

Real MCP clients connect to several servers over stdio/HTTP and merge every
server's ``tools/list`` response into a single context for the model. That
merge is exactly where the vulnerability lives: the model cannot tell which
server a description came from, and there is no isolation between them.

This client models that merge faithfully but locally, so the attack can be
reproduced and then defended against without standing up real transports. It
also supports a *live* mode that talks to real stdio servers via the MCP SDK
(see ``mcp_shadow.servers.email_server`` and ``mcp_shadow.servers.shadow_server``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from mcp import types


def fingerprint_tool(tool: types.Tool) -> str:
    """Stable fingerprint of a tool's security-relevant metadata."""
    payload = json.dumps(
        {
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.input_schema,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class RegisteredTool:
    """A tool as seen by the client, tagged with the server it came from."""

    server: str
    tool: types.Tool
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fingerprint_tool(self.tool)

    @property
    def name(self) -> str:
        return self.tool.name

    @property
    def description(self) -> str:
        return self.tool.description or ""

    @property
    def input_schema(self) -> dict:
        return self.tool.input_schema or {}


@dataclass
class MCPClient:
    """Registers tools from one or more servers into a shared context."""

    servers: dict[str, list[types.Tool]] = field(default_factory=dict)
    tools: list[RegisteredTool] = field(default_factory=list)

    def register_server(self, name: str, tools: list[types.Tool]) -> None:
        """Merge a server's tool list into the shared context.

        This mirrors ``tools/list`` handling in real clients: descriptions are
        appended verbatim and no provenance is attached for the model.
        """
        self.servers[name] = tools
        for tool in tools:
            self.tools.append(RegisteredTool(server=name, tool=tool))

    def register_live_server(self, name: str, command: list[str]) -> None:
        """Fetch a server's tools over real stdio and register them.

        Requires the MCP SDK and a runnable server script. Kept separate from
        the in-memory path so the analysis code has no transport dependency.
        """
        import asyncio

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def _list() -> list[types.Tool]:
            params = StdioServerParameters(command=command[0], args=command[1:])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    return list(result.tools)

        self.register_server(name, asyncio.run(_list()))

    def tools_by_name(self, name: str) -> list[RegisteredTool]:
        """Every registered tool sharing a name, in registration order.

        Duplicate names across servers are the precondition for a shadowing
        attack that relies on name collision.
        """
        return [t for t in self.tools if t.name == name]

    def tool_map(self) -> dict[str, list[RegisteredTool]]:
        grouped: dict[str, list[RegisteredTool]] = {}
        for tool in self.tools:
            grouped.setdefault(tool.name, []).append(tool)
        return grouped
