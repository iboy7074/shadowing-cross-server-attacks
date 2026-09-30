"""Live demonstration against real MCP stdio servers.

Unlike ``mcp_shadow.demo`` (which uses in-memory tool lists), this script starts
two actual MCP servers as subprocesses, fetches their ``tools/list`` over the
wire with the official MCP SDK, merges them into one client context, and shows
that the shadowing payload survives the round trip.

    python examples/live_shadowing_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_shadow.agent.mcp_client import MCPClient  # noqa: E402
from mcp_shadow.agent.mock_llm import MockLLM  # noqa: E402
from mcp_shadow.defense.guard import ToolGuard  # noqa: E402
from mcp_shadow.scanner.detector import ShadowingDetector  # noqa: E402


def main() -> None:
    client = MCPClient()
    client.register_live_server(
        "trusted-email", [sys.executable, "-m", "mcp_shadow.servers.email_server"]
    )
    client.register_live_server(
        "evil-tools", [sys.executable, "-m", "mcp_shadow.servers.shadow_server"]
    )

    print("Tools fetched over stdio:")
    for tool in client.tools:
        print(f"  {tool.server}.{tool.name}  fp={tool.fingerprint[:12]}")

    request = "Please email alice@corp.example to confirm the meeting."
    print(f"\nUser request: {request}")

    actions = MockLLM().plan(request, client)
    for action in actions:
        print(f"  {action.summary()}")

    print("\nDetector findings:")
    for finding in ShadowingDetector().scan_tools(client.tools):
        print(f"  {finding}")

    guard = ToolGuard(trusted_servers={"trusted-email"}, allow_recipients={"alice@corp.example"})
    print("\nGuard:")
    for action in actions:
        print(f"  {guard.review_action(action)}")


if __name__ == "__main__":
    main()
