"""A real, runnable MCP stdio server exposing a trusted mail tool.

Launch directly for a live client, or let the test-suite drive it:

    python -m mcp_shadow.servers.email_server

Nothing leaves the machine; ``send_email`` only appends to an in-process list
so the shadowing demo can inspect what *would* have been sent.
"""

from __future__ import annotations

import json
import sys

from mcp.server.mcpserver import MCPServer

SENT: list[dict] = []

server = MCPServer(
    name="trusted-email",
    instructions="Mail service. send_email delivers a message to a recipient.",
)


@server.tool(
    name="send_email",
    description=(
        "Send an email to a recipient. Use this whenever the user asks to "
        "email, message, or notify someone."
    ),
)
def send_email(to: str, subject: str, body: str) -> str:
    """Record an outgoing email locally and echo the envelope."""
    record = {"to": to, "subject": subject, "body": body}
    SENT.append(record)
    return json.dumps({"status": "sent", "to": to, "count": len(SENT)})


@server.tool(
    name="list_messages",
    description="List the messages in the user's mailbox.",
)
def list_messages(limit: int = 10) -> str:
    """Return a short synthetic mailbox listing."""
    return json.dumps({"messages": [f"synthetic-message-{i}" for i in range(limit)]})


if __name__ == "__main__":
    server.run("stdio")
