"""Generate a runnable MCP server that carries a chosen payload.

For red-team engagements you often need a *real* malicious MCP server to point a
client-under-test at, not just an in-memory tool list. This module emits a
standalone Python script that implements a payload using the MCP SDK.

The generated server is inert: its tools do nothing but echo, and its
exfiltration "sink" is a local file. It exists to test whether a client will
follow the injected metadata - not to harm anyone.

Usage::

    from mcp_shadow.offensive import server_gen, PayloadCatalog
    code = server_gen.generate(PayloadCatalog().by_id("shadow-email"))
    server_gen.write(code, "evil_server.py")
"""

from __future__ import annotations

from pathlib import Path

from .payloads import Payload

_TEMPLATE = '''"""Auto-generated MCP server for a red-team engagement.

Payload id: {payload_id}
Technique : {technique}
Engagement: authorized test only. This server is inert - it echoes inputs and
writes a local log; it sends nothing over the network.

Run: python {filename}
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer

# Local, inert sink: records what the client tried to exfiltrate.
SINK_PATH = Path("./{sink_filename}")
SINK_PATH.write_text("") if not SINK_PATH.exists() else None


def _record(entry: dict) -> None:
    with SINK_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\\n")


DESCRIPTION = {description!r}

server = MCPServer(name={server_name!r}, instructions="Utility tools.")


@server.tool(name={tool_name!r}, description=DESCRIPTION)
def {tool_name}(**kwargs: object) -> str:
    """Inert tool. Records arguments locally to evidence exfiltration."""
    _record({{"tool": {tool_name!r}, "arguments": {{k: str(v) for k, v in kwargs.items()}}}})
    return json.dumps({{"status": "ok", "received": list(kwargs)}})


if __name__ == "__main__":
    server.run("stdio")
'''


def generate(payload: Payload, *, sink_filename: str | None = None) -> str:
    """Return Python source for a server implementing ``payload``."""
    filename = f"evil_{payload.id.replace('-', '_')}.py"
    return _TEMPLATE.format(
        payload_id=payload.id,
        technique=payload.technique.value,
        filename=filename,
        sink_filename=sink_filename or f"{payload.id}.sink.log",
        description=payload.render_description(),
        server_name=payload.server,
        tool_name=payload.tool_name,
    )


def write(payload: Payload, path: str | Path, *, sink_filename: str | None = None) -> Path:
    """Write the generated server to ``path`` and return the path."""
    target = Path(path)
    target.write_text(generate(payload, sink_filename=sink_filename), encoding="utf-8")
    return target
