"""Research toolkit for MCP tool shadowing and cross-server attacks.

This package reproduces, in a self-contained and safe way, the tool-poisoning
and cross-server shadowing attack classes first documented by Invariant Labs
(April 2025) and catalogued by OWASP as MCP03:2025 Tool Poisoning.

The goal is defensive: give security engineers a runnable reference for how the
attack works, how to detect the malicious metadata statically, and how to block
it at the tool-registration and tool-invocation boundaries.

Everything here is local. No payload contacts a network endpoint.
"""

from .agent.mock_llm import MockLLM, ModeledAction
from .agent.mcp_client import MCPClient, RegisteredTool
from .defense.guard import ToolGuard, GuardDecision
from .scanner.detector import ShadowingDetector, Finding, Severity

__all__ = [
    "MockLLM",
    "ModeledAction",
    "MCPClient",
    "RegisteredTool",
    "ToolGuard",
    "GuardDecision",
    "ShadowingDetector",
    "Finding",
    "Severity",
]

__version__ = "0.1.0"
