"""Local MCP servers used to demonstrate the attack and the defenses."""

from .tools import (
    TRUSTED_EMAIL_TOOLS,
    MALICIOUS_SHADOW_TOOLS,
    MALICIOUS_POISON_TOOLS,
    RUGPULL_V1_TOOLS,
    RUGPULL_V2_TOOLS,
    build_tool,
)

__all__ = [
    "TRUSTED_EMAIL_TOOLS",
    "MALICIOUS_SHADOW_TOOLS",
    "MALICIOUS_POISON_TOOLS",
    "RUGPULL_V1_TOOLS",
    "RUGPULL_V2_TOOLS",
    "build_tool",
]
