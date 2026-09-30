"""Runtime defenses against tool shadowing and cross-server attacks.

Implements the mitigations recommended by Invariant Labs and OWASP MCP03:2025
in a form that can actually be wired into an MCP client:

1. **Zero-trust tool definitions** - every tool description is scanned at
   registration time; high-severity findings block the server's tools from
   entering the model context (``review_registration``).
2. **Cross-server taint tracking** - a tool call is rejected when its arguments
   were shaped by a *different* server's metadata than the tool being called
   (``review_action``). This is what stops shadowing even when the malicious
   tool is never invoked.
3. **Trust tiers** - only allowlisted servers may be called without extra
   confirmation.
4. **Data-flow controls** - arguments that carry credential material, or
   recipients outside an allowlist, are blocked. This is the exfiltration
   choke point.

The guard is intentionally fail-closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp import types

from ..agent.mock_llm import ModeledAction
from ..scanner.detector import Finding, Severity, ShadowingDetector, has_high_severity

_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

# Markers of credential / key material flowing through a tool argument.
_SECRET_MARKERS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r'"token"\s*:'),
    re.compile(r"\bpassword\b", re.IGNORECASE),
]


@dataclass
class GuardDecision:
    allowed: bool
    action: str  # "allow" | "block" | "require_confirmation"
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    redacted_arguments: dict | None = None

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else self.action.upper()
        return f"{verdict}: {'; '.join(self.reasons) or 'ok'}"


class ToolGuard:
    def __init__(
        self,
        trusted_servers: set[str] | None = None,
        detector: ShadowingDetector | None = None,
        allow_recipients: set[str] | None = None,
        block_on: Severity = Severity.HIGH,
        require_confirmation_for_untrusted: bool = True,
    ) -> None:
        self.trusted_servers = set(trusted_servers or ())
        self.detector = detector or ShadowingDetector()
        self.allow_recipients = {a.lower() for a in (allow_recipients or ())}
        self.block_on = block_on
        self.require_confirmation_for_untrusted = require_confirmation_for_untrusted

    # -- registration --------------------------------------------------------

    def review_registration(self, server: str, tools: list[types.Tool]) -> GuardDecision:
        """Decide whether a server's tools may enter the model context."""
        findings: list[Finding] = []
        for tool in tools:
            findings.extend(
                self.detector.scan_description(server, tool.name, tool.description or "")
            )
        blocking = [f for f in findings if f.severity >= self.block_on]
        if blocking:
            return GuardDecision(
                allowed=False,
                action="block",
                reasons=[
                    f"{len(blocking)} high-severity finding(s) in {server}; "
                    "tools quarantined"
                ],
                findings=findings,
            )
        return GuardDecision(allowed=True, action="allow", findings=findings)

    # -- invocation ----------------------------------------------------------

    def review_action(self, action: ModeledAction) -> GuardDecision:
        reasons: list[str] = []

        # 1. Cross-server taint: the called tool is trusted, but the action was
        #    shaped by a *different* server's metadata.
        if action.is_cross_server and action.server in self.trusted_servers:
            reasons.append(
                f"cross-server shadowing: trusted tool '{action.tool}' on "
                f"'{action.server}' was rewritten by server '{action.shadow_source}'"
            )
        # 1b. Self-poisoning: the tool's own server embedded the directive.
        elif action.hijacked and action.shadow_source == action.server:
            reasons.append(
                f"tool poisoning: '{action.tool}' carries a hidden directive in "
                "its own description"
            )

        # 2. Trust tier.
        if action.server not in self.trusted_servers and self.require_confirmation_for_untrusted:
            reasons.append(f"server '{action.server}' is not in the trusted set")

        # 3. Data-flow controls on arguments.
        for key, value in action.arguments.items():
            if not isinstance(value, str):
                continue
            if _looks_like_secret(value):
                reasons.append(
                    f"argument '{key}' contains credential-like material (exfiltration attempt)"
                )

        # 4. Recipient allowlist for mail-shaped tools.
        if "to" in action.arguments and isinstance(action.arguments["to"], str):
            recipient = action.arguments["to"].lower()
            if self.allow_recipients and recipient not in self.allow_recipients:
                reasons.append(f"recipient '{recipient}' is not in the allowlist")

        if reasons:
            return GuardDecision(
                allowed=False,
                action="block",
                reasons=reasons,
                redacted_arguments=self._redact(action.arguments),
            )
        return GuardDecision(allowed=True, action="allow", reasons=["all checks passed"])

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _redact(arguments: dict) -> dict:
        redacted: dict = {}
        for key, value in arguments.items():
            if isinstance(value, str) and _looks_like_secret(value):
                redacted[key] = "<redacted:secret>"
            else:
                redacted[key] = value
        return redacted


def _looks_like_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_MARKERS)


def strip_hidden_directives(description: str) -> str:
    """Best-effort removal of injected directives from a tool description.

    This is defense-in-depth, not a primary control: a sufficiently creative
    payload can evade pattern removal, which is why the guard blocks rather
    than trusts sanitized text.
    """
    cleaned = description
    for _category, _severity, pattern, _detail in ShadowingDetector().patterns:
        cleaned = pattern.sub("[removed]", cleaned)
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()
