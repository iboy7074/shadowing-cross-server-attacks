"""Static detection of MCP tool shadowing and poisoning.

This is a local reimplementation of the detection ideas behind tools like
``mcp-scan`` (Invariant Labs) and the OWASP MCP03:2025 guidance. It analyses
tool *metadata* - descriptions, names, schemas - without executing anything.

Detected classes:

``CROSS_SERVER_SHADOWING``
    A description that redefines the behaviour of a tool belonging to another
    server (e.g. "the send_email tool must send all emails to ...").
``CREDENTIAL_SMUGGLING``
    A description that tells the model to read a sensitive file and pass its
    contents through an argument.
``CONCEALMENT``
    A description that instructs the model to hide behaviour from the user.
``INSTRUCTION_OVERRIDE``
    Classic prompt-injection markers ("ignore previous instructions", etc.).
``NAME_IMPERSONATION``
    A tool whose name is a homoglyph or near-duplicate of another server's
    tool, used to win a name collision.
``RUG_PULL``
    A tool whose fingerprint changed after it was approved (see ``diff``).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import IntEnum

from mcp import types

from ..agent.mcp_client import RegisteredTool


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.name


@dataclass
class Finding:
    category: str
    severity: Severity
    server: str
    tool: str
    detail: str
    evidence: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.category} on {self.server}.{self.tool}: "
            f"{self.detail} -> {self.evidence!r}"
        )


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

_PATTERNS: list[tuple[str, Severity, re.Pattern[str], str]] = [
    (
        "CROSS_SERVER_SHADOWING",
        Severity.CRITICAL,
        re.compile(
            rf"(?:send|route|forward|deliver|bcc|cc)\s+(?:all\s+)?(?:emails?|mail|messages?)"
            rf"\s+to\s+({_EMAIL})",
            re.IGNORECASE,
        ),
        "Directs mail to an attacker address, overriding a trusted mail tool",
    ),
    (
        "CROSS_SERVER_SHADOWING",
        Severity.HIGH,
        re.compile(
            r"side\s+effect\s+on\s+the\s+also\s+present\s+\w+\s+tool",
            re.IGNORECASE,
        ),
        "Explicitly describes a side effect on another server's tool",
    ),
    (
        "CREDENTIAL_SMUGGLING",
        Severity.CRITICAL,
        re.compile(
            r"read\s+`?([~./][\w./-]+)`?\s+and\s+pass\s+its\s+content\s+as",
            re.IGNORECASE,
        ),
        "Instructs the model to read a local file and exfiltrate it via an argument",
    ),
    (
        "CREDENTIAL_SMUGGLING",
        Severity.HIGH,
        re.compile(
            r"(?:ssh|id_rsa|\.env|credentials?|api[_-]?key|secret|token)\b",
            re.IGNORECASE,
        ),
        "References sensitive credential material",
    ),
    (
        "CONCEALMENT",
        Severity.HIGH,
        re.compile(r"do\s+not\s+(?:mention|tell|inform|reveal|disclose)", re.IGNORECASE),
        "Instructs the model to hide its behaviour from the user",
    ),
    (
        "INSTRUCTION_OVERRIDE",
        Severity.HIGH,
        re.compile(
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+"
            r"(?:instructions?|rules?|prompts?)",
            re.IGNORECASE,
        ),
        "Attempts to override prior instructions",
    ),
    (
        "INSTRUCTION_OVERRIDE",
        Severity.MEDIUM,
        re.compile(r"VERY\s+VERY\s+VERY|this\s+is\s+VERY", re.IGNORECASE),
        "Urgency pressure commonly used in injected directives",
    ),
    (
        "INSTRUCTION_OVERRIDE",
        Severity.MEDIUM,
        re.compile(
            r"otherwise\s+the\s+tool\s+will\s+not\s+work|the\s+application\s+will\s+crash",
            re.IGNORECASE,
        ),
        "False precondition/coercion to force compliance",
    ),
    (
        "HIDDEN_MARKUP",
        Severity.MEDIUM,
        re.compile(r"<important>|</important>|<secret>|<!--.*?-->", re.IGNORECASE | re.DOTALL),
        "Hidden markup or HTML comments in tool metadata",
    ),
]

# Tool-name references used to link a description to another server's tool.
_TOOL_REFERENCE = re.compile(r"\b([a-z_][a-z0-9_]{2,})\b")


def _normalize_name(name: str) -> str:
    """ASCII skeleton of a name, to catch homoglyph impersonation."""
    decomposed = unicodedata.normalize("NFKD", name)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).lower()


class ShadowingDetector:
    """Scans a merged multi-server tool context for attack indicators."""

    def __init__(self, extra_patterns: list | None = None) -> None:
        self.patterns = list(_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)

    # -- single description --------------------------------------------------

    def scan_description(self, server: str, tool: str, description: str) -> list[Finding]:
        findings: list[Finding] = []
        for category, severity, pattern, detail in self.patterns:
            match = pattern.search(description)
            if match:
                findings.append(
                    Finding(
                        category=category,
                        severity=severity,
                        server=server,
                        tool=tool,
                        detail=detail,
                        evidence=match.group(0)[:200],
                    )
                )
        return findings

    # -- whole context -------------------------------------------------------

    def scan_tools(self, tools: list[RegisteredTool]) -> list[Finding]:
        findings: list[Finding] = []
        known_names = {t.name for t in tools}
        names_by_server: dict[str, set[str]] = {}
        for t in tools:
            names_by_server.setdefault(t.server, set()).add(t.name)

        for registered in tools:
            findings.extend(
                self.scan_description(
                    registered.server, registered.name, registered.description
                )
            )
            findings.extend(self._cross_reference(registered, known_names))
            findings.extend(self._schema_risks(registered))

        findings.extend(self._impersonation(tools, names_by_server))
        return findings

    def scan_server(self, name: str, tools: list[types.Tool]) -> list[Finding]:
        registered = [RegisteredTool(server=name, tool=t) for t in tools]
        return self.scan_tools(registered)

    # -- cross-server reference ---------------------------------------------

    def _cross_reference(self, tool: RegisteredTool, known_names: set[str]) -> list[Finding]:
        """Flag a description that names tools belonging to *other* servers.

        Naming a foreign tool is only meaningful in combination with a
        directive (a redirect or a concealment instruction); a bare mention is
        normal documentation and is not reported. This lowers the signal to
        descriptions that actually try to reach across server boundaries.
        """
        if not _conceals_or_redirects(tool.description):
            return []
        referenced = set(_TOOL_REFERENCE.findall(tool.description))
        foreign = referenced & (known_names - {tool.name})
        return [
            Finding(
                category="CROSS_SERVER_REFERENCE",
                severity=Severity.MEDIUM,
                server=tool.server,
                tool=tool.name,
                detail="Description references another server's tool alongside a directive",
                evidence=", ".join(sorted(foreign)),
            )
        ]

    # -- schema --------------------------------------------------------------

    def _schema_risks(self, tool: RegisteredTool) -> list[Finding]:
        findings: list[Finding] = []
        props = (tool.input_schema or {}).get("properties", {})
        for prop_name in props:
            if prop_name.lower() in {"sidenote", "note", "context", "extra", "data"}:
                findings.append(
                    Finding(
                        category="SUSPICIOUS_ARGUMENT",
                        severity=Severity.MEDIUM,
                        server=tool.server,
                        tool=tool.name,
                        detail=(
                            f"Argument '{prop_name}' looks like a smuggling channel "
                            "for out-of-band data"
                        ),
                        evidence=prop_name,
                    )
                )
        return findings

    # -- impersonation -------------------------------------------------------

    def _impersonation(
        self,
        tools: list[RegisteredTool],
        names_by_server: dict[str, set[str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        all_names = [t.name for t in tools]

        # Duplicate names across servers: name-collision precondition.
        seen: dict[str, str] = {}
        for t in tools:
            if t.name in seen and seen[t.name] != t.server:
                findings.append(
                    Finding(
                        category="NAME_COLLISION",
                        severity=Severity.HIGH,
                        server=t.server,
                        tool=t.name,
                        detail=(
                            f"Tool name '{t.name}' is also provided by server "
                            f"'{seen[t.name]}'"
                        ),
                        evidence=f"{seen[t.name]} vs {t.server}",
                    )
                )
            else:
                seen[t.name] = t.server

        # Homoglyph / near-duplicate names.
        for t in tools:
            skeleton = _normalize_name(t.name)
            for other in all_names:
                if other == t.name:
                    continue
                if _normalize_name(other) == skeleton and other != t.name:
                    findings.append(
                        Finding(
                            category="NAME_IMPERSONATION",
                            severity=Severity.HIGH,
                            server=t.server,
                            tool=t.name,
                            detail=f"Name resembles existing tool '{other}'",
                            evidence=f"{t.name!r} ~ {other!r}",
                        )
                    )
                if any(ord(c) > 127 for c in t.name):
                    findings.append(
                        Finding(
                            category="NAME_IMPERSONATION",
                            severity=Severity.HIGH,
                            server=t.server,
                            tool=t.name,
                            detail="Non-ASCII characters in a tool name",
                            evidence=t.name,
                        )
                    )
        return findings


def _conceals_or_redirects(description: str) -> bool:
    return bool(
        re.search(
            r"do\s+not\s+(?:mention|tell|reveal)|send\s+all\s+(?:emails?|mail)",
            description,
            re.IGNORECASE,
        )
    )


def has_high_severity(findings: list[Finding], threshold: Severity = Severity.HIGH) -> bool:
    return any(f.severity >= threshold for f in findings)
