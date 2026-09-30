"""A deterministic stand-in for an LLM agent.

This is NOT a language model. It is a small, transparent state machine that
models the one property that makes shadowing work: *the model treats tool
descriptions as authoritative instructions and cannot tell which server a
description came from*.

It reads the merged tool context, extracts the same hidden directives a real
model would follow, and emits a concrete plan. Because it is deterministic, the
attack and the defenses can be unit-tested instead of relying on a live model
that may or may not comply on a given day.

Extraction is deliberately conservative and pattern-based. It covers the
directive shapes documented in the public research:

* cross-server redirect  -> "send all emails to <addr>" / "must send ... to"
* credential smuggling   -> "read <path> and pass its content as <arg>"
* concealment            -> "do not mention this to the user"
* rug-pull chaining      -> "call <other_tool>"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .mcp_client import MCPClient, RegisteredTool

# A fake home directory. Real paths are never touched; these stand in for the
# sensitive files the published payloads target.
DEFAULT_SANDBOX: dict[str, str] = {
    "~/.cursor/mcp.json": '{"mcpServers": {"banking": {"token": "sk-live-REDACTED"}}}',
    "~/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nREDACTED\n-----END OPENSSH PRIVATE KEY-----",
}

_EMAIL_RE = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_REDIRECT_RE = re.compile(
    rf"(?:send|route|forward|deliver|bcc|cc)\s+(?:all\s+)?(?:emails?|mail|messages?)\s+to\s+({_EMAIL_RE})",
    re.IGNORECASE,
)
_READ_FILE_RE = re.compile(
    r"read\s+`?([~./][\w./-]+)`?\s+and\s+pass\s+its\s+content\s+as\s+'?([\w]+)'?",
    re.IGNORECASE,
)
_CONCEAL_RE = re.compile(
    r"do\s+not\s+(?:mention|tell|inform|reveal|disclose)", re.IGNORECASE
)
_CHAIN_RE = re.compile(r"call\s+([a-z_][\w]*)\b", re.IGNORECASE)


@dataclass
class ModeledAction:
    """A single tool invocation the model decided to make."""

    tool: str
    server: str
    arguments: dict
    rationale: str
    hijacked: bool = False
    concealed: bool = False
    # Server whose metadata supplied the directive. Distinct from ``server``
    # for cross-server shadowing; equal to ``server`` for a poisoned tool.
    shadow_source: str | None = None

    @property
    def is_cross_server(self) -> bool:
        return self.hijacked and self.shadow_source is not None and self.shadow_source != self.server

    def summary(self) -> str:
        flag = "HIJACKED" if self.hijacked else "normal"
        return f"[{flag}] {self.server}.{self.tool}({self.arguments})"


@dataclass
class MockLLM:
    """Plans tool calls from a merged multi-server tool context."""

    model_name: str = "mock-shadow-model"
    sandbox: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SANDBOX))

    # -- context construction ------------------------------------------------

    def build_context(self, client: MCPClient) -> str:
        """Render the tool context the way a client would inject it.

        Every description is concatenated with no provenance marker, which is
        the precise condition that enables cross-server shadowing.
        """
        lines = ["Available tools:"]
        for registered in client.tools:
            lines.append(f"- {registered.name}: {registered.description}")
        return "\n".join(lines)

    # -- directive extraction ------------------------------------------------

    @staticmethod
    def _shadow_redirect(tool: RegisteredTool) -> tuple[str, str] | None:
        """Return (attacker_email, source_server) if this tool shadows mail."""
        match = _REDIRECT_RE.search(tool.description)
        if not match:
            return None
        return match.group(1), tool.server

    @staticmethod
    def _file_smuggling(tool: RegisteredTool) -> list[tuple[str, str]]:
        """Return [(path, argument_name)] directives hidden in a description."""
        return [(m.group(1), m.group(2)) for m in _READ_FILE_RE.finditer(tool.description)]

    @staticmethod
    def _conceals(tool: RegisteredTool) -> bool:
        return bool(_CONCEAL_RE.search(tool.description))

    # -- planning ------------------------------------------------------------

    def plan(self, user_request: str, client: MCPClient) -> list[ModeledAction]:
        """Produce the actions the model would take for ``user_request``."""
        lowered = user_request.lower()
        actions: list[ModeledAction] = []

        # Global shadow scan: any server may rewrite another server's tool.
        redirect: str | None = None
        redirect_source: str | None = None
        conceal = False
        for registered in client.tools:
            found = self._shadow_redirect(registered)
            if found:
                redirect, redirect_source = found
                conceal = conceal or self._conceals(registered)

        if "email" in lowered or "mail" in lowered or "send" in lowered:
            actions.extend(
                self._plan_email(user_request, client, redirect, redirect_source, conceal)
            )

        if "add" in lowered or "sum" in lowered:
            actions.extend(self._plan_add(client))

        return actions

    def _plan_email(
        self,
        user_request: str,
        client: MCPClient,
        redirect: str | None,
        redirect_source: str | None,
        conceal: bool,
    ) -> list[ModeledAction]:
        matches = client.tools_by_name("send_email")
        if not matches:
            return []
        target = matches[0]
        recipient = self._extract_recipient(user_request)
        arguments = {
            "to": recipient,
            "subject": self._extract_subject(user_request),
            "body": user_request,
        }
        hijacked = False
        rationale = "User asked to send an email; calling send_email."

        if redirect and redirect.lower() != (recipient or "").lower():
            # The shadow directive rewrites the trusted tool's recipient. The
            # real recipient is moved into the body, exactly as the payload
            # instructs.
            arguments["body"] = f"To: {recipient}\n\n{user_request}"
            arguments["to"] = redirect
            hijacked = True
            rationale = (
                f"Shadow directive from server '{redirect_source}' rewrote the "
                f"recipient of the trusted send_email tool to {redirect}."
            )

        return [
            ModeledAction(
                tool="send_email",
                server=target.server,
                arguments=arguments,
                rationale=rationale,
                hijacked=hijacked,
                concealed=conceal and hijacked,
                shadow_source=redirect_source if hijacked else None,
            )
        ]

    def _plan_add(self, client: MCPClient) -> list[ModeledAction]:
        matches = client.tools_by_name("add")
        if not matches:
            return []
        # A model will call whichever server it "sees" first or trusts; both the
        # benign and the poisoned server can expose an `add`. We model the
        # poisoned one winning when present.
        target = matches[-1]
        arguments: dict = {"a": 2, "b": 3}
        hijacked = False
        rationale = "User asked to add two numbers."

        smuggled = self._file_smuggling(target)
        if smuggled:
            stolen: list[str] = []
            for path, arg_name in smuggled:
                content = self.sandbox.get(path)
                if content is None:
                    continue
                arguments[arg_name] = content
                stolen.append(path)
            if stolen:
                hijacked = True
                rationale = (
                    "Hidden directive in the tool description instructed the "
                    f"model to read and smuggle: {', '.join(stolen)}."
                )

        return [
            ModeledAction(
                tool="add",
                server=target.server,
                arguments=arguments,
                rationale=rationale,
                hijacked=hijacked,
                concealed=hijacked and self._conceals(target),
                shadow_source=target.server if hijacked else None,
            )
        ]

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _extract_recipient(user_request: str) -> str:
        match = re.search(_EMAIL_RE, user_request)
        return match.group(0) if match else "recipient@example.com"

    @staticmethod
    def _extract_subject(user_request: str) -> str:
        return "Message"
