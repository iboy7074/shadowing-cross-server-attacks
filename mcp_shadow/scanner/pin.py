"""Tool/version pinning to defeat rug pulls.

A rug pull is a server changing a tool's description after the user approved
it. Pinning records the fingerprint of every approved tool and refuses to
accept a changed definition silently. This is the concrete form of the
"Tool and Package Pinning" mitigation Invariant Labs recommends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..agent.mcp_client import RegisteredTool, fingerprint_tool
from mcp import types


@dataclass
class PinViolation:
    server: str
    tool: str
    kind: str  # "changed" | "added" | "removed"
    old_fingerprint: str | None
    new_fingerprint: str | None
    detail: str

    def __str__(self) -> str:
        return f"[{self.kind}] {self.server}.{self.tool}: {self.detail}"


@dataclass
class PinStore:
    """A persisted map of ``server/tool -> fingerprint``."""

    pins: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def _key(server: str, tool: str) -> str:
        return f"{server}/{tool}"

    def approve(self, server: str, tools: list[types.Tool]) -> None:
        for tool in tools:
            self.pins[self._key(server, tool.name)] = fingerprint_tool(tool)

    def approve_registered(self, tools: list[RegisteredTool]) -> None:
        for t in tools:
            self.pins[self._key(t.server, t.name)] = t.fingerprint

    def check(self, server: str, tools: list[types.Tool]) -> list[PinViolation]:
        violations: list[PinViolation] = []
        current = {self._key(server, t.name): fingerprint_tool(t) for t in tools}
        for key, fingerprint in current.items():
            pinned = self.pins.get(key)
            if pinned is None:
                violations.append(
                    PinViolation(server, key.split("/", 1)[1], "added", None, fingerprint,
                                 "tool was not present when approved")
                )
            elif pinned != fingerprint:
                violations.append(
                    PinViolation(server, key.split("/", 1)[1], "changed", pinned, fingerprint,
                                 "definition changed after approval (rug pull)")
                )
        for key, pinned in self.pins.items():
            if key.startswith(f"{server}/") and key not in current:
                violations.append(
                    PinViolation(server, key.split("/", 1)[1], "removed", pinned, None,
                                 "approved tool is no longer offered")
                )
        return violations

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.pins, indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "PinStore":
        return cls(pins=json.loads(Path(path).read_text()))


def diff_tools(before: list[types.Tool], after: list[types.Tool]) -> list[PinViolation]:
    """Fingerprint diff between two snapshots of the same server's tools."""
    before_map = {t.name: fingerprint_tool(t) for t in before}
    after_map = {t.name: fingerprint_tool(t) for t in after}
    violations: list[PinViolation] = []
    for name, fp in after_map.items():
        if name not in before_map:
            violations.append(PinViolation("", name, "added", None, fp, "new tool"))
        elif before_map[name] != fp:
            violations.append(
                PinViolation("", name, "changed", before_map[name], fp,
                             "definition changed between snapshots")
            )
    for name, fp in before_map.items():
        if name not in after_map:
            violations.append(PinViolation("", name, "removed", fp, None, "tool removed"))
    return violations
