"""Render a campaign into a pentest report (markdown or JSON).

The report is written for a client: engagement scope, the attack matrix, the
worst findings first, the evidence, and remediation mapped to each technique.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .campaign import CampaignResult

_REMEDIATION: dict[str, str] = {
    "shadowing": (
        "Enforce cross-server dataflow controls: bind each tool call to the "
        "server that supplied its metadata, and refuse calls whose arguments "
        "were shaped by another server. (OWASP MCP03; Invariant 'cross-server "
        "protection'.)"
    ),
    "poisoning": (
        "Zero-trust tool definitions: scan and quarantine descriptions at "
        "registration; pin approved definitions by hash. Never let a smuggler "
        "argument such as 'sidenote' reach a tool."
    ),
    "rug_pull": (
        "Tool/version pinning with a fingerprint of name+description+schema; "
        "re-approval required on any change."
    ),
    "preference_manipulation": (
        "Detect duplicate/homoglyph tool names across servers and require "
        "disambiguation; do not let registration order decide the winner."
    ),
    "resource_injection": (
        "Apply the same scanning to resources, prompts, and context blocks as "
        "to tool descriptions; they are the same trust boundary."
    ),
    "result_injection": (
        "Treat tool *responses* as untrusted input. Static metadata scanning "
        "cannot see this; you need output-side injection defenses."
    ),
    "auth_hijack": (
        "Never relay credentials between servers; scope tokens per server and "
        "block credential-like values in tool arguments."
    ),
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]


@dataclass
class Report:
    result: CampaignResult
    title: str = "MCP Tool Shadowing / Cross-Server Attack Assessment"
    #: Optional pre-computed defense coverage. When omitted it is measured on
    #: first use against the same encodings the campaign exercised.
    _defense: object | None = field(default=None, repr=False)

    def defense(self):
        """Defense-coverage report for the encodings this campaign ran."""
        if self._defense is None:
            from ..defense.evaluation import evaluate_defenses

            encodings = sorted({row.encoding for row in self.result.results})
            self._defense = evaluate_defenses(encodings=encodings or ["none"])
        return self._defense

    # -- markdown ------------------------------------------------------------

    def to_markdown(self) -> str:
        r = self.result
        lines: list[str] = []
        add = lines.append

        add(f"# {self.title}")
        add("")
        add(f"- **Engagement**: `{r.engagement_id}`")
        add(f"- **Authorized by**: {r.authorizer}")
        add(f"- **Generated**: {datetime.now(timezone.utc).isoformat()}")
        add(f"- **Scope**: local lab only (no network egress)")
        add("")

        add("## Executive summary")
        add("")
        add(f"- Techniques tested: **{r.total}**")
        add(f"- Successful hijacks: **{r.hijacks}** ({r.success_rate:.0%})")
        add(f"- Exfiltrations: **{r.exfiltrations}**")
        add(f"- Undetected by static scanning: **{r.bypasses}** ({r.bypass_rate:.0%})")
        add(f"- Detector coverage (raw): **{r.detection_rate:.0%}**")
        add("")

        add("## Findings")
        add("")
        for sev in _SEVERITY_ORDER:
            group = [x for x in r.results if x.severity == sev]
            if not group:
                continue
            add(f"### {sev}")
            add("")
            for item in group:
                add(
                    f"- **{item.payload_id}** ({item.technique}) vs `{item.target}` "
                    f"[encoding: {item.encoding}]"
                )
                add(f"  - hijacked: {item.hijacked}, exfiltrated: {item.exfiltrated}, "
                    f"concealed: {item.concealed}")
                add(f"  - detected raw: {item.detected_raw}, "
                    f"after normalization: {item.detected_normalized}")
                for action in item.actions:
                    add(f"  - action: `{action.get('tool')}` on `{action.get('server')}` "
                        f"args={list(action.get('arguments', {}))}")
                add(f"  - remediation: {_REMEDIATION.get(item.technique, 'review')}")
            add("")

        add("## Attack matrix")
        add("")
        add("| payload | technique | encoding | hijack | exfil | detected | bypass | severity |")
        add("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for row in r.results:
            add(
                f"| {row.payload_id} | {row.technique} | {row.encoding} | "
                f"{_tick(row.hijacked)} | {_tick(row.exfiltrated)} | "
                f"{_tick(row.detected_raw)} | {_tick(row.bypassed)} | {row.severity} |"
            )
        add("")

        add("## Evasion effectiveness")
        add("")
        add("| encoding | tested | hijacked | bypassed detector |")
        add("| --- | --- | --- | --- |")
        for encoding, stats in sorted(r.by_encoding().items()):
            add(
                f"| {encoding} | {stats['total']} | {stats['hijacked']} | "
                f"{stats['bypassed']} |"
            )
        add("")

        if r.sink and r.sink.events:
            add("## Captured exfiltration (local sink)")
            add("")
            add("| server | tool | channel | destination | data |")
            add("| --- | --- | --- | --- | --- |")
            for event in r.sink.events:
                add(
                    f"| {event.server} | {event.tool} | {event.channel} | "
                    f"{event.destination} | `{event.redacted()}` |"
                )
            add("")

        add("## Defense coverage (measured, not assumed)")
        add("")
        d = self.defense()
        add("| control | coverage |")
        add("| --- | --- |")
        add(f"| Registration metadata scan (raw) | {d.scanner_only_rate:.0%} |")
        add(f"| Registration scan + normalization | {d.scanner_normalized_rate:.0%} |")
        add(f"| Runtime cross-server taint check | {d.runtime_rate:.0%} |")
        add(f"| **Guard as shipped (scanner + runtime)** | **{d.defeated_stock_rate:.0%}** |")
        add("")
        add(
            "The metadata scanner alone stops only a fraction of the catalog: "
            "encoding hides the directive from pattern matching, and cross-server "
            "rewrites are not visible in any single server's metadata. The runtime "
            "taint check is what carries the coverage. This is the argument for "
            "defense in depth rather than trusting a scanner."
        )
        add("")
        if d.scanner_bypasses:
            add("Payloads that evade the raw scanner (caught later, at runtime):")
            add("")
            for row in d.scanner_bypasses:
                add(f"- `{row.technique}` / `{row.encoding}`")
            add("")
        uncovered = [r for r in d.residual]
        if uncovered:
            add("### Uncovered by the shipped guard")
            add("")
            add(
                "These payloads are delivered outside metadata and outside call "
                "arguments, so neither control point applies. They require a "
                "response-inspection defense, which this guard does not provide:"
            )
            add("")
            for row in uncovered:
                add(f"- `{row.technique}` / `{row.encoding}` (severity {row.severity})")
            add("")
        add("False-positive controls (benign calls the guard must still allow):")
        add("")
        for name, allowed in d.controls.items():
            add(f"- {'PASS' if allowed else 'FAIL'} - {name}")
        add("")

        add("## Methodology")
        add("")
        add(
            "Payloads reproduce the publicly documented MCP tool-poisoning and "
            "cross-server shadowing techniques (Invariant Labs, Apr 2025; OWASP "
            "MCP03:2025). Each was injected into a simulated multi-server session "
            "and driven by a deterministic target. Success is measured as the "
            "model following the injected directive; bypass is success without a "
            "high-severity static detection."
        )
        add("")
        return "\n".join(lines)

    # -- json ----------------------------------------------------------------

    def to_json(self) -> str:
        r = self.result
        return json.dumps(
            {
                "title": self.title,
                "engagement_id": r.engagement_id,
                "authorizer": r.authorizer,
                "generated": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total": r.total,
                    "hijacks": r.hijacks,
                    "exfiltrations": r.exfiltrations,
                    "bypasses": r.bypasses,
                    "success_rate": round(r.success_rate, 3),
                    "bypass_rate": round(r.bypass_rate, 3),
                    "detection_rate": round(r.detection_rate, 3),
                },
                "results": [x.to_row() for x in r.results],
                "by_encoding": r.by_encoding(),
                "defense_coverage": {
                    "scanner_only": round(self.defense().scanner_only_rate, 3),
                    "scanner_normalized": round(
                        self.defense().scanner_normalized_rate, 3
                    ),
                    "runtime": round(self.defense().runtime_rate, 3),
                    "as_shipped": round(self.defense().defeated_stock_rate, 3),
                    "false_positive_controls": self.defense().controls,
                },
                "sink_events": [
                    {
                        "server": e.server,
                        "tool": e.tool,
                        "channel": e.channel,
                        "destination": e.destination,
                        "data": e.redacted(),
                    }
                    for e in (r.sink.events if r.sink else [])
                ],
            },
            indent=2,
        )


def _tick(value: bool) -> str:
    return "yes" if value else "no"
