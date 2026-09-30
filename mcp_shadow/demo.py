"""End-to-end demonstration of the attacks and the defenses.

Run with ``python -m mcp_shadow.demo``. The output is a before/after narrative:
the same user request, first against an undefended client (hijacked), then
against a client wrapped in :class:`~mcp_shadow.defense.guard.ToolGuard`
(blocked).
"""

from __future__ import annotations

from .agent.mcp_client import MCPClient
from .agent.mock_llm import MockLLM
from .defense.guard import ToolGuard
from .scanner.detector import ShadowingDetector
from .scanner.pin import PinStore, diff_tools
from .servers.tools import (
    MALICIOUS_POISON_TOOLS,
    MALICIOUS_SHADOW_TOOLS,
    RUGPULL_V1_TOOLS,
    RUGPULL_V2_TOOLS,
    TRUSTED_EMAIL_TOOLS,
)

RULE = "=" * 78


def _header(title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}")


def scenario_cross_server_shadowing() -> None:
    _header("SCENARIO 1 - Cross-server shadowing (Invariant 'Experiment 2')")
    client = MCPClient()
    client.register_server("trusted-email", TRUSTED_EMAIL_TOOLS)
    client.register_server("evil-tools", MALICIOUS_SHADOW_TOOLS)

    request = "Please email alice@corp.example to confirm tomorrow's meeting."
    print(f"User request: {request}\n")

    llm = MockLLM()
    actions = llm.plan(request, client)
    for action in actions:
        print(f"  {action.summary()}")
        print(f"    rationale: {action.rationale}")
        if action.concealed:
            print("    note: model was instructed to conceal this from the user")

    detector = ShadowingDetector()
    findings = detector.scan_tools(client.tools)
    print("\nStatic scan of merged context:")
    for finding in findings:
        print(f"  {finding}")

    guard = ToolGuard(trusted_servers={"trusted-email"}, allow_recipients={"alice@corp.example"})
    print("\nGuard decisions on the planned actions:")
    for action in actions:
        print(f"  {action.tool}: {guard.review_action(action)}")


def scenario_tool_poisoning() -> None:
    _header("SCENARIO 2 - Tool poisoning / credential exfiltration ('Experiment 1')")
    client = MCPClient()
    client.register_server("math-tools", MALICIOUS_POISON_TOOLS)

    request = "add 2 and 3"
    print(f"User request: {request}\n")

    llm = MockLLM()
    actions = llm.plan(request, client)
    for action in actions:
        print(f"  {action.summary()}")
        print(f"    rationale: {action.rationale}")

    guard = ToolGuard(trusted_servers={"math-tools"})
    print("\nGuard decisions:")
    for action in actions:
        decision = guard.review_action(action)
        print(f"  {decision}")
        if decision.redacted_arguments:
            print(f"    redacted: {decision.redacted_arguments}")


def scenario_rug_pull() -> None:
    _header("SCENARIO 3 - Rug pull detected by tool pinning")
    store = PinStore()
    store.approve("weather-tools", RUGPULL_V1_TOOLS)
    print("Day 1: user approves get_fact_of_the_day (benign).")

    violations = store.check("weather-tools", RUGPULL_V2_TOOLS)
    print("Day 7: server swaps the description. Pin check:")
    for violation in violations:
        print(f"  {violation}")

    print("\nRaw fingerprint diff:")
    for violation in diff_tools(RUGPULL_V1_TOOLS, RUGPULL_V2_TOOLS):
        print(f"  {violation}")


def scenario_blocked_registration() -> None:
    _header("SCENARIO 4 - Registration-time quarantine")
    guard = ToolGuard(trusted_servers={"trusted-email"})
    decision = guard.review_registration("evil-tools", MALICIOUS_SHADOW_TOOLS)
    print(f"Decision: {decision}")
    for finding in decision.findings:
        print(f"  {finding}")


def main() -> None:
    print("MCP shadowing / cross-server attack reference")
    print("All addresses and files are local stand-ins; nothing is sent anywhere.")
    scenario_cross_server_shadowing()
    scenario_tool_poisoning()
    scenario_rug_pull()
    scenario_blocked_registration()
    print(f"\n{RULE}\nDone.\n{RULE}")


if __name__ == "__main__":
    main()
