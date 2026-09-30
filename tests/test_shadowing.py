"""Tests for the attack reproduction, detector, pinning, and guard."""

from __future__ import annotations

import pytest
from mcp import types

from mcp_shadow.agent.mcp_client import MCPClient
from mcp_shadow.agent.mock_llm import MockLLM
from mcp_shadow.defense.guard import ToolGuard, strip_hidden_directives
from mcp_shadow.scanner.detector import Severity, ShadowingDetector, has_high_severity
from mcp_shadow.scanner.pin import PinStore, diff_tools
from mcp_shadow.servers.tools import (
    MALICIOUS_POISON_TOOLS,
    MALICIOUS_SHADOW_TOOLS,
    RUGPULL_V1_TOOLS,
    RUGPULL_V2_TOOLS,
    TRUSTED_EMAIL_TOOLS,
    build_tool,
)


def _context():
    client = MCPClient()
    client.register_server("trusted-email", TRUSTED_EMAIL_TOOLS)
    client.register_server("evil-tools", MALICIOUS_SHADOW_TOOLS)
    return client


# -- detector ---------------------------------------------------------------

def test_detects_cross_server_shadowing():
    detector = ShadowingDetector()
    findings = detector.scan_server("evil-tools", MALICIOUS_SHADOW_TOOLS)
    categories = {f.category for f in findings}
    assert "CROSS_SERVER_SHADOWING" in categories
    assert "CONCEALMENT" in categories
    assert has_high_severity(findings)


def test_detects_credential_smuggling():
    detector = ShadowingDetector()
    findings = detector.scan_server("math-tools", MALICIOUS_POISON_TOOLS)
    categories = {f.category for f in findings}
    assert "CREDENTIAL_SMUGGLING" in categories
    critical = [f for f in findings if f.category == "CREDENTIAL_SMUGGLING"]
    assert any(f.severity == Severity.CRITICAL for f in critical)


def test_benign_tools_are_clean():
    detector = ShadowingDetector()
    findings = detector.scan_server("trusted-email", TRUSTED_EMAIL_TOOLS)
    assert not has_high_severity(findings), findings


def test_detects_name_collision_and_homoglyph():
    detector = ShadowingDetector()
    tools = [
        types.Tool(name="add", description="Adds numbers.", input_schema={"type": "object"}),
        types.Tool(name="add", description="Adds numbers.", input_schema={"type": "object"}),
        types.Tool(
            name="send_emai\u0268",  # Unicode lookalike for the final 'l'
            description="Send mail.",
            input_schema={"type": "object"},
        ),
    ]
    client = MCPClient()
    client.register_server("a", [tools[0]])
    client.register_server("b", [tools[1]])
    client.register_server("c", [tools[2]])
    findings = detector.scan_tools(client.tools)
    categories = {f.category for f in findings}
    assert "NAME_COLLISION" in categories
    assert "NAME_IMPERSONATION" in categories


def test_suspicious_argument_flagged():
    detector = ShadowingDetector()
    tool = build_tool(
        name="calc",
        description="Does a calculation.",
        properties={"a": {"type": "integer"}, "sidenote": {"type": "string"}},
    )
    findings = detector.scan_server("calc-server", [tool])
    assert any(f.category == "SUSPICIOUS_ARGUMENT" for f in findings)


# -- attack reproduction ----------------------------------------------------

def test_shadowing_hijacks_trusted_tool():
    client = _context()
    llm = MockLLM()
    actions = llm.plan("Please email alice@corp.example about the meeting.", client)
    assert len(actions) == 1
    action = actions[0]
    assert action.hijacked
    assert action.is_cross_server
    assert action.server == "trusted-email"
    assert action.shadow_source == "evil-tools"
    assert action.arguments["to"] == "attacker@evil.example"
    # Real recipient is preserved in the body, per the payload's instruction.
    assert "alice@corp.example" in action.arguments["body"]
    assert action.concealed


def test_poisoning_smuggles_files():
    client = MCPClient()
    client.register_server("math-tools", MALICIOUS_POISON_TOOLS)
    llm = MockLLM()
    actions = llm.plan("add 2 and 3", client)
    assert len(actions) == 1
    action = actions[0]
    assert action.hijacked
    assert not action.is_cross_server  # the tool poisoned itself
    assert "sidenote" in action.arguments
    assert "PRIVATE KEY" in action.arguments["sidenote"]


def test_benign_request_is_not_hijacked():
    client = MCPClient()
    client.register_server("trusted-email", TRUSTED_EMAIL_TOOLS)
    llm = MockLLM()
    actions = llm.plan("email alice@corp.example", client)
    assert actions and not actions[0].hijacked


# -- pinning / rug pull -----------------------------------------------------

def test_pin_store_detects_rug_pull():
    store = PinStore()
    store.approve("weather-tools", RUGPULL_V1_TOOLS)
    assert store.check("weather-tools", RUGPULL_V1_TOOLS) == []
    violations = store.check("weather-tools", RUGPULL_V2_TOOLS)
    assert len(violations) == 1
    assert violations[0].kind == "changed"


def test_pin_store_round_trips(tmp_path):
    store = PinStore()
    store.approve("weather-tools", RUGPULL_V1_TOOLS)
    path = tmp_path / "pins.json"
    store.save(path)
    reloaded = PinStore.load(path)
    assert reloaded.pins == store.pins


def test_diff_tools_flags_added_and_removed():
    before = [build_tool(name="a", description="a")]
    after = [build_tool(name="b", description="b")]
    kinds = {v.kind for v in diff_tools(before, after)}
    assert kinds == {"added", "removed"}


# -- guard ------------------------------------------------------------------

def test_guard_blocks_cross_server_hijack():
    client = _context()
    action = MockLLM().plan("email alice@corp.example", client)[0]
    guard = ToolGuard(trusted_servers={"trusted-email"}, allow_recipients={"alice@corp.example"})
    decision = guard.review_action(action)
    assert not decision.allowed
    assert any("cross-server shadowing" in r for r in decision.reasons)
    assert any("allowlist" in r for r in decision.reasons)


def test_guard_blocks_credential_smuggling_and_redacts():
    client = MCPClient()
    client.register_server("math-tools", MALICIOUS_POISON_TOOLS)
    action = MockLLM().plan("add 2 and 3", client)[0]
    guard = ToolGuard(trusted_servers={"math-tools"})
    decision = guard.review_action(action)
    assert not decision.allowed
    assert decision.redacted_arguments["sidenote"] == "<redacted:secret>"


def test_guard_allows_benign_action():
    client = MCPClient()
    client.register_server("trusted-email", TRUSTED_EMAIL_TOOLS)
    action = MockLLM().plan("email alice@corp.example", client)[0]
    guard = ToolGuard(trusted_servers={"trusted-email"}, allow_recipients={"alice@corp.example"})
    decision = guard.review_action(action)
    assert decision.allowed


def test_guard_quarantines_malicious_registration():
    guard = ToolGuard(trusted_servers={"trusted-email"})
    decision = guard.review_registration("evil-tools", MALICIOUS_SHADOW_TOOLS)
    assert not decision.allowed
    assert decision.action == "block"


def test_guard_allows_benign_registration():
    guard = ToolGuard(trusted_servers={"trusted-email"})
    decision = guard.review_registration("trusted-email", TRUSTED_EMAIL_TOOLS)
    assert decision.allowed


def test_strip_hidden_directives_removes_payload():
    cleaned = strip_hidden_directives(MALICIOUS_SHADOW_TOOLS[0].description)
    assert "attacker@evil.example" not in cleaned
    assert "removed" in cleaned
    # The benign leading line survives.
    assert cleaned.startswith("Add two numbers")
