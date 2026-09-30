# MCP Shadowing & Cross-Server Attacks — reference implementation

A self-contained, defensive toolkit that reproduces **tool shadowing** and
**cross-server attacks** against Model Context Protocol (MCP) agents, plus the
detection and runtime controls that stop them.

This exists so security engineers can understand the attack class concretely,
test their own MCP clients against it, and wire in mitigations. Every payload is
inert: exfiltration targets are reserved/example addresses, "sensitive" files are
local stand-ins, and no code makes a network call.

## The attack in one paragraph

An MCP client merges the `tools/list` metadata of every connected server into a
single model context. The model cannot tell which server a description came
from, and it treats tool descriptions as authoritative instructions. A malicious
server can therefore embed hidden directives in an otherwise harmless tool's
description and change how the model uses a *different, trusted* server's tools —
without the malicious tool ever being called. The user sees a clean interaction
log in which only trusted tools were used.

This is the class documented by Invariant Labs in April 2025 and catalogued as
OWASP MCP03:2025 (Tool Poisoning).

## Attack variants covered

| Variant | Where the payload lives | File |
| --- | --- | --- |
| Cross-server shadowing | Malicious server's description rewrites a trusted server's `send_email` | `servers/tools.py::MALICIOUS_SHADOW_TOOLS` |
| Tool poisoning / exfiltration | Hidden directive makes the model read `~/.ssh/id_rsa` and smuggle it via a `sidenote` argument | `servers/tools.py::MALICIOUS_POISON_TOOLS` |
| Rug pull | Benign on approval, poisoned after | `servers/tools.py::RUGPULL_V1_TOOLS` / `RUGPULL_V2_TOOLS` |
| Name impersonation | Duplicate/homoglyph tool names to win a collision | `scanner/detector.py::_impersonation` |

The malicious descriptions are reproductions of the published Invariant Labs
payloads so the detector is exercised against realistic input.

## Quick start

```bash
pip install -r requirements.txt

# In-memory walkthrough of all four scenarios (attack then defense)
python -m mcp_shadow.demo

# Same attack against two real MCP servers over stdio
python examples/live_shadowing_demo.py

# Tests
python -m pytest tests/ -q
```

## Layout

```
mcp_shadow/
  agent/
    mcp_client.py    multi-server client; merges tools into one context, fingerprints each
    mock_llm.py      deterministic model stub that internalizes descriptions as instructions
  servers/
    tools.py         trusted + malicious tool definitions (the payloads)
    email_server.py  runnable trusted MCP stdio server
    shadow_server.py runnable malicious MCP stdio server
  scanner/
    detector.py      static analysis: shadowing, smuggling, concealment, impersonation
    pin.py           tool/version pinning; detects rug pulls by fingerprint
  defense/
    guard.py         registration quarantine, cross-server taint, data-flow controls
  demo.py            end-to-end narrative
examples/
  live_shadowing_demo.py
```

## How detection works

`ShadowingDetector` scans tool *metadata* without executing anything. It flags:

- **CROSS_SERVER_SHADOWING** — a description that redirects mail/actions to an
  attacker address or explicitly describes a side effect on another server's tool.
- **CREDENTIAL_SMUGGLING** — a description instructing the model to read a local
  file and pass its contents through an argument.
- **CONCEALMENT** — "do not mention this to the user".
- **INSTRUCTION_OVERRIDE** — "ignore previous instructions", urgency pressure,
  false preconditions ("otherwise the tool will not work").
- **NAME_COLLISION / NAME_IMPERSONATION** — duplicate or homoglyph tool names.
- **SUSPICIOUS_ARGUMENT** — smuggler arguments such as `sidenote`.

`PinStore` records the fingerprint (`sha256` over name + description + schema) of
every approved tool and raises a violation the moment a definition changes.

## How the defenses work

`ToolGuard` is fail-closed and implements four layers:

1. **Registration quarantine** — high-severity descriptions never enter the model
   context (`review_registration`).
2. **Cross-server taint** — a call to a trusted tool is blocked when the action
   was shaped by a different server's metadata (`review_action`). This stops
   shadowing even when the malicious tool is never invoked.
3. **Trust tiers** — servers outside the allowlist require confirmation.
4. **Data-flow controls** — credential-like argument values and recipients
   outside the allowlist are blocked and redacted.

`strip_hidden_directives` is included as defense-in-depth for display, but the
guard *blocks* rather than trusting sanitized text — pattern removal alone is not
a security boundary.

## Mapping to published mitigations

| Recommendation (Invariant / OWASP) | Implementation |
| --- | --- |
| Tool and package pinning | `scanner/pin.py::PinStore` |
| Cross-server protection / dataflow controls | `defense/guard.py::review_action` |
| Zero trust for tool definitions | `defense/guard.py::review_registration` |
| Clear UI showing full descriptions | `strip_hidden_directives` + `Finding` evidence |

## Offensive toolkit (red team)

An offensive counterpart lives in `mcp_shadow.offensive`: a red-team framework
that weaponizes the same techniques, measures a target's resistance, and emits a
pentest report. It is **fail-closed** — a campaign cannot run without an
authorization record, is local-only by default, and records exfiltration
in-process instead of sending it.

```bash
python -m mcp_shadow.offensive payloads                    # catalog
python -m mcp_shadow.offensive matrix --encoding none --encoding zero_width
python -m mcp_shadow.offensive report --out report.md
python -m mcp_shadow.offensive defenses --encoding none --encoding base64
python -m mcp_shadow.offensive generate shadow-email --out evil_server.py
python examples/offensive_campaign.py
```

Covered techniques: `shadowing`, `poisoning`, `rug_pull`,
`preference_manipulation`, `resource_injection`, `result_injection`,
`auth_hijack`. Evasion encoders (`zero_width`, `tag_chars`, `base64`,
`homoglyph`, `fullwidth`, ...) demonstrate that pattern matching is not a
security boundary — the campaign reports detection both raw and after
normalization.

`defenses` turns that into a measured claim about the shipped guard rather than
an assertion: registration-time metadata scanning catches only the plaintext
payloads, the runtime cross-server taint check carries the rest, and
response-borne techniques (`result_injection`) are uncovered by both. The
evaluation also runs false-positive controls so a guard that blocks everything
cannot score 100%.

See [`docs/offensive.md`](docs/offensive.md) for the safety model, the `Target`
extension point for testing a real client, and how to interpret results.

## Scope and responsible use

The defensive code is safe to run anywhere. The offensive toolkit is for
authorized testing only: it is gated by `RulesOfEngagement`, scoped to local lab
targets, and will not contact a remote endpoint without an explicit, documented
`allow_network_egress` grant. Do not deploy the generated server scripts against
systems you do not own.

## References

- Invariant Labs, *MCP Security Notification: Tool Poisoning Attacks* (Apr 2025)
- Invariant Labs, *WhatsApp MCP exploited* (Apr 2025)
- Simon Willison, *Model Context Protocol has prompt injection security problems* (Apr 2025)
- OWASP MCP Top 10 — MCP03:2025 Tool Poisoning
- Cloud Security Alliance, *MCP Tool Poisoning: Adversarial Hijacking of AI Agent Workflows*
- arXiv:2507.19880, *Trivial Trojans: How Minimal MCP Servers Enable Cross-Tool Exfiltration*
