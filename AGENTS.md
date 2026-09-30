# AGENTS.md

## Project

Defensive reference implementation of MCP tool shadowing and cross-server
attacks. Python package `mcp_shadow`, plus runnable MCP stdio servers and a
pytest suite.

## Commands

```bash
pip install -r requirements.txt      # mcp>=2.0, pytest
python -m pytest tests/ -q           # 45 tests (defensive + offensive)
python -m mcp_shadow.demo            # in-memory attack + defense walkthrough
python examples/live_shadowing_demo.py  # attack over real MCP stdio

# Offensive (red team) toolkit — fail-closed, local-only
python -m mcp_shadow.offensive payloads
python -m mcp_shadow.offensive matrix --encoding none --encoding zero_width
python -m mcp_shadow.offensive report --out report.md
python -m mcp_shadow.offensive generate shadow-email --out evil_server.py
python examples/offensive_campaign.py
```

## Layout / where things live

- `mcp_shadow/servers/tools.py` — the payloads (verbatim Invariant Labs repros).
  `MALICIOUS_SHADOW_TOOLS` = cross-server shadowing; `MALICIOUS_POISON_TOOLS` =
  credential exfiltration; `RUGPULL_V1/V2_TOOLS` = rug pull.
- `mcp_shadow/agent/mcp_client.py` — merges multi-server `tools/list` into one
  context. `fingerprint_tool()` hashes name+description+schema.
- `mcp_shadow/agent/mock_llm.py` — deterministic model stub. Not an LLM; a state
  machine that models "descriptions are trusted instructions". Keeps tests
  reproducible.
- `mcp_shadow/scanner/detector.py` — static analysis, `Severity`/`Finding`.
- `mcp_shadow/scanner/pin.py` — `PinStore` fingerprints; detects rug pulls.
- `mcp_shadow/defense/guard.py` — `ToolGuard`, fail-closed, 4 layers.
- `mcp_shadow/offensive/` — red-team toolkit. `authorization.py` is the
  fail-closed RoE gate; `payloads.py` the technique catalog; `encoders.py`
  evasion + normalization; `targets.py` victim models; `campaign.py`
  orchestration/scoring; `sink.py` local (non-egress) collection; `report.py`
  markdown/json; `server_gen.py` emits runnable inert servers; `cli.py` entry.
- `docs/offensive.md` — offensive safety model and usage.

## Offensive toolkit invariants (do not weaken)

- `Campaign.__init__` calls `roe.validate()` and must stay fail-closed.
- No code path may contact a remote endpoint unless the engagement has
  `allow_network_egress=True` **and** the URL is in scope. `LocalSink.capture`
  records attempts with `egress_blocked=True` rather than sending.
- Payload exfil targets must stay in the reserved `.example` TLD; victim
  "secrets" must stay obvious fakes.
- `Target.sees_encodings` (can the victim read through an encoding) and
  `Target.resists_injection` (does it refuse metadata instructions) are the two
  axes of the victim model. `LocalMockTarget` = (True, False),
  `MetadataBlindTarget` = (False, False), `HardenedTarget` = (True, True).
- Detector `detected_raw` vs `detected_normalized` is the bypass measurement;
  `result_inject` has `metadata_visible=False` so it is undetectable by design.

## Conventions / gotchas

- **MCP SDK is v2.x.** `mcp.server.fastmcp` no longer exists; use
  `from mcp.server.mcpserver import MCPServer`. `types.Tool` field is
  `input_schema` (wire alias `inputSchema`).
- Tool descriptions are the attack surface. Any change to a payload must be
  reflected in `tests/test_shadowing.py` and the detector patterns.
- Everything must stay inert: exfil targets are `*.example` addresses and
  sandbox file contents are fakes. Never add real network calls.
- `ModeledAction.is_cross_server` distinguishes cross-server shadowing
  (`shadow_source != server`) from self-poisoning (`shadow_source == server`);
  the guard reports them separately.
- New detector rules: add to `_PATTERNS` as `(category, severity, compiled_regex,
  detail)` tuples, then cover with a test.

## Defense evaluation (`mcp_shadow.defense.evaluation`)

- `evaluate_defenses(techniques=None, encodings=None)` replays catalog payloads
  through the shipped `ToolGuard` and reports coverage **per control point**:
  `registration_raw`, `registration_normalized`, `runtime`. Do not collapse
  these into one number — the whole point is that the metadata scanner alone is
  weak (catches plaintext, blind to encodings) while the runtime taint check
  carries coverage.
- Layer fields are tri-state: `None` means "control does not apply" (N/A), not
  "failed". `result_injection` is response-borne, so both the registration scan
  and the runtime action check are `None`; a row is `uncovered_by_design` and
  `severity == "CRITICAL"`. Such rows appear in `residual`; that is intended.
- The evaluator configures `ToolGuard` with trusted session servers and an
  allowlisted recipient. With the fail-closed defaults every call is blocked and
  all coverage numbers become meaningless 100%. Never benchmark against a
  default-constructed guard.
- `false_positive_controls()` must stay all-`True`. A guard that blocks benign
  calls would otherwise report 100% coverage; `test_no_false_positives` pins it.
- `Report` embeds the same coverage via a lazily computed `Report.defense()`;
  the `defenses` CLI subcommand prints the per-payload matrix plus the rates and
  controls. When you change the evaluator, keep all three in sync.
