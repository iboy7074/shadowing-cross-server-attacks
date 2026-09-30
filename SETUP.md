# Setup

Two parts: a **defensive** reference implementation and an **offensive**
(red-team) toolkit. Both are pure Python and share one dependency set.

## Requirements

- Python **3.10+** (developed on 3.13)
- pip
- Node.js is *not* required

## 1. Unzip

```bash
unzip shadowing-cross-server-attacks.zip
cd shadowing-cross-server-attacks
```

## 2. Create a virtual environment and install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` installs `mcp>=2.0` and `pytest>=8.0`.

Optional, to install the package itself (adds the `mcp-shadow` console script):

```bash
pip install -e .
```

## 3. Verify

```bash
python -m pytest tests/ -q         # expect: 45 passed
```

## 4. Run the demos

```bash
# Defensive: in-memory attack + defense walkthrough
python -m mcp_shadow.demo

# Defensive: the same attack over a real MCP stdio server
python examples/live_shadowing_demo.py

# Offensive: full red-team campaign and report
python examples/offensive_campaign.py
```

## 5. Use the offensive CLI

```bash
python -m mcp_shadow.offensive payloads
python -m mcp_shadow.offensive matrix --encoding none --encoding zero_width --encoding base64
python -m mcp_shadow.offensive report --out report.md --format markdown
python -m mcp_shadow.offensive defenses --encoding none --encoding base64
python -m mcp_shadow.offensive generate shadow-email --out evil_server.py
python evil_server.py              # serves the poisoned tool over stdio
```

`defenses` measures the shipped guard against the payload catalog and reports
coverage per control point (registration-time metadata scan vs. runtime
cross-server taint check), plus false-positive controls. The headline result:
encoding blinds the metadata scanner, and the runtime taint check is what
carries coverage.

The offensive toolkit is fail-closed: campaigns require an authorization record
and are local-only by default. See `docs/offensive.md`.

## Troubleshooting

- **`No module named mcp`** — the virtualenv isn't active, or step 2 didn't run.
- **`ModuleNotFoundError: mcp_shadow`** — run commands from the repo root, or
  `pip install -e .`.
- **`python -m mcp_shadow.offensive` prints an authorization error** — that is
  expected fail-closed behavior; pass `--authorized-by "your name"` or use the
  Python API with `RulesOfEngagement.for_local_lab(...)`.

## Safety

The defensive code is safe to run anywhere. The offensive toolkit is for
authorized testing only — local lab targets, no network egress unless
explicitly granted.
