"""Run a full offensive campaign against the local lab and print the report.

    python examples/offensive_campaign.py

Local-only: the engagement is authorized for the built-in lab targets and
network egress is disabled. Exfiltration is recorded in-process.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_shadow.offensive import (  # noqa: E402
    Campaign,
    HardenedTarget,
    LocalSink,
    LocalMockTarget,
    MetadataBlindTarget,
    Report,
    RulesOfEngagement,
)


def main() -> None:
    roe = RulesOfEngagement.for_local_lab("red-team-demo")
    campaign = Campaign(roe)

    encodings = ["none", "zero_width", "base64", "tag_chars", "homoglyph"]
    sink = LocalSink(roe=roe)
    targets = [LocalMockTarget(sink), MetadataBlindTarget(sink), HardenedTarget(sink)]

    result = campaign.run(encodings=encodings, targets=targets)
    print(Report(result).to_markdown())

    print("\nTarget comparison (hijack rate per target):")
    for target in targets:
        rows = [r for r in result.results if r.target == target.name]
        hijacks = sum(1 for r in rows if r.hijacked)
        print(f"  {target.name:<16} {hijacks}/{len(rows)} hijacked")


if __name__ == "__main__":
    main()
