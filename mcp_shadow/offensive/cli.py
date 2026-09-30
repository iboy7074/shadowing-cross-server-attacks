"""Command-line interface for the offensive toolkit.

    python -m mcp_shadow.offensive payloads
    python -m mcp_shadow.offensive campaign --encoding none,zero_width,base64
    python -m mcp_shadow.offensive matrix
    python -m mcp_shadow.offensive report --out report.md --format markdown
    python -m mcp_shadow.offensive generate shadow-email --out evil_server.py

Every command requires ``--authorized-by`` (or defaults to the local lab), which
is recorded in the output. There is no way to run a campaign without an
authorization record.
"""

from __future__ import annotations

import argparse
import sys

from .campaign import Campaign
from .encoders import ENCODERS
from .payloads import PayloadCatalog, Technique
from .authorization import AuthorizationError, RulesOfEngagement
from .report import Report
from .server_gen import write as write_server


def _roe(args: argparse.Namespace) -> RulesOfEngagement:
    """Build the engagement from CLI args. Local lab unless remote is granted."""
    if getattr(args, "allow_remote", False):
        raise AuthorizationError(
            "remote engagements are not enabled in this build; use the Python "
            "API with an explicit Scope(allowed_hosts=..., allow_remote=True) "
            "after documenting written permission"
        )
    return RulesOfEngagement.for_local_lab(
        authorizer=args.authorized_by,
        engagement_id=args.engagement_id,
        notes="created via CLI",
    )


def _catalog() -> PayloadCatalog:
    return PayloadCatalog()


def cmd_payloads(args: argparse.Namespace) -> int:
    catalog = _catalog()
    print(f"{'id':<24} {'technique':<24} tool")
    print("-" * 70)
    for payload in catalog.payloads:
        print(f"{payload.id:<24} {payload.technique.value:<24} {payload.tool_name}")
        print(f"    {payload.summary}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    catalog = _catalog()
    payload = catalog.by_id(args.payload)
    path = write_server(payload, args.out)
    print(f"wrote inert red-team server for '{payload.id}' -> {path}")
    print("run it with: python", path)
    return 0


def _run_campaign(args: argparse.Namespace):
    roe = _roe(args)
    techniques = [Technique(t) for t in args.technique] if args.technique else None
    encodings = args.encoding or ["none"]
    campaign = Campaign(roe)
    return campaign.run(payload_ids=args.payload or None, techniques=techniques, encodings=encodings)


def cmd_campaign(args: argparse.Namespace) -> int:
    result = _run_campaign(args)
    print(Report(result).to_markdown())
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    result = _run_campaign(args)
    print(f"{'payload':<24} {'technique':<22} {'enc':<14} {'hijack':<7} "
          f"{'exfil':<6} {'det':<5} {'bypass':<7} severity")
    print("-" * 100)
    for row in result.results:
        print(
            f"{row.payload_id:<24} {row.technique:<22} {row.encoding:<14} "
            f"{str(row.hijacked):<7} {str(row.exfiltrated):<6} "
            f"{str(row.detected_raw):<5} {str(row.bypassed):<7} {row.severity}"
        )
    print("-" * 100)
    print(
        f"hijacks {result.hijacks}/{result.total}  "
        f"bypasses {result.bypasses}/{result.total}  "
        f"detection {result.detection_rate:.0%}"
    )
    return 0


def cmd_defenses(args: argparse.Namespace) -> int:
    from ..defense.evaluation import evaluate_defenses

    techniques = [Technique(t) for t in args.technique] if args.technique else None
    encodings = args.encoding or ["none"]
    report = evaluate_defenses(techniques=techniques, encodings=encodings)

    def cell(value: bool | None) -> str:
        return "n/a" if value is None else str(value)

    print(f"{'technique':<24} {'encoding':<14} {'scanner':<8} {'norm':<6} "
          f"{'runtime':<8} {'sev':<8} verdict")
    print("-" * 84)
    for row in report.rows:
        verdict = "blocked" if row.defeated_stock else "UNCOVERED"
        print(
            f"{row.technique:<24} {row.encoding:<14} "
            f"{cell(row.registration_raw):<8} {cell(row.registration_normalized):<6} "
            f"{cell(row.runtime):<8} {row.severity:<8} {verdict}"
        )
    print("-" * 84)
    print(f"metadata-visible payloads: {len(report.metadata_rows)}")
    print(f"  scanner alone          : {report.scanner_only_rate:.0%}")
    print(f"  scanner + normalization: {report.scanner_normalized_rate:.0%}")
    print(f"  runtime taint tracking : {report.runtime_rate:.0%}")
    print(f"  guard as shipped (meta) : {report.defeated_stock_rate:.0%}")
    print(f"  residual (unstopped)   : {len(report.residual)}")
    print()
    print("false-positive controls (must all be allowed):")
    for name, allowed in report.controls.items():
        print(f"  {'ok  ' if allowed else 'FAIL'} {name}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    result = _run_campaign(args)
    report = Report(result)
    body = report.to_json() if args.format == "json" else report.to_markdown()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(body)
        print(f"wrote {args.format} report -> {args.out}")
    else:
        print(body)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp_shadow.offensive",
        description="Offensive MCP shadowing / cross-server attack toolkit "
        "(authorized testing only).",
    )
    parser.add_argument(
        "--authorized-by",
        default="local-lab",
        help="name of the authorizer for this engagement (recorded in output)",
    )
    parser.add_argument("--engagement-id", default="local-lab")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="attempt a remote engagement (refused in this build; use the API)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("payloads", help="list the payload catalog").set_defaults(func=cmd_payloads)

    gen = sub.add_parser("generate", help="write a runnable inert malicious server")
    gen.add_argument("payload", help="payload id (see 'payloads')")
    gen.add_argument("--out", required=True, help="output .py path")
    gen.set_defaults(func=cmd_generate)

    def add_run_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--payload", action="append", help="payload id (repeatable)")
        p.add_argument(
            "--technique",
            action="append",
            choices=[t.value for t in Technique],
            help="technique (repeatable)",
        )
        p.add_argument(
            "--encoding",
            action="append",
            choices=sorted(ENCODERS),
            help="encoder (repeatable); default 'none'",
        )

    campaign = sub.add_parser("campaign", help="run a campaign and print the report")
    add_run_args(campaign)
    campaign.set_defaults(func=cmd_campaign)

    matrix = sub.add_parser("matrix", help="run a campaign and print the attack matrix")
    add_run_args(matrix)
    matrix.set_defaults(func=cmd_matrix)

    report = sub.add_parser("report", help="run a campaign and emit a report file")
    add_run_args(report)
    report.add_argument("--out", help="output path (default stdout)")
    report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    report.set_defaults(func=cmd_report)

    defenses = sub.add_parser(
        "defenses",
        help="measure the shipped guard against the catalog (scanner vs runtime)",
    )
    defenses.add_argument(
        "--technique",
        action="append",
        choices=[t.value for t in Technique],
        help="technique (repeatable)",
    )
    defenses.add_argument(
        "--encoding",
        action="append",
        choices=sorted(ENCODERS),
        help="encoder (repeatable); default 'none'",
    )
    defenses.set_defaults(func=cmd_defenses)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AuthorizationError as exc:
        print(f"authorization error: {exc}", file=sys.stderr)
        return 2
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
