"""Tests for defense evaluation: the guard measured against the payload catalog.

These assert the *finding*, not just that the code runs: the metadata scanner
alone is not sufficient, and the runtime taint check is what carries coverage.
"""

from __future__ import annotations

import json

import pytest

from mcp_shadow.defense import DefenseEvaluator, evaluate_defenses
from mcp_shadow.offensive import Report, Technique
from mcp_shadow.offensive.campaign import Campaign
from mcp_shadow.offensive.authorization import RulesOfEngagement

ENCODINGS = ["none", "zero_width", "base64", "homoglyph", "fullwidth", "tag_chars"]


def test_scanner_alone_is_insufficient():
    report = evaluate_defenses(encodings=ENCODINGS)
    # Most of the catalog evades a raw metadata scan.
    assert report.scanner_only_rate < 0.5


def test_normalization_improves_scanner_coverage():
    report = evaluate_defenses(encodings=ENCODINGS)
    assert report.scanner_normalized_rate > report.scanner_only_rate


def test_runtime_taint_check_carries_coverage():
    report = evaluate_defenses(encodings=ENCODINGS)
    assert report.runtime_rate == 1.0


def test_guard_stops_all_metadata_visible_payloads():
    report = evaluate_defenses(encodings=ENCODINGS)
    assert report.defeated_stock_rate == 1.0
    assert [r for r in report.residual if r.metadata_visible] == []


def test_response_borne_technique_is_uncovered():
    """Result injection is not a metadata or argument attack, so no shipped
    control sees it; it must be reported as residual, not silently passed."""
    report = evaluate_defenses(encodings=["none"])
    residual = report.residual
    assert [r.technique for r in residual] == [Technique.RESULT_INJECTION.value]
    assert residual[0].uncovered_by_design
    assert residual[0].severity == "CRITICAL"


def test_no_false_positives():
    """A guard that blocks everything would score 100%; it must not."""
    report = evaluate_defenses(encodings=ENCODINGS)
    assert report.controls
    assert report.controls_pass


def test_encoding_defeats_metadata_scanner_but_not_runtime():
    """The headline finding: base64/zero-width hides a shadowing directive from
    the metadata scanner, yet the runtime taint check still stops the call."""
    report = evaluate_defenses(
        techniques=[Technique.SHADOWING], encodings=["base64", "zero_width"]
    )
    for row in report.rows:
        assert row.metadata_visible is True
        assert row.registration_raw is False  # scanner blinded by encoding
        assert row.runtime is True            # runtime taint check still fires
        assert row.defeated_stock is True


def test_plaintext_shadowing_is_caught_by_scanner():
    report = evaluate_defenses(techniques=[Technique.SHADOWING], encodings=["none"])
    row = report.rows[0]
    assert row.registration_raw is True
    assert row.runtime is True


def test_result_injection_scan_not_applicable():
    """Result injection never appears in metadata, so the scan is N/A, not a
    failure - and the technique is flagged CRITICAL because metadata scanning
    cannot see it by construction."""
    report = evaluate_defenses(
        techniques=[Technique.RESULT_INJECTION], encodings=["none"]
    )
    row = report.rows[0]
    assert row.metadata_visible is False
    assert row.registration_raw is None
    assert row.registration_normalized is None
    assert row.severity == "CRITICAL"


def test_unknown_encoder_raises():
    with pytest.raises(KeyError):
        evaluate_defenses(encodings=["not-a-real-encoder"])


def test_evaluator_accepts_explicit_guard():
    from mcp_shadow.defense.guard import ToolGuard

    evaluator = DefenseEvaluator(guard=ToolGuard(trusted_servers={"trusted-email"}))
    report = evaluator.evaluate(techniques=[Technique.SHADOWING], encodings=["none"])
    assert report.rows[0].runtime is True


def test_report_embeds_defense_coverage():
    result = Campaign(RulesOfEngagement.for_local_lab("unit-test")).run(
        payload_ids=["shadow-email"], encodings=["base64"]
    )
    report = Report(result)
    assert "Defense coverage" in report.to_markdown()
    data = json.loads(report.to_json())
    assert data["defense_coverage"]["runtime"] == 1.0
    assert all(data["defense_coverage"]["false_positive_controls"].values())
