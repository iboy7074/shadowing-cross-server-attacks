"""Tests for the offensive toolkit: authorization, encoders, campaign, report."""

from __future__ import annotations

import json

import pytest

from mcp_shadow.offensive import (
    ENCODERS,
    AuthorizationError,
    Campaign,
    HardenedTarget,
    LocalMockTarget,
    LocalSink,
    MetadataBlindTarget,
    PayloadCatalog,
    Report,
    RulesOfEngagement,
    Scope,
    Technique,
    decode_payload,
    strip_invisibles,
)
from mcp_shadow.offensive import server_gen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement.for_local_lab("unit-test")


# -- authorization (fail-closed) -------------------------------------------

def test_campaign_refuses_without_authorization():
    ungranted = RulesOfEngagement(authorizer="")  # not granted
    with pytest.raises(AuthorizationError):
        Campaign(ungranted)


def test_grant_requires_named_authorizer():
    with pytest.raises(AuthorizationError):
        RulesOfEngagement(authorizer="  ").grant()


def test_scope_blocks_remote_by_default():
    scope = Scope()
    assert scope.permits_host("evil.example")          # reserved, inert
    assert not scope.permits_host("attacker.com")      # real third party
    assert scope.permits_host("localhost")


def test_scope_allows_listed_remote_when_enabled():
    scope = Scope(allowed_hosts={"lab.internal"}, allow_remote=True)
    assert scope.permits_host("lab.internal")
    assert not scope.permits_host("other.internal")


def test_roe_expiry_is_enforced():
    from datetime import datetime, timedelta, timezone

    roe = RulesOfEngagement(
        authorizer="x",
        not_after=datetime.now(timezone.utc) - timedelta(days=1),
    ).grant()
    with pytest.raises(AuthorizationError):
        roe.validate()


def test_authorize_target_rejects_out_of_scope_server():
    roe = RulesOfEngagement(
        authorizer="x", scope=Scope(allowed_servers={"trusted-email"})
    ).grant()
    roe.authorize_target("trusted-email")
    with pytest.raises(AuthorizationError):
        roe.authorize_target("other-server")


# -- encoders ---------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_every_encoder_round_trips_through_decode(name):
    payload = PayloadCatalog().by_id("shadow-email").with_encoding(name)
    recovered = decode_payload(payload.render_description())
    assert "send all emails" in recovered.lower()


def test_zero_width_hides_literal_from_naive_search():
    payload = PayloadCatalog().by_id("shadow-email").with_encoding("zero_width")
    assert "send all emails" not in payload.render_description().lower()


def test_strip_invisibles_removes_zero_width():
    assert "\u200b" not in strip_invisibles("a\u200bb")


def test_tag_chars_decode_to_ascii():
    payload = PayloadCatalog().by_id("shadow-email").with_encoding("tag_chars")
    assert "send all emails" in decode_payload(payload.render_description()).lower()


# -- campaign ---------------------------------------------------------------

def test_payload_catalog_covers_every_technique():
    catalog = PayloadCatalog()
    covered = {p.technique for p in catalog.payloads}
    assert covered == set(Technique)


def test_campaign_hijacks_and_exfiltrates_against_naive_target():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["shadow-email"], encodings=["none"])
    item = result.results[0]
    assert item.hijacked
    assert item.exfiltrated
    assert item.concealed
    assert result.hijacks == 1


def test_encoding_bypasses_raw_detector_but_not_normalized():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["shadow-email"], encodings=["zero_width"])
    item = result.results[0]
    assert item.hijacked
    assert not item.detected_raw          # the bypass
    assert item.detected_normalized       # normalization recovers detection
    assert item.severity == "CRITICAL"


def test_hardened_target_resists_metadata_payloads():
    sink = LocalSink(roe=_roe())
    campaign = Campaign(_roe())
    result = campaign.run(
        payload_ids=["shadow-email"], encodings=["none"], targets=[HardenedTarget(sink)]
    )
    assert not result.results[0].hijacked


def test_metadata_blind_target_ignores_encoded_payload():
    sink = LocalSink(roe=_roe())
    campaign = Campaign(_roe())
    result = campaign.run(
        payload_ids=["shadow-email"],
        encodings=["zero_width"],
        targets=[MetadataBlindTarget(sink)],
    )
    assert not result.results[0].hijacked


def test_result_injection_is_undetectable_by_metadata_scan():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["result-inject"], encodings=["none"])
    item = result.results[0]
    assert item.hijacked
    assert not item.detected_raw
    assert not item.detected_normalized


def test_auth_hijack_relays_credential():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["auth-hijack"], encodings=["none"])
    item = result.results[0]
    assert item.hijacked and item.exfiltrated
    assert any("vault-token" in e.data for e in item.events)


def test_full_campaign_aggregates():
    campaign = Campaign(_roe())
    result = campaign.run(encodings=["none", "zero_width"])
    assert result.total == len(PayloadCatalog().payloads) * 2
    assert result.success_rate > 0
    assert "zero_width" in result.by_encoding()


# -- sink -------------------------------------------------------------------

def test_sink_blocks_egress_by_default_and_records_attempt():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["result-inject"], encodings=["none"])
    events = result.results[0].events
    assert events
    assert all(e.egress_blocked for e in events)  # nothing left the process


# -- server generation ------------------------------------------------------

def test_generated_server_is_valid_python(tmp_path):
    payload = PayloadCatalog().by_id("shadow-email")
    path = server_gen.write(payload, tmp_path / "evil.py")
    source = path.read_text()
    compile(source, str(path), "exec")           # must be syntactically valid
    assert "MCPServer" in source
    assert "attacker@evil.example" in source


# -- report -----------------------------------------------------------------

def test_report_markdown_and_json():
    campaign = Campaign(_roe())
    result = campaign.run(payload_ids=["shadow-email"], encodings=["zero_width"])
    report = Report(result)
    markdown = report.to_markdown()
    assert "Executive summary" in markdown
    assert "Attack matrix" in markdown
    data = json.loads(report.to_json())
    assert data["summary"]["total"] == 1
    assert data["results"][0]["payload"] == "shadow-email"
