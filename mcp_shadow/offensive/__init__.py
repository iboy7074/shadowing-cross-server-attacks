"""Offensive security toolkit for MCP shadowing / cross-server attacks.

This is a red-team framework for testing MCP clients and agents that you are
authorized to test. It is the offensive counterpart to the detector and guard in
``mcp_shadow.scanner`` and ``mcp_shadow.defense``.

Guardrails (enforced, not advisory):

* :class:`~mcp_shadow.offensive.authorization.RulesOfEngagement` is fail-closed.
  A campaign cannot start without an authorization record that names a scope and
  an authorizer.
* All exfiltration targets default to ``*.example`` reserved addresses and all
  collection is done by a **local** sink. The framework is local-only by default
  and will not send data to a remote endpoint unless a target is explicitly and
  legally in scope.
* Targets are adapters. The default target is a local, in-process model stub, so
  a full campaign runs offline.

Use only against systems you own or have written permission to test.
"""

from .authorization import AuthorizationError, RulesOfEngagement, Scope
from .payloads import Payload, PayloadCatalog, Technique
from .targets import HardenedTarget, LocalMockTarget, MetadataBlindTarget, Target
from .campaign import Campaign, CampaignResult, TechniqueResult
from .report import Report
from .sink import LocalSink
from .encoders import ENCODERS, decode_payload, strip_invisibles
from .victim_env import build_victim_environment

__all__ = [
    "AuthorizationError",
    "RulesOfEngagement",
    "Scope",
    "Payload",
    "PayloadCatalog",
    "Technique",
    "Target",
    "LocalMockTarget",
    "MetadataBlindTarget",
    "HardenedTarget",
    "Campaign",
    "CampaignResult",
    "TechniqueResult",
    "Report",
    "LocalSink",
    "ENCODERS",
    "decode_payload",
    "strip_invisibles",
    "build_victim_environment",
]
