"""Campaign orchestration and success scoring.

A campaign wires the pieces together for a scoped engagement:

1. Validate the :class:`RulesOfEngagement` (fail-closed).
2. Build the victim session and inject a payload's malicious server into it.
3. Run the chosen target against a matching user request.
4. Score whether the payload *worked* (hijack / exfil / concealment) and whether
   the defensive detector would have caught it - raw and after normalization.

The delta between "worked" and "detected" is the finding: an undocumented bypass
in the client under test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product

from mcp import types

from ..agent.mcp_client import MCPClient, RegisteredTool
from ..scanner.detector import ShadowingDetector, has_high_severity
from .authorization import RulesOfEngagement
from .encoders import ENCODERS, decode_payload
from .payloads import Payload, PayloadCatalog, Technique
from .sink import ExfilEvent, LocalSink
from .targets import (
    HardenedTarget,
    LocalMockTarget,
    MetadataBlindTarget,
    Target,
    TargetOutcome,
)
from .victim_env import REQUESTS, build_victim_environment

#: Which user request pairs with each technique.
_REQUEST_FOR_TECHNIQUE: dict[Technique, str] = {
    Technique.SHADOWING: REQUESTS["email"],
    Technique.POISONING: REQUESTS["add"],
    Technique.RUG_PULL: REQUESTS["fact"],
    Technique.PREFERENCE_MANIPULATION: REQUESTS["email"],
    Technique.RESOURCE_INJECTION: REQUESTS["fact"],
    Technique.RESULT_INJECTION: REQUESTS["weather"],
    Technique.AUTH_HIJACK: REQUESTS["token"],
}


@dataclass
class TechniqueResult:
    payload_id: str
    technique: str
    target: str
    encoding: str
    hijacked: bool
    exfiltrated: bool
    concealed: bool
    detected_raw: bool
    detected_normalized: bool
    actions: list[dict] = field(default_factory=list)
    events: list[ExfilEvent] = field(default_factory=list)
    #: The user request that paired with this payload (needed to replay actions
    #: through the runtime guard).
    request: str = ""

    @property
    def bypassed(self) -> bool:
        """Payload worked but the raw detector missed it."""
        return self.hijacked and not self.detected_raw

    @property
    def severity(self) -> str:
        if self.hijacked and self.exfiltrated and self.bypassed:
            return "CRITICAL"
        if self.hijacked and self.bypassed:
            return "HIGH"
        if self.hijacked:
            return "MEDIUM"
        return "INFO"

    def to_row(self) -> dict:
        return {
            "payload": self.payload_id,
            "technique": self.technique,
            "target": self.target,
            "encoding": self.encoding,
            "hijacked": self.hijacked,
            "exfiltrated": self.exfiltrated,
            "concealed": self.concealed,
            "detected_raw": self.detected_raw,
            "detected_normalized": self.detected_normalized,
            "bypassed": self.bypassed,
            "severity": self.severity,
        }


@dataclass
class CampaignResult:
    engagement_id: str
    authorizer: str
    results: list[TechniqueResult] = field(default_factory=list)
    sink: LocalSink | None = None

    # -- aggregate metrics ---------------------------------------------------

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def hijacks(self) -> int:
        return sum(1 for r in self.results if r.hijacked)

    @property
    def exfiltrations(self) -> int:
        return sum(1 for r in self.results if r.exfiltrated)

    @property
    def bypasses(self) -> int:
        return sum(1 for r in self.results if r.bypassed)

    @property
    def success_rate(self) -> float:
        return self.hijacks / self.total if self.total else 0.0

    @property
    def bypass_rate(self) -> float:
        return self.bypasses / self.total if self.total else 0.0

    @property
    def detection_rate(self) -> float:
        detected = sum(1 for r in self.results if r.detected_raw)
        return detected / self.total if self.total else 0.0

    def worst_findings(self) -> list[TechniqueResult]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
        return sorted(self.results, key=lambda r: order[r.severity])

    def by_encoding(self) -> dict[str, dict[str, int]]:
        table: dict[str, dict[str, int]] = {}
        for r in self.results:
            bucket = table.setdefault(r.encoding, {"total": 0, "hijacked": 0, "bypassed": 0})
            bucket["total"] += 1
            bucket["hijacked"] += int(r.hijacked)
            bucket["bypassed"] += int(r.bypassed)
        return table


class Campaign:
    """Runs payloads against targets under a validated engagement."""

    def __init__(
        self,
        roe: RulesOfEngagement,
        catalog: PayloadCatalog | None = None,
        detector: ShadowingDetector | None = None,
    ) -> None:
        self.roe = roe
        self.catalog = catalog or PayloadCatalog()
        self.detector = detector or ShadowingDetector()
        # Fail closed before doing anything else.
        self.roe.validate()

    # -- construction helpers ------------------------------------------------

    def _build_client(self, payload: Payload) -> MCPClient:
        """Victim session with the payload's malicious server merged in last.

        Registering the malicious server last means name collisions resolve to
        it, which is how a real client's "last server wins" behaviour is abused.
        """
        client = MCPClient()
        for server, tools in build_victim_environment().items():
            client.register_server(server, tools)
        client.register_server(payload.server, [_payload_to_tool(payload)])
        return client

    def _detected(self, payload: Payload, normalize: bool) -> bool:
        # A payload whose directive lives outside tool metadata (e.g. in a tool
        # response) is invisible to a static metadata scan by construction.
        if not payload.metadata_visible:
            return False
        description = payload.render_description()
        if normalize:
            description = decode_payload(description)
        findings = self.detector.scan_description(
            payload.server, payload.tool_name, description
        )
        return has_high_severity(findings)

    # -- execution -----------------------------------------------------------

    def run(
        self,
        *,
        payload_ids: list[str] | None = None,
        techniques: list[Technique] | None = None,
        encodings: list[str] | None = None,
        targets: list[Target] | None = None,
    ) -> CampaignResult:
        sink = LocalSink(roe=self.roe)
        selected = self._select(payload_ids, techniques)
        encoding_names = encodings or ["none"]
        target_objs = targets or [LocalMockTarget(sink)]

        for name in encoding_names:
            if name not in ENCODERS:
                raise KeyError(f"unknown encoder '{name}'; known: {sorted(ENCODERS)}")

        result = CampaignResult(
            engagement_id=self.roe.engagement_id,
            authorizer=self.roe.authorizer,
            sink=sink,
        )

        for payload, encoding, target in product(selected, encoding_names, target_objs):
            self.roe.authorize_target(payload.server)
            armed = payload.with_encoding(encoding)
            sink.reset()
            outcome, client = self.simulate(armed, target)
            request = _REQUEST_FOR_TECHNIQUE[armed.technique]

            result.results.append(
                TechniqueResult(
                    payload_id=armed.id,
                    technique=armed.technique.value,
                    target=target.name,
                    encoding=encoding,
                    hijacked=outcome.hijacked,
                    exfiltrated=bool(outcome.exfiltrated),
                    concealed=outcome.concealed and outcome.hijacked,
                    detected_raw=self._detected(armed, normalize=False),
                    detected_normalized=self._detected(armed, normalize=True),
                    actions=outcome.actions,
                    events=list(sink.events),
                    request=request,
                )
            )
        return result

    def simulate(
        self, payload: Payload, target: Target
    ) -> tuple[TargetOutcome, MCPClient]:
        """Run one payload against one target, returning the outcome and the
        session that produced it.

        Exposed so defense evaluation can replay the exact actions the target
        took and feed them to the guard's runtime control.
        """
        client = self._build_client(payload)
        request = _REQUEST_FOR_TECHNIQUE[payload.technique]
        outcome = target.run_turn(request, client, payload)
        return outcome, client

    def _select(
        self, payload_ids: list[str] | None, techniques: list[Technique] | None
    ) -> list[Payload]:
        if payload_ids:
            return [self.catalog.by_id(pid) for pid in payload_ids]
        if techniques:
            selected: list[Payload] = []
            for technique in techniques:
                selected.extend(self.catalog.by_technique(technique))
            return selected
        return list(self.catalog.payloads)


def _payload_to_tool(payload: Payload) -> types.Tool:
    schema = {
        "type": "object",
        "properties": payload.arguments,
        "required": [k for k in payload.arguments if k not in {"sidenote", "auth_context"}],
    }
    return types.Tool(
        name=payload.tool_name,
        description=payload.render_description(),
        input_schema=schema,
    )


def default_campaign(roe: RulesOfEngagement | None = None) -> Campaign:
    """Convenience constructor for the built-in local lab."""
    roe = roe or RulesOfEngagement.for_local_lab("local-lab")
    return Campaign(roe)
