"""Local exfiltration sink.

A real attacker collects stolen data at a network endpoint. A red-team tool
should not - that turns a test into an actual breach of whoever runs it, and it
leaks real secrets to a third party. So collection here is **in-process**: the
sink records what a payload *would* have exfiltrated and to where, and never
transmits anything.

If an engagement explicitly enables network egress (``allow_network_egress``)
and the sink URL is in scope, the sink will also attempt a real POST - but that
path is off by default and gated by :class:`RulesOfEngagement`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .authorization import RulesOfEngagement


@dataclass
class ExfilEvent:
    server: str
    tool: str
    channel: str  # "argument" | "body" | "resource" | "result"
    destination: str
    data: str
    #: True when the payload named a network endpoint that the engagement
    #: refused to contact. The attempt is still evidence of the finding.
    egress_blocked: bool = False
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def redacted(self, keep: int = 8) -> str:
        if len(self.data) <= keep:
            return "*" * len(self.data)
        return self.data[:keep] + f"...<{len(self.data)} chars>"


@dataclass
class LocalSink:
    """Records exfiltration attempts in-process. Sends nothing by default."""

    roe: RulesOfEngagement
    destination: str = "attacker@evil.example"
    events: list[ExfilEvent] = field(default_factory=list)

    def capture(
        self,
        *,
        server: str,
        tool: str,
        channel: str,
        data: str,
        sink_url: str | None = None,
    ) -> ExfilEvent:
        """Record a piece of data a payload steered into an exfil channel.

        The event is always recorded - the *attempt* is the evidence. Actual
        network egress happens only when the engagement authorizes it and the
        URL is in scope; otherwise the attempt is recorded with
        ``egress_blocked=True`` and nothing leaves the process. Naming a URL in
        a payload is attacker data, not a privileged action, so it does not
        raise; the privileged action (the POST) is what the RoE gates.
        """
        egress_allowed = self._egress_permitted(sink_url)
        event = ExfilEvent(
            server=server,
            tool=tool,
            channel=channel,
            destination=sink_url or self.destination,
            data=data,
            egress_blocked=bool(sink_url) and not egress_allowed,
        )
        self.events.append(event)

        if sink_url and egress_allowed:
            self._post(sink_url, event)
        return event

    def _egress_permitted(self, sink_url: str | None) -> bool:
        if not sink_url:
            return False
        if not self.roe.scope.allow_network_egress:
            return False
        return self.roe.scope.permits_url(sink_url)

    def _post(self, sink_url: str, event: ExfilEvent) -> None:  # pragma: no cover
        """Real egress path. Only reachable when the RoE explicitly allows it."""
        import urllib.request

        import json

        payload = json.dumps(
            {"server": event.server, "tool": event.tool, "data": event.data}
        ).encode()
        request = urllib.request.Request(
            sink_url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()

    # -- reporting -----------------------------------------------------------

    @property
    def count(self) -> int:
        return len(self.events)

    def by_channel(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.channel] = counts.get(event.channel, 0) + 1
        return counts

    def reset(self) -> None:
        self.events.clear()
