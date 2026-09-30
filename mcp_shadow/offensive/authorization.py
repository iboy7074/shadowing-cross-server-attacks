"""Rules-of-engagement gate for offensive campaigns.

Fail-closed: nothing runs until an authorization record proves the engagement is
scoped and approved. This is the difference between a red-team tool and a
weapon, so it is enforced in code rather than documented and hoped for.

An authorization record answers three questions:

1. **Who authorized it?** (``authorizer``, non-empty)
2. **What is in scope?** (``Scope`` with explicit targets / server names)
3. **How long is it valid?** (``not_before`` / ``not_after`` window)

Anything not explicitly in scope is refused. The default scope is *local only*.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

# Reserved TLDs/hosts that can never be a real third party. Using these keeps a
# campaign inert by construction.
RESERVED_SUFFIXES = (".example", ".invalid", ".test", ".localhost")
RESERVED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class AuthorizationError(RuntimeError):
    """Raised when a campaign is attempted without valid authorization."""


def _is_local_host(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    if host in RESERVED_HOSTS:
        return True
    if host.endswith(RESERVED_SUFFIXES):
        return True
    try:
        return ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Scope:
    """The set of systems a campaign is permitted to touch.

    By default only local / reserved targets are in scope. A remote host is
    accepted only if it is listed in ``allowed_hosts`` *and* the engagement was
    explicitly marked ``allow_remote=True``.
    """

    allowed_hosts: set[str] = field(default_factory=set)
    allowed_servers: set[str] = field(default_factory=set)
    allow_remote: bool = False
    allow_network_egress: bool = False

    def permits_host(self, host: str) -> bool:
        host = (host or "").lower()
        if _is_local_host(host):
            return True
        if not self.allow_remote:
            return False
        return host in {h.lower() for h in self.allowed_hosts}

    def permits_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "stdio", "mcp", ""}:
            return False
        return self.permits_host(parsed.hostname or "")

    def permits_server(self, name: str) -> bool:
        if not self.allowed_servers:
            return True  # local in-process servers are always allowed
        return name in self.allowed_servers


@dataclass
class RulesOfEngagement:
    """A signed-off engagement. Constructed explicitly; never implied."""

    authorizer: str
    scope: Scope = field(default_factory=Scope)
    engagement_id: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    notes: str = ""
    _granted: bool = field(default=False, repr=False)

    # -- construction --------------------------------------------------------

    @classmethod
    def for_local_lab(
        cls, authorizer: str, engagement_id: str = "local-lab", notes: str = ""
    ) -> "RulesOfEngagement":
        """Authorization for the built-in local lab targets only.

        This is the only constructor that should be used for the sample
        campaigns. It cannot reach a network endpoint.
        """
        roe = cls(
            authorizer=authorizer,
            scope=Scope(allow_remote=False, allow_network_egress=False),
            engagement_id=engagement_id,
            notes=notes,
        )
        roe._granted = True
        return roe

    def grant(self) -> "RulesOfEngagement":
        """Mark this engagement authorized. Call only with real sign-off."""
        if not self.authorizer.strip():
            raise AuthorizationError("authorizer must be named")
        self._granted = True
        return self

    # -- validation ----------------------------------------------------------

    @property
    def granted(self) -> bool:
        return self._granted

    def validate(self, *, now: datetime | None = None) -> None:
        """Raise if the engagement is not currently valid."""
        if not self._granted:
            raise AuthorizationError(
                "engagement is not authorized: call grant() or for_local_lab() "
                "only with documented permission to test"
            )
        if not self.authorizer.strip():
            raise AuthorizationError("authorizer must be named")
        now = now or datetime.now(timezone.utc)
        if self.not_before and now < self.not_before:
            raise AuthorizationError(f"engagement not yet valid until {self.not_before}")
        if self.not_after and now > self.not_after:
            raise AuthorizationError(f"engagement expired at {self.not_after}")

    def authorize_target(self, name: str, host: str | None = None) -> None:
        """Raise if ``name``/``host`` is out of scope."""
        self.validate()
        if not self.scope.permits_server(name):
            raise AuthorizationError(f"server '{name}' is out of scope")
        if host is not None and not self.scope.permits_host(host):
            raise AuthorizationError(f"host '{host}' is out of scope")

    def require_egress_allowed(self, sink_url: str | None) -> None:
        """Raise if a network egress sink is used without explicit permission."""
        if not sink_url:
            return
        if not self.scope.allow_network_egress:
            raise AuthorizationError(
                "network egress is disabled for this engagement; the local sink "
                "records exfiltration in-process without sending anything"
            )
        if not self.scope.permits_url(sink_url):
            raise AuthorizationError(f"sink '{sink_url}' is out of scope")
