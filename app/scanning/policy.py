"""Organisation-specific tuning applied after Semgrep runs (n8n workflows).

Rule files describe what is risky in general. This policy encodes decisions
specific to our environment that depend on configuration rather than on
patterns, for example which private subnets are trusted. Suppressed findings
are not silently dropped: they are returned in ScanResponse.suppressed so
reviewers can see what the policy hid and why.

Configured through environment variables (see app/config.py):
  TRUSTED_NETWORKS     comma-separated CIDRs, e.g. "10.0.12.0/24,10.20.0.0/16"
  TRUST_FORM_TRIGGERS  "true" -> n8n Form Triggers are not treated as
                       unauthenticated endpoints
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..models import Finding, SuppressedFinding

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

CLEARTEXT_RULES = {"n8n-cleartext-http-internal", "n8n-cleartext-http-url"}
UNAUTHENTICATED_TRIGGER_RULES = {"n8n-webhook-without-authentication"}
FORM_TRIGGER_TYPE = "n8n-nodes-base.formTrigger"

_HTTP_HOST = re.compile(r"http://\[?([0-9A-Za-z.:-]+?)\]?(?::\d+)?(?:[/?\"]|$)", re.IGNORECASE)


def parse_networks(value: str) -> tuple[IPNetwork, ...]:
    """Parse "10.0.12.0/24, 192.168.5.0/24" (raises ValueError on bad input)."""
    return tuple(ipaddress.ip_network(part.strip(), strict=False) for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class TuningPolicy:
    trusted_networks: tuple[IPNetwork, ...] = ()
    trust_form_triggers: bool = False

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[SuppressedFinding]]:
        kept: list[Finding] = []
        suppressed: list[SuppressedFinding] = []
        for finding in findings:
            reason = self._suppression_reason(finding)
            if reason is None:
                kept.append(finding)
            else:
                suppressed.append(SuppressedFinding(
                    rule_id=finding.rule_id, title=finding.title, risk=finding.risk,
                    start_line=finding.start_line, node_name=finding.node_name, reason=reason,
                ))
        return kept, suppressed

    def _suppression_reason(self, finding: Finding) -> str | None:
        if finding.rule_id in CLEARTEXT_RULES and self.trusted_networks:
            network = self.trusted_network_for(finding.snippet)
            if network is not None:
                return f"Plain HTTP inside trusted network {network}"
        if (
            finding.rule_id in UNAUTHENTICATED_TRIGGER_RULES
            and self.trust_form_triggers
            and finding.node_type == FORM_TRIGGER_TYPE
        ):
            return "Form trigger trusted by policy (TRUST_FORM_TRIGGERS)"
        return None

    def trusted_network_for(self, text: str) -> IPNetwork | None:
        """The trusted network containing the host of the first http:// URL in text."""
        match = _HTTP_HOST.search(text)
        if not match:
            return None
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            return None  # a host name, not an IP literal
        return next((net for net in self.trusted_networks if address in net), None)
