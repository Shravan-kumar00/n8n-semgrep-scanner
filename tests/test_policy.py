"""Unit tests for the tuning policy (no semgrep needed)."""

import pytest

from app.models import Finding
from app.scanning.policy import TuningPolicy, parse_networks


def finding(rule_id, snippet="", node_type=None):
    return Finding(
        rule_id=rule_id, title="t", brief="b.", message="m", risk="low", category="transport",
        remediation="r", start_line=1, end_line=1, snippet=snippet, node_name="N", node_type=node_type,
    )


POLICY = TuningPolicy(parse_networks("10.0.12.0/24, 192.168.50.0/24"), trust_form_triggers=True)


@pytest.mark.parametrize(
    "url, suppressed",
    [
        ('"url": "http://10.0.12.187:8080/convert"', True),
        ('"url": "=http://192.168.50.9/api"', True),
        ('"url": "http://10.0.13.5/api"', False),        # private, but not trusted
        ('"url": "http://gotenberg:3000/convert"', False),  # host names are never matched by CIDR
        ('"url": "http://10.0.12.187.evil.example/x"', False),
    ],
)
def test_trusted_networks(url, suppressed):
    kept, hidden = POLICY.apply([finding("n8n-cleartext-http-internal", url)])
    assert bool(hidden) is suppressed and bool(kept) is not suppressed


def test_form_triggers_only_when_enabled():
    form = finding("n8n-webhook-without-authentication", node_type="n8n-nodes-base.formTrigger")
    webhook = finding("n8n-webhook-without-authentication", node_type="n8n-nodes-base.webhook")
    kept, hidden = POLICY.apply([form, webhook])
    assert kept == [webhook] and hidden[0].reason.startswith("Form trigger trusted")
    kept, hidden = TuningPolicy().apply([form])
    assert kept == [form] and hidden == []


def test_invalid_networks_rejected():
    with pytest.raises(ValueError):
        parse_networks("10.0.12.0/24, not-a-network")


def test_disabled_rules():
    sql = finding("n8n-sql-injection-via-expression", '"query": "SELECT 1"')
    kept, hidden = TuningPolicy(disabled_rules=frozenset({"n8n-sql-injection-via-expression"})).apply([sql])
    assert kept == [] and hidden[0].reason == "Rule turned off by policy (DISABLED_RULES)"
    assert TuningPolicy().apply([sql]) == ([sql], [])
