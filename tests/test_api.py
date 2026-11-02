"""End-to-end API tests. These run the real semgrep binary."""

import json
import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

if shutil.which(os.getenv("SEMGREP_BIN", "semgrep")) is None:
    pytest.skip("semgrep is not installed", allow_module_level=True)

from app.main import app  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "static" / "samples" / "vulnerable-workflow.json"
AI_SAMPLE = SAMPLE.with_name("ai-agents-m365-workflow.json")
CREDENTIAL_CASES = Path(__file__).resolve().parent / "fixtures" / "credential-cases.json"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # runs lifespan -> semgrep version check
        yield c


def scan(client, workflow: str):
    return client.post("/api/scan", json={"workflow": workflow})


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["rules_loaded"] >= 10


def test_sample_triggers_every_rule(client):
    res = scan(client, SAMPLE.read_text())
    assert res.status_code == 200, res.text
    body = res.json()
    assert res.headers["cache-control"] == "no-store"

    rule_ids = {f["rule_id"] for f in body["findings"]}
    assert rule_ids == {
        "n8n-hardcoded-secret-parameter",
        "n8n-hardcoded-secret-name-value-pair",
        "n8n-known-secret-format",
        "n8n-credentials-in-url",
        "n8n-hardcoded-secret-in-code-or-body",
        "n8n-literal-authorization-token",
        "n8n-tls-verification-disabled",
        "n8n-cleartext-http-url",
        "n8n-command-injection-via-expression",
        "n8n-execute-command-node",
        "n8n-code-node-dangerous-api",
        "n8n-sql-injection-via-expression",
        "n8n-webhook-without-authentication",
        "n8n-webhook-permissive-cors",
        "n8n-pinned-data-exported",
    }
    assert body["summary"]["total"] == len(body["findings"])
    # Findings are sorted most severe first and mapped to their nodes.
    assert body["findings"][0]["risk"] == "critical"
    by_rule = {f["rule_id"]: f for f in body["findings"]}
    assert by_rule["n8n-command-injection-via-expression"]["node_name"] == "Archive Orders"
    assert by_rule["n8n-tls-verification-disabled"]["node_name"] == "Push to ERP"
    # Snippets are masked; the exact value is in exposed_value.
    assert "P@ssw0rd-prod" not in "\n".join(f["snippet"] for f in body["findings"])
    assert "P@ssw0rd-prod" in {f["exposed_value"] for f in body["findings"]}
    assert by_rule["n8n-credentials-in-url"]["snippet"].endswith('"https://admin:****@reports.example.com/upload",')


def test_credentials_profile_reports_only_secrets(client):
    res = client.post("/api/scan", json={"workflow": SAMPLE.read_text(), "profile": "credentials"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["profile"] == "credentials"
    assert body["findings"] and {f["category"] for f in body["findings"]} == {"secrets"}
    assert body["summary"]["total"] == len(body["findings"])


def test_credential_detection_cases(client):
    """Every hardcoded credential in node POS is found; nothing in node NEG."""
    res = client.post("/api/scan", json={"workflow": CREDENTIAL_CASES.read_text(), "profile": "credentials"})
    assert res.status_code == 200, res.text
    findings = res.json()["findings"]
    assert {f["node_name"] for f in findings} == {"POS"}
    found = sorted((f["rule_id"].removeprefix("n8n-"), f["start_line"]) for f in findings)
    assert found == [
        ("credentials-in-url", 13),                 # ?api_key=...
        ("credentials-in-url", 14),                 # mongodb://user:pass@
        ("hardcoded-secret-in-code-or-body", 12),   # connection string Password=...;
        ("hardcoded-secret-in-code-or-body", 15),   # escaped JSON body
        ("hardcoded-secret-in-code-or-body", 16),   # jsCode password = '...'
        ("hardcoded-secret-name-value-pair", 19),   # X-Shopify-Access-Token header
        ("hardcoded-secret-name-value-pair", 23),   # Authorization: Basic (nested Basic finding merged)
        ("hardcoded-secret-name-value-pair", 35),   # Set node adminPassword
        ("hardcoded-secret-parameter", 8),          # dbPassword
        ("hardcoded-secret-parameter", 9),          # smtp_pass
        ("hardcoded-secret-parameter", 10),         # x_api_key
        ("hardcoded-secret-parameter", 11),         # password: "admin"
        ("literal-authorization-token", 16),        # Bearer in jsCode
    ]
    # exposed_value carries the exact hardcoded value / leaked text.
    exposed = {(f["start_line"], f["exposed_value"]) for f in findings}
    assert exposed == {
        (8, "Sup3rS3cret"),
        (9, "hunter22"),
        (10, "abcd1234efgh"),
        (11, "admin"),
        (12, "Password=Passw0rd123;"),
        (13, "?api_key=live1234abcd"),
        (14, "mongodb://svc:pw12345@mongo.internal:27017/app"),
        (15, 'password": "P4ssw0rd!"'),
        (16, "password = 'Winter2026'"),
        (16, "Bearer abc123def456ghi789"),
        (19, "shpat_abc123xyz"),
        (23, "Basic dXNlcjpwYXNzMTIz"),
        (35, "Welcome1"),
    }
    # ...while the surrounding snippet stays masked.
    snippets = "\n".join(f["snippet"] for f in findings)
    for secret in ["Sup3rS3cret", "hunter22", '"admin"', "Passw0rd123", "live1234abcd", "pw12345",
                   "P4ssw0rd", "Winter2026", "shpat_abc123xyz", "Welcome1", "dXNlcjpwYXNz"]:
        assert secret not in snippets, secret


def test_ai_and_integration_findings(client):
    res = scan(client, AI_SAMPLE.read_text())
    assert res.status_code == 200, res.text
    body = res.json()
    found = {(f["rule_id"].removeprefix("n8n-"), f["node_name"]) for f in body["findings"]}
    assert found == {
        # AI agents: workflow-graph checks
        ("ai-prompt-injection-exfiltration", "Support Agent"),
        ("ai-private-data-to-public-users", "FAQ Agent"),
        # AI agents: single-node rules
        ("ai-prompt-contains-env-secret", "Support Agent"),
        ("ai-intermediate-steps-exposed", "Support Agent"),
        ("ai-shared-conversation-memory", "Chat Memory"),
        ("ai-tool-model-chosen-recipient", "Send Email"),
        ("ai-tool-model-controlled-url", "Fetch URL"),
        ("ai-tool-destructive-operation", "Delete Item"),
        ("ai-chat-public-without-auth", "Public Chat"),
        ("ai-mcp-server-without-auth", "MCP Server"),
        # Outlook / Teams / monday.com
        ("endpoint-returns-internal-data", "Lookup Webhook"),
        ("endpoint-writes-business-systems", "Intake Form"),
        ("bulk-record-forwarded", "Post to Teams"),
        ("email-recipient-from-request", "Notify Requester"),
        ("email-hidden-bcc", "Notify Requester"),
        ("bulk-read-internal-data", "Read Mailbox"),
        ("bulk-read-internal-data", "Board Lookup"),
        ("teams-webhook-url-exposed", "Teams Alert"),
        ("webhook-without-authentication", "Lookup Webhook"),
        ("webhook-without-authentication", "Intake Form"),
    }
    by_rule = {f["rule_id"]: f for f in body["findings"]}
    trifecta = by_rule["n8n-ai-prompt-injection-exfiltration"]
    assert trifecta["risk"] == "critical" and trifecta["source"] == "workflow-graph"
    assert "Send Email" in trifecta["snippet"] and "Read Mailbox" in trifecta["snippet"]
    # The Teams webhook path is the secret: masked in the snippet.
    assert "IncomingWebhook" not in by_rule["n8n-teams-webhook-url-exposed"]["snippet"]

    flows = {(d["service"], d["direction"], d["node_name"]) for d in body["data_flows"]}
    assert ("OpenAI", "sends", "OpenAI Chat Model") in flows
    assert ("Anthropic", "sends", "Anthropic Model") in flows
    assert ("Microsoft Outlook", "reads", "Read Mailbox") in flows
    assert ("monday.com", "sends", "Create Item") in flows
    assert ("Microsoft Teams", "receives", "Teams Trigger") in flows


def test_credentials_profile_skips_graph_and_flows(client):
    res = client.post("/api/scan", json={"workflow": AI_SAMPLE.read_text(), "profile": "credentials"})
    body = res.json()
    assert [f["rule_id"] for f in body["findings"]] == ["n8n-teams-webhook-url-exposed"]
    assert body["data_flows"] == []


def test_only_secret_findings_expose_values(client):
    body = scan(client, SAMPLE.read_text()).json()
    for f in body["findings"]:
        assert (f["exposed_value"] is not None) == (f["category"] == "secrets"), f["rule_id"]
    assert "n8n-code-node-present" not in {f["rule_id"] for f in body["findings"]}


def test_unknown_profile_rejected(client):
    res = client.post("/api/scan", json={"workflow": SAMPLE.read_text(), "profile": "everything"})
    assert res.status_code == 422


def test_secure_workflow_is_clean(client):
    workflow = {
        "name": "Secure",
        "nodes": [
            {
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "parameters": {"path": "x", "authentication": "headerAuth"},
                "credentials": {"httpHeaderAuth": {"id": "1", "name": "Hook auth"}},
            },
            {
                "name": "Call API",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {
                    "url": "https://api.example.com/items",
                    "authentication": "genericCredentialType",
                    "headerParameters": {"parameters": [{"name": "X-Request-Id", "value": "={{ $json.id }}"}]},
                    "password": "={{ $env.API_PASSWORD }}",
                },
            },
            {
                "name": "Query",
                "type": "n8n-nodes-base.postgres",
                "parameters": {
                    "query": "SELECT * FROM t WHERE id = $1",
                    "options": {"queryReplacement": "={{ $json.id }}"},
                },
            },
        ],
        "connections": {},
    }
    res = scan(client, json.dumps(workflow))
    assert res.status_code == 200, res.text
    assert res.json()["findings"] == []


@pytest.mark.parametrize(
    "kwargs, status",
    [
        ({"json": {"workflow": "{bad"}}, 422),
        ({"json": {"workflow": "[]"}}, 422),
        ({"json": {"nope": "x"}}, 422),
        ({"json": {"workflow": "{}", "extra": 1}}, 422),
        ({"content": b"workflow=x", "headers": {"content-type": "text/plain"}}, 415),
        ({"json": {"workflow": '{"nodes": [], "pad": "' + "a" * 2_100_000 + '"}'}}, 413),
    ],
)
def test_rejects_bad_requests(client, kwargs, status):
    res = client.post("/api/scan", **kwargs)
    assert res.status_code == status, res.text
    assert "detail" in res.json()


def test_index_has_security_headers(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert res.headers["x-content-type-options"] == "nosniff"
