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
        "n8n-tls-verification-disabled",
        "n8n-cleartext-http-url",
        "n8n-command-injection-via-expression",
        "n8n-execute-command-node",
        "n8n-code-node-dangerous-api",
        "n8n-code-node-present",
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
    # Secret values are masked in snippets.
    assert "P@ssw0rd-prod" not in json.dumps(body)
    assert by_rule["n8n-credentials-in-url"]["snippet"].endswith('"https://admin:****@reports.example.com/upload",')


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
