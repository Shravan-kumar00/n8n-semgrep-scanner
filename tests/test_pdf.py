"""PDF report endpoint tests. These run the real semgrep binary."""

import re
from pathlib import Path

import pytest
from reportlab import rl_config

SAMPLE = Path(__file__).resolve().parent.parent / "app" / "static" / "samples" / "vulnerable-workflow.json"


@pytest.fixture
def uncompressed(monkeypatch):
    # Leave page streams uncompressed so the tests can search the PDF text.
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def pdf_text(content: bytes) -> str:
    """Text drawn with Tj operators, joined (good enough for assertions)."""
    return " ".join(m.decode("latin-1") for m in re.findall(rb"\((.*?)\) Tj", content, re.DOTALL))


def test_pdf_download(client, uncompressed):
    res = client.post("/api/report.pdf", json={"workflow": SAMPLE.read_text()})
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/pdf"
    assert res.headers["content-disposition"].startswith('attachment; filename="security-report-sample-insecure-order-sync')
    assert res.content.startswith(b"%PDF")

    text = pdf_text(res.content)
    # Grouped by severity, each finding with brief, fix and line number.
    order = [text.index(f"{label} - ") for label in ("Critical", "High", "Medium", "Low") if f"{label} - " in text]
    assert len(order) >= 3 and order == sorted(order)
    assert "IN BRIEF" in text and "HOW TO FIX" in text and "Line 95" in text
    assert "Outside data is inserted into a shell command" in text
    # Only findings: no workflow JSON, and no secrets unless requested.
    assert '"nodes"' not in text and "P@ssw0rd-prod" not in text and "EXPOSED VALUE" not in text


def test_pdf_can_include_exposed_values(client, uncompressed):
    res = client.post("/api/report.pdf", json={"workflow": SAMPLE.read_text(), "include_secrets": True})
    text = pdf_text(res.content)
    assert "EXPOSED VALUE" in text and "P@ssw0rd-prod" in text


def test_pdf_rejects_invalid_workflow(client):
    res = client.post("/api/report.pdf", json={"workflow": "{bad"})
    assert res.status_code == 422


def test_every_finding_has_a_brief(client):
    for sample in ("vulnerable-workflow.json", "ai-agents-m365-workflow.json"):
        body = client.post("/api/scan", json={"workflow": SAMPLE.with_name(sample).read_text()}).json()
        assert all(f["brief"] and f["brief"].endswith(".") for f in body["findings"])
