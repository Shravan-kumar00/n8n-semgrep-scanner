"""Pydantic request/response schemas for the HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Risk = Literal["critical", "high", "medium", "low", "info"]

# Display/sort order, most severe first.
RISK_ORDER: tuple[Risk, ...] = ("critical", "high", "medium", "low", "info")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The raw n8n workflow JSON, exactly as pasted by the user.
    workflow: str = Field(..., min_length=2, description="n8n workflow export as a JSON string")


class Finding(BaseModel):
    rule_id: str
    title: str
    message: str
    risk: Risk
    category: str
    cwe: str | None = None
    owasp: str | None = None
    remediation: str
    # Line numbers refer to the normalized workflow (json.dumps(indent=2)),
    # which is line-for-line identical to JSON.stringify(data, null, 2) in the UI.
    start_line: int
    end_line: int
    snippet: str
    node_name: str | None = None
    node_type: str | None = None


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    workflow_name: str | None
    node_count: int
    duration_ms: int
    semgrep_version: str
    summary: ScanSummary
    findings: list[Finding]
    # Non-fatal problems reported by semgrep (e.g. a single rule timing out).
    warnings: list[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    semgrep_version: str
    rules_loaded: int
