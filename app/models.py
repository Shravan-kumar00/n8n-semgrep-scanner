"""Pydantic request/response schemas for the HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .languages import LANGUAGES

Risk = Literal["critical", "high", "medium", "low", "info"]
# "full" = every rule; "credentials" = only secret / password / token rules.
ScanProfile = Literal["full", "credentials"]

# Display/sort order, most severe first.
RISK_ORDER: tuple[Risk, ...] = ("critical", "high", "medium", "low", "info")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # What to scan. `workflow` is the original n8n field and still works;
    # `content` is the general field for any language.
    workflow: str | None = Field(None, description="n8n workflow export as a JSON string")
    content: str | None = Field(None, description="File contents to scan (any supported language)")
    language: str = Field("n8n", description="Language id from GET /api/languages")
    filename: str | None = Field(None, max_length=255, description="Original file name (extension hint only)")
    profile: ScanProfile = Field("full", description='"full" or "credentials" (secrets only)')

    @model_validator(mode="after")
    def _check(self) -> "ScanRequest":
        if self.language not in LANGUAGES:
            raise ValueError(f"Unknown language {self.language!r}")
        if self.workflow is not None and self.content is not None:
            raise ValueError('Send either "workflow" or "content", not both')
        if not (self.text or "").strip():
            raise ValueError('"content" (or "workflow") must not be empty')
        return self

    @property
    def text(self) -> str:
        return self.content if self.content is not None else (self.workflow or "")


class PdfReportRequest(ScanRequest):
    # Off by default so a PDF can be shared without spreading the secrets.
    include_secrets: bool = False


class Finding(BaseModel):
    rule_id: str
    title: str
    # One plain-English sentence summarising the issue (used by the PDF report).
    brief: str
    message: str
    risk: Risk
    category: str
    cwe: str | None = None
    owasp: str | None = None
    remediation: str
    # n8n: line numbers refer to the normalized workflow (json.dumps(indent=2)),
    # line-for-line identical to JSON.stringify(data, null, 2) in the UI.
    # Code: line numbers are those of the uploaded file, unchanged.
    start_line: int
    end_line: int
    snippet: str
    # Secrets only: the exact hardcoded value / leaked text, unmasked. The
    # snippet stays masked so it can be shown as surrounding context.
    exposed_value: str | None = None
    node_name: str | None = None
    node_type: str | None = None
    # "semgrep" = pattern rule; "workflow-graph" = found by following node
    # connections (app/graph.py). For graph findings `snippet` holds evidence.
    source: Literal["semgrep", "workflow-graph"] = "semgrep"


class DataFlow(BaseModel):
    """One place workflow data leaves (or enters from) an external service."""

    node_name: str
    service: str
    direction: Literal["sends", "reads", "receives"]
    via: str
    detail: str
    external: bool = True


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    profile: ScanProfile
    language: str
    language_label: str
    # Display name: the n8n workflow name or the uploaded file name.
    target_name: str | None
    workflow_name: str | None
    node_count: int | None  # n8n only
    line_count: int
    duration_ms: int
    semgrep_version: str
    summary: ScanSummary
    findings: list[Finding]
    # Where data goes: LLM providers, Microsoft 365, monday.com, HTTP hosts...
    data_flows: list[DataFlow] = Field(default_factory=list)
    # Non-fatal problems reported by semgrep (e.g. a single rule timing out).
    warnings: list[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    semgrep_version: str
    rules_loaded: int
    languages: int


class LanguageInfo(BaseModel):
    id: str
    label: str
    group: str
    short: str
    extensions: list[str]
    filenames: list[str]
    sample: str | None
    rules: int
