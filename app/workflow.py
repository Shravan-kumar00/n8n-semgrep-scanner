"""Parsing, validation and normalization of n8n workflow JSON.

The pasted text is never handed to Semgrep as-is. It is parsed, validated and
re-serialized with a fixed layout (2-space indent). This:
  * guarantees Semgrep only ever sees well-formed JSON,
  * gives stable line numbers the UI can map back to a snippet, and
  * lets us map each finding to the n8n node that contains it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

MAX_NODES = 5_000


class WorkflowValidationError(ValueError):
    """The submitted text is not a usable n8n workflow. Message is user-safe."""


@dataclass(frozen=True)
class NodeSpan:
    start_line: int
    end_line: int
    name: str | None
    type: str | None


@dataclass(frozen=True)
class NormalizedWorkflow:
    text: str
    name: str | None
    node_count: int
    node_spans: list[NodeSpan]

    def node_at(self, line: int) -> NodeSpan | None:
        """Return the node whose JSON object encloses `line`, if any."""
        for span in self.node_spans:
            if span.start_line <= line <= span.end_line:
                return span
        return None


def _reject_constant(value: str) -> Any:
    # json.loads accepts NaN/Infinity by default; they are not valid JSON.
    raise WorkflowValidationError(f"Invalid JSON constant: {value}")


def parse_workflow(raw: str) -> dict[str, Any]:
    """Parse and structurally validate an n8n workflow export."""
    if not raw or not raw.strip():
        raise WorkflowValidationError("Workflow JSON is empty.")
    try:
        data = json.loads(raw, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise WorkflowValidationError(
            f"Invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})."
        ) from None
    except RecursionError:
        raise WorkflowValidationError("JSON is nested too deeply.") from None

    if not isinstance(data, dict):
        raise WorkflowValidationError("Expected a JSON object at the top level (an n8n workflow export).")
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        raise WorkflowValidationError('Not an n8n workflow: missing a "nodes" array.')
    if len(nodes) > MAX_NODES:
        raise WorkflowValidationError(f"Workflow has too many nodes (max {MAX_NODES}).")
    if not all(isinstance(node, dict) for node in nodes):
        raise WorkflowValidationError('Every entry in "nodes" must be a JSON object.')
    return data


def normalize_workflow(data: dict[str, Any]) -> NormalizedWorkflow:
    """Pretty-print the workflow and index which lines belong to which node."""
    try:
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    except RecursionError:
        raise WorkflowValidationError("JSON is nested too deeply.") from None
    name = data.get("name") if isinstance(data.get("name"), str) else None
    return NormalizedWorkflow(
        text=text,
        name=name,
        node_count=len(data["nodes"]),
        node_spans=_index_nodes(text),
    )


def _index_nodes(text: str) -> list[NodeSpan]:
    """Find the line range of every node object in the normalized text.

    Relies on the deterministic layout of json.dumps(indent=2):

        {
          "nodes": [
            {                         <- node starts (4 spaces)
              "name": "Webhook",      <- node-level key (6 spaces)
              ...
            },                        <- node ends (4 spaces)
    """
    spans: list[NodeSpan] = []
    in_nodes = False
    current: dict[str, Any] | None = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        if not in_nodes:
            if line == '  "nodes": [':
                in_nodes = True
            continue
        if line in ("  ]", "  ],"):
            break
        if line == "    {":
            current = {"start": lineno, "name": None, "type": None}
            continue
        if current is None:
            continue
        if line in ("    }", "    },"):
            spans.append(NodeSpan(current["start"], lineno, current["name"], current["type"]))
            current = None
            continue
        for key in ("name", "type"):
            prefix = f'      "{key}": '
            if line.startswith(prefix):
                try:
                    value = json.loads(line[len(prefix):].rstrip(","))
                except json.JSONDecodeError:
                    value = None
                if isinstance(value, str):
                    current[key] = value
    return spans
