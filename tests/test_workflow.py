"""Unit tests for workflow parsing / normalization (no semgrep needed)."""

import json

import pytest

from app.workflow import WorkflowValidationError, normalize_workflow, parse_workflow


@pytest.mark.parametrize(
    "raw, message",
    [
        ("", "empty"),
        ("{not json", "Invalid JSON"),
        ("[]", "top level"),
        ('{"name": "x"}', '"nodes"'),
        ('{"nodes": [1]}', "JSON object"),
        ('{"nodes": [], "x": NaN}', "constant"),
        ("[" * 100_000 + "]" * 100_000, "deeply"),
    ],
)
def test_rejects_invalid_input(raw, message):
    with pytest.raises(WorkflowValidationError, match=message):
        parse_workflow(raw)


def test_node_index_maps_lines_to_nodes():
    data = {
        "name": "WF",
        "nodes": [
            {"parameters": {"name": "nested-not-a-node-name"}, "name": "A", "type": "t.a"},
            {"parameters": {}, "name": "B", "type": "t.b"},
        ],
        "connections": {},
    }
    wf = normalize_workflow(parse_workflow(json.dumps(data)))
    assert wf.name == "WF" and wf.node_count == 2
    assert [(s.name, s.type) for s in wf.node_spans] == [("A", "t.a"), ("B", "t.b")]

    lines = wf.text.splitlines()
    b_line = next(i for i, line in enumerate(lines, 1) if line.strip() == '"name": "B",')
    assert wf.node_at(b_line).name == "B"
    assert wf.node_at(1) is None
