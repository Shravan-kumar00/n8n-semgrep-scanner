"""Unit tests for the connection-graph analysis (no semgrep needed)."""

import json

from app.graph import analyze_workflow
from app.workflow import normalize_workflow, parse_workflow


def analyze(nodes, connections):
    wf = normalize_workflow(parse_workflow(json.dumps({"name": "t", "nodes": nodes, "connections": connections})))
    findings, flows = analyze_workflow(wf)
    return {f.rule_id for f in findings}, flows


def node(name, type_, **params):
    return {"name": name, "type": type_, "parameters": params}


def tool(name, agent="Agent"):
    return {name: {"ai_tool": [[{"node": agent, "type": "ai_tool", "index": 0}]]}}


AGENT = node("Agent", "@n8n/n8n-nodes-langchain.agent")
READ_MAIL = node("Read Mail", "n8n-nodes-base.microsoftOutlookTool", resource="message", operation="getAll")
SEND_MAIL = node("Send Mail", "n8n-nodes-base.microsoftOutlookTool", resource="message", operation="send")
BOARD = node("Board", "n8n-nodes-base.mondayComTool", resource="boardItem", operation="getAll")


def test_trifecta_needs_untrusted_input():
    # Manual trigger + board read + send: no untrusted content reaches the agent.
    manual = node("Start", "n8n-nodes-base.manualTrigger")
    rules, _ = analyze(
        [manual, AGENT, BOARD, SEND_MAIL],
        {"Start": {"main": [[{"node": "Agent", "type": "main", "index": 0}]]}, **tool("Board"), **tool("Send Mail")},
    )
    assert rules == set()


def test_reading_email_is_untrusted_input():
    # The mailbox itself carries attacker-written text: read mail + send mail = trifecta.
    rules, _ = analyze([AGENT, READ_MAIL, SEND_MAIL], {**tool("Read Mail"), **tool("Send Mail")})
    assert rules == {"n8n-ai-prompt-injection-exfiltration"}


def test_authenticated_chat_is_not_public():
    chat = node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", public=True, authentication="n8nUserAuth")
    rules, _ = analyze(
        [chat, AGENT, BOARD],
        {"Chat": {"main": [[{"node": "Agent", "type": "main", "index": 0}]]}, **tool("Board")},
    )
    assert rules == set()


def test_authenticated_webhook_reading_outlook_is_fine():
    hook = node("Hook", "n8n-nodes-base.webhook", authentication="headerAuth", responseMode="lastNode")
    mail = node("Mail", "n8n-nodes-base.microsoftOutlook", resource="message", operation="getAll")
    rules, _ = analyze([hook, mail], {"Hook": {"main": [[{"node": "Mail", "type": "main", "index": 0}]]}})
    assert rules == set()


def test_data_flows_name_llm_providers_and_hosts():
    nodes = [
        AGENT,
        node("Model", "@n8n/n8n-nodes-langchain.lmChatAzureOpenAi"),
        node("Local", "@n8n/n8n-nodes-langchain.lmChatOllama"),
        node("Call", "n8n-nodes-base.httpRequest", url="https://api.example.com/v1/x", method="POST"),
        node("Dyn", "n8n-nodes-base.httpRequest", url="={{ $json.target }}"),
    ]
    connections = {"Model": {"ai_languageModel": [[{"node": "Agent", "type": "ai_languageModel", "index": 0}]]}}
    _, flows = analyze(nodes, connections)
    by_node = {f.node_name: f for f in flows}
    assert by_node["Model"].service == "Azure OpenAI" and by_node["Model"].via == "AI model of Agent"
    assert by_node["Local"].external is False
    assert by_node["Call"].service == "HTTP · api.example.com"
    assert by_node["Dyn"].service == "HTTP (URL decided at runtime)"


def test_malformed_connections_are_ignored():
    rules, flows = analyze([AGENT], {"Agent": "nope", "Ghost": {"main": [[{"node": "Agent"}]]}, "X": {"main": [None, [1]]}})
    assert rules == set() and flows == []
