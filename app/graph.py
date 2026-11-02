"""Workflow-level analysis that needs the connection graph.

Semgrep matches patterns inside single nodes. Some of the most important data
leak risks only appear when you follow the connections between nodes:

  * AI agent prompt injection -> data exfiltration ("lethal trifecta"):
    an agent that (1) sees untrusted content, (2) can read private data and
    (3) has a tool that can send data out.
  * AI agents / endpoints that hand internal Outlook, Teams or monday.com data
    to unauthenticated callers.
  * Unauthenticated triggers that write into Outlook, Teams or monday.com.

It also produces a data-flow inventory ("where does data go?") for the report.

n8n connection model:
  connections[source]["main"]        -> normal data flow between steps
  connections[source]["ai_tool"]     -> source is a tool of the target agent
  connections[source]["ai_languageModel" | "ai_memory" | ...] -> sub-nodes
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import DataFlow, Finding
from .workflow import NormalizedWorkflow

LANGCHAIN_PREFIX = "@n8n/n8n-nodes-langchain."
BASE_PREFIX = "n8n-nodes-base."

# Business systems whose data we treat as private. key = node "kind" (type
# without package prefix and without Tool/Trigger suffix).
SERVICES: dict[str, str] = {
    "microsoftOutlook": "Microsoft Outlook",
    "microsoftTeams": "Microsoft Teams",
    "mondayCom": "monday.com",
    "microsoftOneDrive": "Microsoft OneDrive",
    "microsoftSharePoint": "Microsoft SharePoint",
    "microsoftExcel": "Microsoft Excel",
    "microsoftToDo": "Microsoft To Do",
    "gmail": "Gmail",
    "googleDrive": "Google Drive",
    "googleSheets": "Google Sheets",
    "slack": "Slack",
    "telegram": "Telegram",
    "whatsApp": "WhatsApp",
    "discord": "Discord",
    "emailSend": "SMTP email",
    "emailReadImap": "IMAP mailbox",
    "notion": "Notion",
    "jira": "Jira",
    "hubspot": "HubSpot",
    "salesforce": "Salesforce",
    "postgres": "PostgreSQL",
    "mySql": "MySQL",
    "microsoftSql": "Microsoft SQL Server",
    "mongoDb": "MongoDB",
    "redis": "Redis",
    "supabase": "Supabase",
}
# Services whose records are messages written by people outside your control
# (emails, chats): reading them puts untrusted text in front of an AI model.
MESSAGE_SERVICES = {"microsoftOutlook", "microsoftTeams", "gmail", "emailReadImap", "slack", "telegram", "whatsApp", "discord"}
# Internal data stores: private data for AI checks, but not "external
# services" for the endpoint checks (SQL risks are covered by Semgrep rules).
DATABASE_KINDS = {"postgres", "mySql", "microsoftSql", "mongoDb", "redis", "supabase"}
HTTP_KINDS = {"httpRequest", "toolHttpRequest"}
# Tools that can run arbitrary logic: assume they can both read and send.
OPAQUE_TOOL_KINDS = {"toolCode", "toolWorkflow", "mcpClientTool", "agentTool"}
AGENT_KINDS = {"agent", "agentTool"}
ENDPOINT_TRIGGERS = {"webhook", "formTrigger", "chatTrigger", "mcpTrigger"}
READ_OPERATIONS = {"get", "getall", "getmany", "search", "getbycolumnvalue", "list", "download", "read", "getitems", "getallitems"}

LLM_PROVIDERS = {
    "OpenAi": "OpenAI",
    "AzureOpenAi": "Azure OpenAI",
    "Anthropic": "Anthropic",
    "GoogleGemini": "Google Gemini",
    "GoogleVertex": "Google Vertex AI",
    "GooglePalm": "Google PaLM",
    "MistralCloud": "Mistral AI",
    "Groq": "Groq",
    "Ollama": "Ollama (self-hosted)",
    "AwsBedrock": "AWS Bedrock",
    "DeepSeek": "DeepSeek",
    "OpenRouter": "OpenRouter",
    "XAiGrok": "xAI Grok",
    "Cohere": "Cohere",
    "HuggingFaceInference": "Hugging Face",
}


@dataclass
class Node:
    name: str
    type: str
    params: dict[str, Any]
    kind: str = ""
    is_trigger: bool = False
    tool_of: list[str] = field(default_factory=list)   # agents this node is a tool for
    model_of: list[str] = field(default_factory=list)  # agents/chains this node is the LLM / embeddings for

    @property
    def operation(self) -> str:
        op = self.params.get("operation")
        return op if isinstance(op, str) else ""

    @property
    def is_read(self) -> bool:
        return self.is_trigger or self.operation.lower() in READ_OPERATIONS

    @property
    def is_write(self) -> bool:
        # Unknown operation (default) is treated as possibly writing.
        return not self.is_trigger and self.operation.lower() not in READ_OPERATIONS

    @property
    def service(self) -> str | None:
        return SERVICES.get(self.kind)


def _kind(node_type: str) -> tuple[str, bool]:
    """"n8n-nodes-base.microsoftOutlookTool" -> ("microsoftOutlook", False)."""
    kind = node_type.split(".", 1)[1] if "." in node_type else node_type
    is_trigger = kind.endswith("Trigger") and kind not in ENDPOINT_TRIGGERS
    if kind.endswith("Tool") and kind not in {"mcpClientTool", "agentTool"}:
        kind = kind[: -len("Tool")]
    if is_trigger:
        kind = kind[: -len("Trigger")]
    if kind in ENDPOINT_TRIGGERS:
        is_trigger = True
    if kind == "emailReadImap":
        is_trigger = True
    return kind, is_trigger


def _llm_provider(kind: str) -> str | None:
    for prefix in ("lmChat", "lm", "embeddings"):
        if kind.startswith(prefix) and len(kind) > len(prefix):
            suffix = kind[len(prefix):]
            return LLM_PROVIDERS.get(suffix, re.sub(r"(?<!^)(?=[A-Z])", " ", suffix))
    if kind == "openAi":
        return "OpenAI"
    return None


class WorkflowGraph:
    def __init__(self, data: dict[str, Any]) -> None:
        self.nodes: dict[str, Node] = {}
        for raw in data.get("nodes", []):
            name, node_type = raw.get("name"), raw.get("type")
            if not isinstance(name, str) or not isinstance(node_type, str):
                continue
            params = raw.get("parameters") if isinstance(raw.get("parameters"), dict) else {}
            kind, is_trigger = _kind(node_type)
            self.nodes[name] = Node(name, node_type, params, kind, is_trigger)

        self.downstream: dict[str, set[str]] = {n: set() for n in self.nodes}
        self.upstream: dict[str, set[str]] = {n: set() for n in self.nodes}
        connections = data.get("connections") if isinstance(data.get("connections"), dict) else {}
        for source, outputs in connections.items():
            if source not in self.nodes or not isinstance(outputs, dict):
                continue
            for conn_type, branches in outputs.items():
                for target in _targets(branches):
                    if target not in self.nodes:
                        continue
                    if conn_type == "main":
                        self.downstream[source].add(target)
                        self.upstream[target].add(source)
                    elif conn_type == "ai_tool":
                        self.nodes[source].tool_of.append(target)
                    elif conn_type in ("ai_languageModel", "ai_embedding"):
                        self.nodes[source].model_of.append(target)

    def walk(self, start: str, direction: str) -> set[str]:
        """All nodes reachable from `start` through main connections (excluding start)."""
        edges = self.downstream if direction == "down" else self.upstream
        seen: set[str] = set()
        queue = deque(edges.get(start, ()))
        while queue:
            name = queue.popleft()
            if name in seen:
                continue
            seen.add(name)
            queue.extend(edges.get(name, ()))
        return seen

    def tools_of(self, agent: str) -> list[Node]:
        return [n for n in self.nodes.values() if agent in n.tool_of]

    def agents(self) -> list[Node]:
        with_tools = {a for n in self.nodes.values() for a in n.tool_of}
        return [n for n in self.nodes.values() if n.kind in AGENT_KINDS or n.name in with_tools]


def _targets(branches: Any) -> Iterable[str]:
    if not isinstance(branches, list):
        return
    for branch in branches:
        if not isinstance(branch, list):
            continue
        for conn in branch:
            if isinstance(conn, dict) and isinstance(conn.get("node"), str):
                yield conn["node"]


# --------------------------------------------------------------- classifiers
def _unauthenticated_endpoint(node: Node) -> bool:
    """Webhook / form / chat / MCP trigger that anyone can call."""
    auth = node.params.get("authentication")
    no_auth = auth in (None, "", "none")
    if node.kind == "chatTrigger":
        return node.params.get("public") is True and no_auth
    return node.kind in ENDPOINT_TRIGGERS and no_auth


def _untrusted_input(node: Node) -> str | None:
    """Why this node brings attacker-controllable text into the workflow."""
    if node.kind in ENDPOINT_TRIGGERS and _unauthenticated_endpoint(node):
        return "unauthenticated endpoint"
    if node.kind in MESSAGE_SERVICES and node.is_read:
        return "external messages" if node.is_trigger else "reads messages"
    return None


def _reads_private(node: Node) -> bool:
    return (
        node.kind in OPAQUE_TOOL_KINDS
        or node.kind in DATABASE_KINDS
        or node.kind.startswith("vectorStore")
        or (node.service is not None and node.is_read)
    )


def _sends_out(node: Node) -> bool:
    if node.kind in HTTP_KINDS or node.kind in OPAQUE_TOOL_KINDS:
        return True
    return node.service is not None and node.is_write and node.kind not in DATABASE_KINDS


def _business_service(node: Node) -> bool:
    """External SaaS (Outlook, Teams, monday.com, ...) used as a normal step."""
    return node.service is not None and node.kind not in DATABASE_KINDS and not node.tool_of


def _describe(node: Node) -> str:
    label = node.service or ("HTTP" if node.kind in HTTP_KINDS else node.kind)
    op = f" · {node.operation}" if node.operation else ""
    return f"{node.name} ({label}{op})"


def _returns_response(graph: WorkflowGraph, trigger: Node, reachable: set[str]) -> bool:
    if trigger.kind == "chatTrigger":
        return True  # chat UI shows the last node's output
    if trigger.params.get("responseMode") in ("lastNode", "responseNode"):
        if trigger.params.get("responseMode") == "lastNode":
            return True
        return any(graph.nodes[n].kind == "respondToWebhook" for n in reachable)
    return False


# ------------------------------------------------------------------- checks
def analyze_workflow(workflow: NormalizedWorkflow) -> tuple[list[Finding], list[DataFlow]]:
    graph = WorkflowGraph(workflow.data)
    findings: list[Finding] = []
    findings += _check_agents(graph, workflow)
    findings += _check_endpoints(graph, workflow)
    return findings, _data_flows(graph)


def _check_agents(graph: WorkflowGraph, wf: NormalizedWorkflow) -> list[Finding]:
    findings: list[Finding] = []
    for agent in graph.agents():
        upstream = [graph.nodes[n] for n in graph.walk(agent.name, "up")]
        tools = graph.tools_of(agent.name)

        untrusted = [f"{n.name} ({why})" for n in upstream + tools if (why := _untrusted_input(n))]
        private = [_describe(t) for t in tools if _reads_private(t)]
        outbound = [_describe(t) for t in tools if _sends_out(t)]
        public_entry = [n for n in upstream if n.is_trigger and _unauthenticated_endpoint(n)]

        evidence = [
            f"Untrusted input : {', '.join(untrusted) or '-'}",
            f"Private data    : {', '.join(private) or '-'}",
            f"Outbound actions: {', '.join(outbound) or '-'}",
        ]

        if untrusted and private and outbound:
            findings.append(_finding(
                wf, agent, "n8n-ai-prompt-injection-exfiltration", "critical",
                "AI agent can be tricked into leaking private data",
                f"Agent \"{agent.name}\" reads untrusted content, can access private data and "
                "has tools that send data out. A single crafted email, chat message or form "
                "entry can instruct it to collect internal data and send it to the attacker "
                "(prompt injection).",
                "Break the chain: remove either the outbound tools or the private-data tools "
                "from this agent, or split it into two agents. Fix recipients/URLs in tool "
                "settings instead of letting the model choose them, and require human approval "
                "(Send and Wait for Response) before anything leaves the organisation.",
                "CWE-77: Improper Neutralization of Special Elements used in a Command",
                "LLM01:2025 Prompt Injection", evidence,
            ))
        elif untrusted and outbound:
            findings.append(_finding(
                wf, agent, "n8n-ai-untrusted-input-outbound-actions", "high",
                "Untrusted input can make the AI agent act",
                f"Agent \"{agent.name}\" processes untrusted content and can call tools that send "
                "data or change external systems. Instructions hidden in that content can "
                "trigger those tools.",
                "Limit the agent's tools to read-only actions, fix recipients/URLs in the tool "
                "configuration and add a human approval step before sends or updates.",
                "CWE-77: Improper Neutralization of Special Elements used in a Command",
                "LLM01:2025 Prompt Injection", evidence,
            ))

        if public_entry and private:
            replies = any(_returns_response(graph, t, graph.walk(t.name, "down")) for t in public_entry)
            if replies:
                findings.append(_finding(
                    wf, agent, "n8n-ai-private-data-to-public-users", "high",
                    "AI agent can reveal internal data to anonymous users",
                    f"Agent \"{agent.name}\" is reachable without authentication "
                    f"({', '.join(t.name for t in public_entry)}) and its tools read private data. "
                    "Anyone can ask it to return that data.",
                    "Add authentication to the trigger, or restrict the tools to data that is "
                    "safe to show the public (e.g. a curated FAQ board).",
                    "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                    "LLM02:2025 Sensitive Information Disclosure", evidence,
                ))
    return findings


def _check_endpoints(graph: WorkflowGraph, wf: NormalizedWorkflow) -> list[Finding]:
    findings: list[Finding] = []
    for trigger in graph.nodes.values():
        if not (trigger.is_trigger and trigger.kind in {"webhook", "formTrigger"} and _unauthenticated_endpoint(trigger)):
            continue
        reachable = [graph.nodes[n] for n in graph.walk(trigger.name, "down")]
        reads = [n for n in reachable if _business_service(n) and n.is_read]
        writes = [n for n in reachable if _business_service(n) and n.is_write]

        if reads and _returns_response(graph, trigger, {n.name for n in reachable}):
            findings.append(_finding(
                wf, trigger, "n8n-endpoint-returns-internal-data", "high",
                "Unauthenticated endpoint returns internal data",
                f"\"{trigger.name}\" has no authentication, reads "
                f"{', '.join(sorted({n.service for n in reads if n.service}))} data and returns a "
                "response to the caller. Anyone who finds the URL can read that data.",
                "Add Header Auth / Basic Auth / JWT to the trigger and return only the fields the "
                "caller needs.",
                "CWE-306: Missing Authentication for Critical Function",
                "A01:2021 - Broken Access Control",
                [f"Reads : {', '.join(_describe(n) for n in reads)}",
                 f"Path  : {trigger.name} → … → response to caller"],
                category="integrations",
            ))
        if writes:
            services = sorted({n.service for n in writes if n.service})
            findings.append(_finding(
                wf, trigger, "n8n-endpoint-writes-business-systems", "medium",
                f"Anonymous input writes to {', '.join(services)}",
                f"\"{trigger.name}\" has no authentication and its data flows into "
                f"{', '.join(services)}. Anyone can create records, post messages or send email "
                "through your accounts (spam, phishing from a trusted sender, data pollution).",
                "Add authentication or a CAPTCHA-protected form, validate input in an IF / Code "
                "node, and rate-limit before writing to business systems.",
                "CWE-306: Missing Authentication for Critical Function",
                "A01:2021 - Broken Access Control",
                [f"Writes: {', '.join(_describe(n) for n in writes)}"],
                category="integrations",
            ))
    return findings


GRAPH_BRIEFS = {
    "n8n-ai-prompt-injection-exfiltration": "A malicious email or message can trick this AI agent into sending private data to an attacker.",
    "n8n-ai-untrusted-input-outbound-actions": "Untrusted messages can make this AI agent send data or change other systems.",
    "n8n-ai-private-data-to-public-users": "Anyone can ask this AI agent to reveal internal data.",
    "n8n-endpoint-returns-internal-data": "Anyone with the URL can read internal mailbox, chat or board data.",
    "n8n-endpoint-writes-business-systems": "Anyone can create records or send messages through your company accounts.",
}


def _finding(
    wf: NormalizedWorkflow, node: Node, rule_id: str, risk: str, title: str, message: str,
    remediation: str, cwe: str, owasp: str, evidence: list[str], category: str = "ai-agent",
) -> Finding:
    span = next((s for s in wf.node_spans if s.name == node.name), None)
    return Finding(
        rule_id=rule_id,
        title=title,
        brief=GRAPH_BRIEFS[rule_id],
        message=message,
        risk=risk,  # type: ignore[arg-type]
        category=category,
        cwe=cwe,
        owasp=owasp,
        remediation=remediation,
        start_line=span.start_line if span else 1,
        end_line=span.start_line if span else 1,
        snippet="\n".join(evidence),
        node_name=node.name,
        node_type=node.type,
        source="workflow-graph",
    )


# ---------------------------------------------------------------- inventory
def _data_flows(graph: WorkflowGraph) -> list[DataFlow]:
    flows: list[DataFlow] = []
    for node in graph.nodes.values():
        via = (
            f"AI tool of {', '.join(node.tool_of)}" if node.tool_of
            else f"AI model of {', '.join(node.model_of)}" if node.model_of
            else "trigger" if node.is_trigger
            else "workflow step"
        )
        provider = _llm_provider(node.kind)
        if provider:
            external = "self-hosted" not in provider
            flows.append(DataFlow(
                node_name=node.name, service=provider, direction="sends",
                via=via, detail="prompts, conversation and tool results", external=external,
            ))
        elif node.kind in HTTP_KINDS:
            flows.append(DataFlow(
                node_name=node.name, service=_http_target(node.params.get("url")), direction="sends",
                via=via, detail=str(node.params.get("method", "GET")), external=True,
            ))
        elif node.service:
            direction = "receives" if node.is_trigger else "reads" if node.is_read else "sends"
            detail = " · ".join(str(p) for p in (node.params.get("resource"), node.operation) if p)
            flows.append(DataFlow(
                node_name=node.name, service=node.service, direction=direction,
                via=via, detail=detail or "-", external=node.kind not in DATABASE_KINDS,
            ))
    order = {"sends": 0, "reads": 1, "receives": 2}
    return sorted(flows, key=lambda f: (order.get(f.direction, 3), f.service, f.node_name))


def _http_target(url: Any) -> str:
    if not isinstance(url, str) or not url.strip():
        return "HTTP (no URL)"
    value = url.lstrip("=").strip()
    if "{" in value.split("/")[2 if "://" in value else 0]:
        return "HTTP (URL decided at runtime)"
    try:
        host = urlsplit(value if "://" in value else f"https://{value}").hostname
    except ValueError:
        host = None
    return f"HTTP · {host}" if host else "HTTP (URL decided at runtime)"
