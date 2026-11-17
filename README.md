# Workflow & Code Security Scanner

One place to scan **n8n workflows, source code and infrastructure files** for security problems. Upload or paste a file in the web UI (or call the API) and get a readable report with a verdict, what to fix first, and a plain-English fix for every finding. You can download it as a PDF, HTML, Markdown or JSON.

| Group | Languages / formats | What it looks for |
|---|---|---|
| Automation | **n8n workflows** | Leaked credentials, AI agent data leaks (prompt injection, public agents, shared memory), Outlook / Teams / monday.com risks, injection, TLS, unauthenticated webhooks, plus a data-flow inventory |
| Application code | **Python, JavaScript, TypeScript, Java, Go, C#, PHP, Ruby** | Hardcoded secrets, command / SQL / code injection, XSS, unsafe deserialisation, disabled TLS checks, weak crypto, JWT misuse, debug mode, CSRF / CORS misconfiguration |
| Infrastructure & config | **Shell scripts, Dockerfiles, YAML (Kubernetes, Docker Compose, GitHub Actions), Terraform** | Secrets in config and images, `curl \| sh`, root and privileged containers, Docker socket mounts, CI script injection, public buckets, open firewalls, wildcard IAM, unencrypted storage |
| Other | **Any text file** (`.env`, `.properties`, `.ini`, `.toml`, `.xml`, …) | Leaked passwords, tokens, API keys, private keys, connection strings and credentials in URLs |

The language is detected automatically from the uploaded file name, and you can change it with the picker. All rules are local: nothing is downloaded from the Semgrep registry, and scanned content never leaves the server.

> **A first line of review, not a replacement for one.** The scanner catches known patterns quickly and consistently. It does not understand business context and cannot find every vulnerability. Use it to point reviewers at the riskiest areas, and keep your normal security review and approval process.

## Repository layout

```
n8n-semgrep-scanner/
├── pyproject.toml          # the only dependency / packaging / pytest config file
├── Dockerfile              # FastAPI + Semgrep image (non-root, read-only friendly)
├── docker-compose.yml      # hardened runtime settings and tuning env vars
├── app/                    # Python package
│   ├── main.py             # FastAPI entrypoint: routes, body-size limit, security headers
│   ├── config.py           # settings from environment variables
│   ├── models.py           # API request / response schemas
│   ├── scanning/           # everything that produces findings
│   │   ├── languages.py    # supported languages: extensions, rule files, samples
│   │   ├── scanner.py      # temp files, Semgrep subprocess, result parsing, masking
│   │   ├── policy.py       # tuning policy: trusted networks, trusted form triggers
│   │   ├── workflow.py     # n8n JSON validation, normalisation, line -> node index
│   │   └── graph.py        # n8n connection checks (AI agents, endpoints) + data flows
│   ├── reports/
│   │   └── pdf.py          # PDF report (ReportLab)
│   └── static/             # web UI, served at /static
│       ├── index.html
│       ├── app.js          # rendering + HTML / Markdown / JSON export
│       └── samples/        # n8n samples + code/ (one vulnerable file per language)
├── rules/                  # all Semgrep rules (see rules/README.md for conventions)
│   ├── n8n/workflow.yml
│   ├── code/<language>.yml
│   └── common/secrets.yml, config-secrets.yml
└── tests/
    ├── conftest.py         # shared client fixture; skips Semgrep tests if it is missing
    ├── fixtures/           # credential, tuning and per-language safe cases
    └── test_*.py           # api, languages, pdf, policy, graph, workflow
```

## Run

**Docker (recommended)**

```bash
docker compose up --build -d
```

Open http://localhost:8000, pick a language, click **Load sample** and then **Scan**.

After changing code or rules, rebuild the running container:

```bash
docker compose up -d --build
```

**Local (Python 3.10+)**

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload
pytest
```

All dependencies are pinned in `pyproject.toml`: runtime ones under `[project].dependencies` and test tools under the `dev` extra. The Docker image installs only the runtime set.

## Using the UI

- **Editor:** shows line numbers. **Show line N in editor** on a finding scrolls to that line, highlights it and puts the cursor there. Lines don't wrap, so the numbers always match the report.
- **Step 1, What are you scanning?** Pick n8n workflow, a programming language, an infrastructure format, or *Other text file*.
- **Step 2, Add your file:** paste text, click **Upload file**, or drag a file onto the editor.
  - An uploaded file is read in the browser and its language is detected from the file name: `.py`, `Dockerfile`, `.tf`, `.env`, and so on. A `.json` file is treated as an n8n workflow when it has a `nodes` array.
  - The file is then scanned straight away.
  - Binary files and files over 2 MB are rejected before upload.
- **Line numbers:** for code, line numbers are those of your file. n8n workflows are formatted first (2-space JSON) so that lines map to nodes.
- **Scan mode:**
  - **All checks** runs every rule.
  - **Credentials only** reports just leaked secrets: hardcoded passwords, tokens, API keys, Bearer/Basic values, connection-string passwords and credentials in URLs.

  Pick the mode before you upload or scan.

## The report

| Section | What it tells you |
|---|---|
| **Overall risk** | A verdict (Critical / High / Moderate / Low / No issues) and what to do before deploying |
| **Severity tiles** | Counts per severity; click one to filter the findings |
| **Fix these first** | The top 5 critical / high issues; click one to jump to it |
| **Risk by area** | Secrets, AI agents, Outlook/Teams/monday.com, injection, …; click one to filter |
| **Where your data goes** *(n8n only)* | A compact map: *Data comes from* on one side and *Data goes to* on the other, one chip per service (LLM providers marked **AI**, a count when several nodes use the same service; hover for node names). The full node-by-node table is under *Show all N connections* |
| **Hidden by tuning policy** | Findings suppressed by `TRUSTED_NETWORKS` / `TRUST_FORM_TRIGGERS`, each with its reason (collapsed; also included in HTML, Markdown and PDF) |
| **All findings** | Grouped by area, severity or node (n8n). Each one has *What's wrong* and *How to fix*, plus technical details: masked code excerpt, line numbers, rule id, CWE / OWASP. Secret findings also show the **Exposed value**: the exact hardcoded password, token, header value, connection-string password or URL |

### PDF report

**Download PDF** gives a printable report of the findings only. It never includes the scanned workflow, the source code or code excerpts.

- **Page 1:** the overall verdict, severity counts and an *At a glance* table (#, severity, issue, node or area, line).
- **Then one section per severity**, in the order Critical, High, Medium, Low. Each finding is a card with:
  - a colour-coded **severity** badge and stripe
  - the **error title** and the **line number(s)** it comes from, plus the node name (n8n) or file name (code)
  - **In brief:** what's wrong in one plain-English sentence
  - **How to fix**, in a green box
  - the **Exposed value**, only if *Include exposed values in downloads* is ticked
- **Every page** has a header, a footer and *Page X of Y*.

The server scans the file again to build the PDF (`POST /api/report.pdf`), so the report always matches the rules rather than anything the browser sends.

### Other downloads

Downloads leave out exposed values unless you tick **Include exposed values in downloads**, so a report can be shared without spreading the secrets. When you tick it, the report carries a warning.

**Download report (HTML)** saves a self-contained, printable page with no scripts or external assets, so you can attach it to a ticket or print it to PDF. **Markdown** is for pasting into GitHub, Jira or Confluence, and **JSON** is the raw API response.

## API

`GET /api/languages` lists the supported languages: id, label, group, file extensions and names, rule count and sample file.

`POST /api/scan` with `Content-Type: application/json`:

```json
{ "content": "import os\nos.system(cmd)\n", "language": "python", "filename": "app.py", "profile": "full" }
```

- `language` is an id from `/api/languages` (`n8n`, `python`, `javascript`, `typescript`, `java`, `go`, `csharp`, `php`, `ruby`, `bash`, `dockerfile`, `yaml`, `terraform`, `generic`). It defaults to `n8n`.
- `filename` is optional. Only its extension is used (for example `.tsx` vs `.ts`), and it is shown in reports; it is never used as a path.
- `profile` is optional: `"full"` (default) or `"credentials"` (only findings whose rule has `metadata.category: secrets`).
- The original n8n form `{"workflow": "<json>"}` still works.

The response contains `language`, `target_name` (file or workflow name), `line_count`, `node_count` (n8n only), `summary` (counts per severity), `findings[]` and `data_flows[]` (n8n only; empty in credentials mode). Each finding has `rule_id`, `title`, `brief` (one sentence), `risk`, `category`, `message`, `remediation`, `cwe`, `owasp`, `node_name`, `start_line`/`end_line`, `snippet`, `exposed_value` (secrets only, unmasked) and `source`. `source` is `semgrep` for pattern rules or `workflow-graph` for connection checks; for connection checks, `snippet` lists the evidence. For code, line numbers are those of the submitted file. For n8n, they refer to the workflow pretty-printed with a 2-space indent; the UI reformats the editor to that layout, so **Line N** links jump to the right place.

| Status | Meaning |
|---|---|
| 413 | Body larger than `MAX_PAYLOAD_BYTES` |
| 415 | Not `application/json` |
| 422 | Invalid request, unknown language, binary content, or invalid n8n JSON |
| 429 | All scan slots busy (`Retry-After: 5`) |
| 504 | Semgrep exceeded `SCAN_TIMEOUT_SECONDS` |

`POST /api/report.pdf` takes the same body plus an optional `"include_secrets": true` and returns the PDF report as an attachment.

`GET /api/health` returns the Semgrep version, the number of rules loaded and the number of languages.

## Rules

### Source code and infrastructure

Each language runs its own rule file in `rules/code/` plus the shared secret rules in `rules/common/`. Config-style formats (shell, YAML and other text) also get `config-secrets.yml`, which catches unquoted values such as `PASSWORD=abc`.

| Language | Rules | Detects |
|---|---|---|
| All code / config | `common/secrets.yml` | Known provider keys (AWS, GitHub, GitLab, Slack, Stripe, OpenAI / Anthropic, Google, SendGrid, npm), private keys, JWTs, Slack / Teams webhooks, `password = "…"`-style literals, `Password=…;` connection strings, credentials in URLs |
| Python | `code/python.yml` | `os.system` / `shell=True` injection, SQL built with `%` / f-strings / `+`, `eval` / `exec`, pickle / unsafe YAML, `verify=False`, JWT without signature check, MD5 / SHA-1, debug mode, `tempfile.mktemp` |
| JavaScript / TypeScript | `code/javascript.yml` | `child_process.exec` injection, SQL via concatenation / template literals, `eval` / `new Function`, `rejectUnauthorized: false`, `innerHTML` / `dangerouslySetInnerHTML`, hardcoded JWT secret, MD5 / SHA-1, CORS `*`, node-serialize |
| Java | `code/java.yml` | `Runtime.exec` / `sh -c` injection, JDBC / JPA string concatenation, `ObjectInputStream` / `XMLDecoder`, trust-all TrustManager / hostname verifier, MD5 / SHA-1 / DES / ECB, Spring CSRF disabled |
| Go | `code/go.yml` | `sh -c` injection, `fmt.Sprintf` SQL, `InsecureSkipVerify`, MD5 / SHA-1, `template.HTML` |
| C# | `code/csharp.yml` | `Process.Start` injection, `SqlCommand` / `FromSqlRaw` concatenation and interpolation, `BinaryFormatter` / `TypeNameHandling`, certificate validation bypass, MD5 / SHA-1 / DES |
| PHP | `code/php.yml` | `exec` / `system` / `shell_exec` injection, `eval`, `mysqli_query` concatenation, `unserialize`, file inclusion from request, unescaped `echo $_GET`, cURL without SSL verify, `md5` / `sha1` |
| Ruby | `code/ruby.yml` | `system` / backtick injection, `eval`, interpolated ActiveRecord SQL, `Marshal.load` / unsafe YAML, `VERIFY_NONE`, MD5 / SHA-1, `params.permit!` |
| Shell | `code/bash.yml` | `curl … \| sh`, `curl -k` / `--no-check-certificate`, `eval "$var"`, `chmod 777` |
| Dockerfile | `code/dockerfile.yml` | No `USER` / `USER root`, secrets in `ENV` / `ARG`, `:latest`, `curl \| sh` in `RUN`, `ADD` from a URL |
| YAML | `code/yaml.yml` | Privileged containers, host network / PID / IPC, root or privilege escalation, Docker socket mounts, GitHub Actions script injection and `write-all` permissions |
| Terraform | `code/terraform.yml` | Public buckets, `0.0.0.0/0` ingress, wildcard IAM actions, publicly accessible databases, encryption disabled |

Every language has an intentionally vulnerable sample in `app/static/samples/code/` and a safe counterpart in `tests/fixtures/safe/`. `tests/test_languages.py` checks that every rule fires on the sample and that nothing fires on the safe file. When you add a rule, add a case to both. Naming and metadata conventions are in `rules/README.md`.

These rules are pattern based: they flag risky code, they don't trace whether the data really comes from a user. Treat a finding as "review this line", not as proof of an exploit.

### n8n: secrets, injection and configuration

| Rule | Risk | Detects |
|---|---|---|
| `n8n-known-secret-format` | critical | AWS/GitHub/Slack/Stripe/OpenAI/Google/GitLab keys, JWTs, private keys |
| `n8n-command-injection-via-expression` | critical | `{{ }}` expressions inside Execute Command / SSH commands |
| `n8n-hardcoded-secret-parameter` | high | literal values in any parameter whose name contains password/pass/pwd/secret/token/api key/credential (`dbPassword`, `smtp_pass`, `x_api_key`, …) |
| `n8n-hardcoded-secret-name-value-pair` | high | literal header / query / body / Set-node fields such as `Authorization`, `X-Shopify-Access-Token`, `adminPassword`, `Cookie` |
| `n8n-hardcoded-secret-in-code-or-body` | high | `password = '…'` / `apiKey: "…"` in Code nodes, passwords inside escaped JSON bodies, `Password=…;` connection strings |
| `n8n-literal-authorization-token` | high | literal `Bearer …` / `Basic …` values anywhere |
| `n8n-credentials-in-url` | high | real-looking credentials in URLs: `scheme://user:pass@host`, or `?password=` / `?api_key=` / `?token=` values of 8+ characters with letters and digits. Placeholders are ignored |
| `n8n-tls-verification-disabled` | high | `allowUnauthorizedCerts`, `ignoreSSLIssues`, `rejectUnauthorized: false`, `ssl: disable` |
| `n8n-code-node-dangerous-api` | high | `eval`, `new Function`, `child_process`, `process.env`, `os.system`, … in Code/Function nodes |
| `n8n-sql-injection-via-expression` | high | SQL statements built with `{{ }}`, unless every expression is a report-window / date value |
| `n8n-webhook-without-authentication` | medium | Webhook / Form trigger with no or `none` authentication |
| `n8n-webhook-permissive-cors` | medium | `allowedOrigins: "*"` |
| `n8n-cleartext-http-url` | medium | `http://` endpoints on public hosts |
| `n8n-cleartext-http-internal` | low | `http://` to private IPs (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16), single-label service names (`http://gotenberg:3000`) and internal DNS (`.local`, `.internal`, `.lan`, `.corp`, `.svc`, `.cluster.local`) |
| `n8n-execute-command-node` | medium | any Execute Command node |
| `n8n-teams-webhook-url-exposed` | high | Teams incoming-webhook / Power Automate workflow URLs (the URL is the credential) |

### n8n: AI agents

The checks marked *graph* follow the workflow's connections (in `app/scanning/graph.py`) rather than matching a single node. An agent's **untrusted input** is any of these:

- an unauthenticated webhook, form, chat or MCP trigger upstream
- an Outlook / Teams / Gmail / Slack trigger upstream
- a tool that reads emails or chat messages

| Check | Risk | Detects |
|---|---|---|
| `n8n-ai-prompt-injection-exfiltration` *(graph)* | critical | Agent with untrusted input **and** a private-data tool (Outlook / Teams / monday.com read, database, vector store, sub-workflow) **and** an outbound tool (send email, post to Teams, write to monday.com, HTTP, code): prompt injection can make it leak data. This combination is known as the "lethal trifecta". |
| `n8n-ai-untrusted-input-outbound-actions` *(graph)* | high | Agent with untrusted input and outbound tools, but no private-data tool |
| `n8n-ai-private-data-to-public-users` *(graph)* | high | Agent reachable without authentication whose tools read private data and whose reply goes back to the caller |
| `n8n-ai-tool-model-controlled-url` | high | HTTP tool whose host comes from `$fromAI()` / `{placeholder}` |
| `n8n-ai-tool-model-chosen-recipient` | high | Outlook / Teams / monday.com / Gmail / Slack tool whose recipient, chat, channel or board comes from `$fromAI()` |
| `n8n-ai-prompt-contains-env-secret` | high | `$env` used in a system prompt or prompt text |
| `n8n-ai-chat-public-without-auth` | high | Public chat trigger with no authentication |
| `n8n-ai-mcp-server-without-auth` | high | MCP Server Trigger with no authentication |
| `n8n-ai-shared-conversation-memory` | high | Chat memory with a fixed session key, so all users share one history |
| `n8n-ai-tool-destructive-operation` | medium | Agent tool that deletes, archives or moves data |
| `n8n-ai-intermediate-steps-exposed` | low | `returnIntermediateSteps` returns raw tool output |

### n8n: Microsoft Outlook, Teams and monday.com

| Check | Risk | Detects |
|---|---|---|
| `n8n-endpoint-returns-internal-data` *(graph)* | high | Unauthenticated webhook that reads Outlook / Teams / monday.com data and returns it to the caller |
| `n8n-endpoint-writes-business-systems` *(graph)* | medium | Unauthenticated webhook / form whose input is written to Outlook, Teams or monday.com (spam, phishing from your tenant, data pollution) |
| `n8n-email-hidden-bcc` | medium | Outlook / Gmail / SMTP mail with a BCC recipient |
| `n8n-email-recipient-from-request` | medium | Email recipient taken from webhook or form input |
| `n8n-bulk-record-forwarded` | medium | `JSON.stringify($json)`, `{{ $json }}` or `$input.all()` posted to Teams, Outlook, monday.com, Slack or HTTP |

The rule ids and parameter names follow n8n's Outlook v2, Teams v2, monday.com v1 and AI Agent (LangChain) nodes. Older node versions may use different parameter names; if a known issue in your workflows isn't flagged, send a sanitised export so a case can be added.

### n8n: tuning decisions

These adjustments were agreed after scanning real workflows. `tests/fixtures/tuning-cases.json` and `test_rule_tuning_decisions` keep them in place.

| Finding | Decision | How it's implemented |
|---|---|---|
| SQL injection via expression | Report-window / date parameters in queries are trusted | A query is still flagged if **any** `{{ }}` expression is something other than a date or window value: `reportStartDate` / `reportEndDate`, `start_date`, `end_date`, `from_date`, `to_date`, `date_from` / `date_to`, `window_start` / `window_end`, `period_start` / `period_end`, `$now`, `$today` or `DateTime.` |
| Credentials in URL | Only real-looking secrets count | Ignored: placeholders (`your-…`, `example`, `test`, `dummy`, `changeme`, `REPLACE_ME`, `<API_KEY>`, `{TOKEN}`, `xxx`, …), expressions and empty values. A query-string value must be at least 8 characters and contain both letters and digits |
| Pinned execution data | Not significant | Rule removed |
| Clear-text HTTP | Internal traffic is low risk; trusted subnets are fully accepted | Private and internal hosts are moved to the low-risk `n8n-cleartext-http-internal` rule; public `http://` stays medium. Calls into `TRUSTED_NETWORKS` (default `10.0.12.0/24`) are suppressed by the policy |
| Unauthenticated Form Triggers | Form Triggers (e.g. *Upload 500 Subscribers*) are secured by our internal submission flow | With `TRUST_FORM_TRIGGERS=true` (default), Form Triggers are not reported by `n8n-webhook-without-authentication`, and the workflow analysis does not treat them as anonymous entry points. Webhooks and public chat triggers are still checked |
| Bulk reads (`returnAll`) | Intentional for processing incoming items and emails | Rule removed |
| Risky API in Code node | Text-parsing code (e.g. *Regex Extraction1*) is safe | `n8n-code-node-dangerous-api` matches `exec(` only as a standalone call (Python `exec`), not JavaScript's `regex.exec(text)`. `eval`, `new Function`, `child_process`, `process.env` and similar are still flagged |

Notes:
- **Date parameters:** an expression counts as a date value from its name, not its contents. If a "date" field could be set by an outside caller (for example a webhook body), validate it before the query (an IF node or a `DateTime` parse) or bind it with query parameters.
- **Suppressions are visible:** anything the policy hides is listed under *Hidden by tuning policy* in the UI and in every export.
- **Changing the policy:** set `TRUSTED_NETWORKS` to an empty string to report every internal HTTP call, or `TRUST_FORM_TRIGGERS=false` to check Form Triggers again.
- **Code files:** the shared credentials-in-URL rule for code files (`rules/common/secrets.yml`) uses the same placeholder handling.

### n8n: notes on the secrets rules

All the rules in the `secrets` category skip the following, so they aren't reported. These are `n8n-known-secret-format`, `n8n-hardcoded-secret-*`, `n8n-literal-authorization-token`, `n8n-credentials-in-url` and `n8n-teams-webhook-url-exposed`.

- n8n expressions (`={{ $env.X }}`, `={{ $json.x }}`)
- empty values and placeholders (`YOUR_API_KEY`, `<token>`, `xxx`)
- option names that only describe auth (`authentication`, `tokenType`, `accessTokenUrl`, `secretName`, …)

Credentials stored in n8n's credential store never appear in a workflow export; only their id and name do, so they are not reported. When one secret matches several rules, it is reported once.

`tests/fixtures/credential-cases.json` holds the positive and negative cases these rules are tuned against. Add a case there whenever you change a secrets rule.

To add a rule, add an entry to the right file under `rules/` with `metadata.title`, `brief`, `risk`, `category` and `remediation`, then add a case to the sample and tests. Two things about Semgrep's JSON support (n8n rules) are easy to get wrong:

- A metavariable bound to a JSON key includes the quotes.
- `metavariable-regex` only matches from the start of the value, so use `(?s).*foo` to find `foo` anywhere in it.

## Security design

- **Input handling:** the body size is capped while it streams in, before any parsing. Binary content and unknown languages are rejected. n8n JSON is parsed strictly (no `NaN`, depth-guarded, must contain a `nodes` array) and re-serialized, so Semgrep only ever sees well-formed JSON. Source files are scanned byte-for-byte with their own line endings.
- **Temporary files:** each scan writes to its own `mkdtemp` directory (0700) as a 0600 file opened with `O_EXCL`. The file name is chosen by the server (for example `source.py`); the uploaded name is never used as a path. The directory is deleted when the scan ends, whether it succeeds, fails or times out.
- **Running Semgrep:**
  - Semgrep is started with a fixed argument list and no shell.
  - Only local rules are used: no registry fetches, metrics are off and version checks are disabled, so workflow content never leaves the host.
  - Semgrep gets a minimal environment with a throwaway `HOME`.
  - It runs in its own process group, so a timeout kills `semgrep-core` too.
  - There is a per-rule timeout and a wall-clock timeout.
  - Concurrency is limited by a semaphore, and extra requests get a 429.
- **Output:**
  - For secret findings, the API returns the exact leaked value in `exposed_value` to the browser that submitted the workflow. It is never logged or stored, and downloads omit it unless the user opts in.
  - Code snippets stay masked. At most the first 4 characters are shown, short values are fully hidden, and URLs keep everything except the credential, for example `"P@ss*********"`, `"*****"`, `https://admin:****@host`, `?api_key=****` and `/webhookb2/****`.
  - Downloaded HTML reports contain no scripts, and every value in them is HTML-escaped.
  - API responses are sent with `Cache-Control: no-store`.
  - Workflow content is never logged.
  - Internal errors return a generic message.
- **Browser:**
  - Responses carry CSP, `X-Frame-Options: DENY`, `nosniff` and `no-referrer` headers.
  - The page and its script are sent with `Cache-Control: no-cache`, so browsers check for a newer version on every load (a cheap 304 when nothing changed) and never mix an old `app.js` with a new page after an upgrade.
  - The UI inserts all scan data with `textContent`, never `innerHTML`.
- **Container:**
  - The app runs as a non-root user (UID 10001) on a read-only root filesystem.
  - `/tmp` is the only writable path (tmpfs).
  - All capabilities are dropped and `no-new-privileges` is set.
  - There are memory, CPU and PID limits.
  - The port is published on `127.0.0.1` only.

## Before exposing this to a team or the internet

1. Put it behind a reverse proxy with TLS and SSO (for example oauth2-proxy, Cloudflare Access or an ALB with OIDC). The app has no authentication of its own, and users paste workflows that may contain live secrets.
2. Build the Tailwind CSS with the Tailwind CLI and drop `https://cdn.tailwindcss.com` and `'unsafe-inline'` from the CSP in `app/main.py`.
3. Pin the base image by digest, and run the container without outbound network access; Semgrep doesn't need it.
4. On ECS, Cloud Run or Kubernetes, apply the same settings as the compose file: read-only root filesystem, tmpfs or emptyDir on `/tmp`, non-root user, no capabilities.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MAX_PAYLOAD_BYTES` | 2000000 | Request body cap |
| `SCAN_TIMEOUT_SECONDS` | 60 | Wall-clock limit for one scan |
| `SEMGREP_RULE_TIMEOUT` | 20 | Semgrep per-rule timeout |
| `MAX_CONCURRENT_SCANS` | 4 | Parallel scans per worker |
| `SCAN_QUEUE_WAIT_SECONDS` | 10 | Wait for a free slot before 429 |
| `WEB_CONCURRENCY` | 2 | Uvicorn workers |
| `SEMGREP_RULES_PATH` | `./rules` | Rule file or directory |
| `SEMGREP_BIN` | `semgrep` | Semgrep executable |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allow-list; empty = same-origin only |
| `ENABLE_DOCS` | false | Expose `/docs` (Swagger UI) |
| `TRUSTED_NETWORKS` | `10.0.12.0/24` | Comma-separated CIDRs where plain HTTP is accepted (tuning policy). Empty = none |
| `TRUST_FORM_TRIGGERS` | true | Don't report n8n Form Triggers as unauthenticated endpoints |

The static UI assumes the default 2 MB limit (`MAX_BYTES` in `app/static/app.js`); keep it in sync if you change `MAX_PAYLOAD_BYTES`.
