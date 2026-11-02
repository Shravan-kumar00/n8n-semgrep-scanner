# n8n Workflow Security Scanner

Paste an n8n workflow export into a web UI and scan it with Semgrep. The scanner looks for hardcoded secrets, command and SQL injection through expressions, risky Code-node APIs, disabled TLS verification and unauthenticated webhooks. Each finding shows its severity, the node it was found in, the matching lines and how to fix it.

```
n8n-semgrep-scanner/
├── app/
│   ├── __init__.py
│   ├── config.py        # env-driven settings (limits, timeouts, paths)
│   ├── models.py        # Pydantic request/response schemas
│   ├── workflow.py      # JSON validation, normalization, line -> node index
│   ├── scanner.py       # temp file handling, semgrep subprocess, result parsing
│   └── main.py          # FastAPI app, routes, body-size limit, security headers
├── rules/
│   └── n8n-security.yml # 14 Semgrep rules for n8n workflow JSON
├── static/
│   ├── index.html       # Tailwind single-page UI
│   ├── app.js           # async submit + safe DOM rendering
│   └── samples/vulnerable-workflow.json
├── tests/
│   ├── test_workflow.py # parser/normalizer unit tests
│   └── test_api.py      # end-to-end tests against real semgrep
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```

## Run

**Docker (recommended)**

```bash
docker compose up --build -d
```

Open http://localhost:8000 and click **Load sample** → **Scan Workflow**.

**Local (Python 3.10+)**

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest
```

## API

`POST /api/scan` with `Content-Type: application/json`:

```json
{ "workflow": "{\"name\":\"My flow\",\"nodes\":[...],\"connections\":{}}" }
```

The response contains `summary` (counts per severity) and `findings[]`. Each finding has `rule_id`, `title`, `risk`, `message`, `remediation`, `cwe`, `node_name`, `start_line`/`end_line` and `snippet`. Line numbers refer to the workflow pretty-printed with a 2-space indent; the UI reformats the text area to that layout, so **Line N** links jump to the right place.

| Status | Meaning |
|---|---|
| 413 | Body larger than `MAX_PAYLOAD_BYTES` |
| 415 | Not `application/json` |
| 422 | Invalid JSON / not an n8n workflow |
| 429 | All scan slots busy (`Retry-After: 5`) |
| 504 | Semgrep exceeded `SCAN_TIMEOUT_SECONDS` |

`GET /api/health` returns the Semgrep version and the number of rules loaded.

## Rules

| Rule | Risk | Detects |
|---|---|---|
| `n8n-known-secret-format` | critical | AWS/GitHub/Slack/Stripe/OpenAI/Google/GitLab keys, JWTs, private keys |
| `n8n-command-injection-via-expression` | critical | `{{ }}` expressions inside Execute Command / SSH commands |
| `n8n-hardcoded-secret-parameter` | high | literal `password`, `apiKey`, `token`, … parameters |
| `n8n-hardcoded-secret-name-value-pair` | high | literal `Authorization` / `X-API-Key` headers, Set-node fields |
| `n8n-credentials-in-url` | high | `scheme://user:pass@host` |
| `n8n-tls-verification-disabled` | high | `allowUnauthorizedCerts`, `ignoreSSLIssues`, `rejectUnauthorized: false`, `ssl: disable` |
| `n8n-code-node-dangerous-api` | high | `eval`, `new Function`, `child_process`, `process.env`, `os.system`, … in Code/Function nodes |
| `n8n-sql-injection-via-expression` | high | SQL statements built with `{{ }}` |
| `n8n-webhook-without-authentication` | medium | Webhook / Form trigger with no or `none` authentication |
| `n8n-webhook-permissive-cors` | medium | `allowedOrigins: "*"` |
| `n8n-cleartext-http-url` | medium | non-local `http://` endpoints |
| `n8n-execute-command-node` | medium | any Execute Command node |
| `n8n-pinned-data-exported` | low | `pinData` included in the export |
| `n8n-code-node-present` | info | Code/Function nodes that need review |

Values that are n8n expressions (strings starting with `=`) are not reported as hardcoded secrets.

To add a rule, add an entry to `rules/n8n-security.yml` with `metadata.title`, `risk`, `category` and `remediation`, then add a case to the sample or tests. Two things about Semgrep's JSON support are easy to get wrong:

- A metavariable bound to a JSON key includes the quotes.
- `metavariable-regex` only matches from the start of the value, so use `(?s).*foo` to find `foo` anywhere in it.

## Security design

- **Input handling:** the body size is capped while it streams in, before any parsing. The JSON is parsed strictly (no `NaN`, depth-guarded, must contain a `nodes` array) and re-serialized, so Semgrep only ever sees well-formed JSON.
- **Temporary files:** each scan writes to its own `mkdtemp` directory (0700) as a 0600 file opened with `O_EXCL`. The directory is deleted when the scan ends, whether it succeeds, fails or times out.
- **Running Semgrep:**
  - Semgrep is started with a fixed argument list and no shell.
  - Only local rules are used: no registry fetches, metrics are off and version checks are disabled, so workflow content never leaves the host.
  - Semgrep gets a minimal environment with a throwaway `HOME`.
  - It runs in its own process group, so a timeout kills `semgrep-core` too.
  - There is a per-rule timeout and a wall-clock timeout.
  - Concurrency is limited by a semaphore, and extra requests get a 429.
- **Output:**
  - Secret values are masked in returned snippets, for example `"P@ss*********"` and `https://admin:****@host`.
  - API responses are sent with `Cache-Control: no-store`.
  - Workflow content is never logged.
  - Internal errors return a generic message.
- **Browser:**
  - Responses carry CSP, `X-Frame-Options: DENY`, `nosniff` and `no-referrer` headers.
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

The static UI assumes the default 2 MB limit (`MAX_BYTES` in `static/app.js`); keep it in sync if you change `MAX_PAYLOAD_BYTES`.
