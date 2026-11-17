# Semgrep rules

All rules are local YAML files; nothing is fetched from the Semgrep registry.
Which files run for which language is defined in `app/scanning/languages.py`.

```
rules/
├── n8n/workflow.yml          # n8n workflow export (JSON)
├── code/<language>.yml       # one file per language: python, javascript (JS + TS), java,
│                             # go, csharp, php, ruby, bash, dockerfile, yaml, terraform
└── common/
    ├── secrets.yml           # secret detection for every code / config language
    └── config-secrets.yml    # unquoted KEY=value secrets (shell, YAML, .env, other text)
```

## Conventions

- **File names:** lower-case, one file per language or topic, `.yml`.
- **Rule ids:** prefixed by scope, kebab-case:
  - `n8n-…` for workflows
  - `python-…`, `js-…`, `java-…`, `go-…`, `csharp-…`, `php-…`, `ruby-…`, `bash-…`, `dockerfile-…`, `k8s-…` / `github-actions-…`, `terraform-…` for code
  - no prefix for shared rules in `common/`
- **Metadata:** every rule needs these fields, which the API, UI and PDF rely on:

  | Field | Meaning |
  |---|---|
  | `title` | Short headline shown on the finding |
  | `brief` | One plain-English sentence (used in the PDF) |
  | `risk` | `critical`, `high`, `medium`, `low` or `info` |
  | `category` | `secrets`, `injection`, `code-execution`, `crypto`, `transport`, `configuration`, `access-control`, `ai-agent` or `integrations` |
  | `cwe`, `owasp` | References, where applicable |
  | `remediation` | How to fix it |

  The `secrets` category drives the *Credentials only* scan mode.
- **Tests:** every rule must fire on its language's sample in `app/static/samples/` and must not fire on `tests/fixtures/safe/`. Both are checked by `tests/test_languages.py` (code) and `tests/test_api.py` (n8n).

## Tuning

Rule files hold general patterns. Decisions specific to our environment are handled in two places:

- **In the rules**, for pattern-level choices: trusted SQL date parameters, URL placeholders, and the internal vs public HTTP split.
- **In `app/scanning/policy.py`**, for decisions that depend on configuration: trusted subnets (`TRUSTED_NETWORKS`), trusted Form Triggers (`TRUST_FORM_TRIGGERS`) and rules switched off entirely (`DISABLED_RULES`).

Policy suppressions are listed in the report under *Hidden by tuning policy*, so they are never silent. The agreed decisions are listed in the main README under *Tuning decisions*.
