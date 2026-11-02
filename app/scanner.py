"""Semgrep execution and result parsing.

Security properties of a scan:
  * The workflow is written to a private temp dir (0700) as a 0600 file and the
    whole directory is deleted when the scan finishes, success or failure.
  * Semgrep is invoked with an argument list (never a shell), local rules only,
    metrics and version checks disabled, and a minimal environment.
  * The process runs in its own process group so a timeout kills Semgrep and
    every helper it spawned (semgrep-core).
  * Concurrency is bounded per worker; excess requests are rejected with 429.
  * Workflow contents are never logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import tempfile
import textwrap
import time
import uuid
from pathlib import Path
from typing import Any

from .config import Settings
from .graph import analyze_workflow
from .models import RISK_ORDER, Finding, ScanProfile, ScanResponse, ScanSummary
from .workflow import NormalizedWorkflow

logger = logging.getLogger(__name__)

SECRETS_CATEGORY = "secrets"  # rules in this category form the "credentials" profile
TARGET_FILENAME = "workflow.json"  # .json extension -> Semgrep's JSON parser
MAX_SNIPPET_LINES = 15
MAX_SNIPPET_LINE_CHARS = 300
MAX_WARNINGS = 20

# Fallback when a rule lacks metadata.risk.
_SEVERITY_TO_RISK = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


class ScanError(RuntimeError):
    """Semgrep failed. The message is safe to show to users."""


class ScanTimeoutError(ScanError):
    pass


class ScannerBusyError(ScanError):
    pass


class SemgrepScanner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._slots = asyncio.Semaphore(settings.max_concurrent_scans)
        self.version: str = "unknown"

    # ------------------------------------------------------------------ setup
    def check_installation(self) -> None:
        """Fail fast at startup if semgrep or the rules are missing."""
        if not self.settings.rules_path.exists():
            raise RuntimeError(f"Semgrep rules not found at {self.settings.rules_path}")
        try:
            proc = subprocess.run(
                [self.settings.semgrep_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                env=self._base_env(Path(tempfile.gettempdir())),
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Unable to run semgrep ({self.settings.semgrep_bin}): {exc}") from exc
        self.version = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "unknown"

    def count_rules(self) -> int:
        path = self.settings.rules_path
        files = [path] if path.is_file() else [*path.rglob("*.yml"), *path.rglob("*.yaml")]
        pattern = re.compile(r"^\s*-\s+id:\s*\S", re.MULTILINE)
        return sum(len(pattern.findall(f.read_text(encoding="utf-8"))) for f in files)

    # ------------------------------------------------------------------- scan
    async def scan(self, workflow: NormalizedWorkflow, profile: ScanProfile = "full") -> ScanResponse:
        """Scan a normalized workflow. Raises ScanError subclasses on failure.

        profile="credentials" reports only rules with metadata.category
        "secrets" (hardcoded passwords, tokens, keys, credentials in URLs).
        """
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=self.settings.queue_wait_seconds)
        except asyncio.TimeoutError:
            raise ScannerBusyError("Scanner is busy, please retry in a few seconds.") from None

        scan_id = uuid.uuid4().hex
        started = time.monotonic()
        try:
            raw = await asyncio.to_thread(self._scan_in_tempdir, workflow.text, scan_id)
        finally:
            self._slots.release()

        findings, warnings = self._parse_results(raw, workflow)
        if profile == "credentials":
            findings = [f for f in findings if f.category == SECRETS_CATEGORY]
            data_flows = []
        else:
            graph_findings, data_flows = analyze_workflow(workflow)
            findings = sorted(
                findings + graph_findings,
                key=lambda f: (RISK_ORDER.index(f.risk), f.start_line, f.rule_id),
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info("scan %s (%s) finished: %d findings in %d ms", scan_id, profile, len(findings), duration_ms)

        return ScanResponse(
            scan_id=scan_id,
            profile=profile,
            workflow_name=workflow.name,
            node_count=workflow.node_count,
            duration_ms=duration_ms,
            semgrep_version=self.version,
            summary=_summarize(findings),
            findings=findings,
            data_flows=data_flows,
            warnings=warnings,
        )

    def _scan_in_tempdir(self, text: str, scan_id: str) -> dict[str, Any]:
        # mkdtemp creates the directory with mode 0700; it is removed on exit
        # from the `with` block even if semgrep fails or times out.
        with tempfile.TemporaryDirectory(prefix=f"n8n-scan-{scan_id[:8]}-") as tmp:
            tmp_path = Path(tmp)
            target_dir = tmp_path / "target"
            home_dir = tmp_path / "home"  # semgrep writes ~/.semgrep here, not in the image
            target_dir.mkdir(mode=0o700)
            home_dir.mkdir(mode=0o700)

            target = target_dir / TARGET_FILENAME
            # O_EXCL: fail rather than follow a pre-existing file/symlink.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)

            return self._run_semgrep(target, home_dir)

    def _run_semgrep(self, target: Path, home_dir: Path) -> dict[str, Any]:
        s = self.settings
        cmd = [
            s.semgrep_bin,
            "scan",
            "--config", str(s.rules_path),
            "--json",
            "--quiet",
            "--metrics", "off",
            "--disable-version-check",
            "--no-git-ignore",
            "--jobs", "1",
            "--timeout", str(s.rule_timeout_seconds),
            "--max-target-bytes", str(s.max_payload_bytes * 4),  # normalized text can grow
            str(target),
        ]
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            cmd,
            cwd=target.parent,
            env=self._base_env(home_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # own process group -> killable as a unit
        )
        try:
            stdout, stderr = proc.communicate(timeout=s.scan_timeout_seconds)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            proc.communicate()
            logger.warning("semgrep timed out after %ss", s.scan_timeout_seconds)
            raise ScanTimeoutError(
                f"Scan exceeded the {s.scan_timeout_seconds}s time limit."
            ) from None

        try:
            data = json.loads(stdout) if stdout.strip() else None
        except json.JSONDecodeError:
            data = None

        if not isinstance(data, dict) or "results" not in data:
            logger.error("semgrep exited %s without JSON output: %s", proc.returncode, stderr[-2000:])
            raise ScanError("The scanning engine failed to produce a result.")

        # Exit codes: 0 = ok, 1 = findings with --error (unused). Anything else
        # is acceptable only if every reported error is non-fatal.
        fatal = [e for e in data.get("errors", []) if e.get("level") == "error"]
        if proc.returncode not in (0, 1) and fatal:
            logger.error("semgrep exited %s: %s", proc.returncode, json.dumps(fatal)[:2000])
            raise ScanError("The scanning engine reported an error. Check server logs for details.")
        return data

    @staticmethod
    def _base_env(home_dir: Path) -> dict[str, str]:
        """Minimal environment: nothing from the API process leaks to semgrep."""
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(home_dir),
            "XDG_CONFIG_HOME": str(home_dir / ".config"),
            "XDG_CACHE_HOME": str(home_dir / ".cache"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_FORCE_COLOR": "0",
        }

    # ---------------------------------------------------------------- parsing
    def _parse_results(
        self, data: dict[str, Any], workflow: NormalizedWorkflow
    ) -> tuple[list[Finding], list[str]]:
        lines = workflow.text.splitlines()
        raw_bytes = workflow.text.encode("utf-8")  # semgrep offsets are byte offsets
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()

        for result in data.get("results", []):
            try:
                finding = _to_finding(result, lines, raw_bytes, workflow)
            except (KeyError, TypeError, ValueError):
                logger.exception("skipping malformed semgrep result")
                continue
            key = (finding.rule_id, finding.start_line, finding.end_line)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

        findings = _drop_nested_secret_findings(findings)
        findings.sort(key=lambda f: (RISK_ORDER.index(f.risk), f.start_line, f.rule_id))

        warnings = []
        for err in data.get("errors", [])[:MAX_WARNINGS]:
            message = str(err.get("message", "unknown error"))
            # Don't expose server temp paths to the client.
            message = re.sub(r"/\S*/" + re.escape(TARGET_FILENAME), TARGET_FILENAME, message)
            warnings.append(f"{err.get('type', 'Error')}: {message[:300]}")
        return findings, warnings


# ---------------------------------------------------------------------- helpers
def _drop_nested_secret_findings(findings: list[Finding]) -> list[Finding]:
    """Report one leaked secret once.

    Several secret rules can fire on the same value, e.g. the name/value rule
    matches a whole {"name": "Authorization", "value": "Basic ..."} object
    while the Bearer/Basic rule matches the value line inside it. A secrets
    finding is dropped when another secrets finding of equal or higher risk
    covers a strictly larger line range around it.
    """
    secrets = [f for f in findings if f.category == SECRETS_CATEGORY]

    def covered(inner: Finding) -> bool:
        return any(
            outer is not inner
            and outer.start_line <= inner.start_line
            and inner.end_line <= outer.end_line
            and (outer.end_line - outer.start_line) > (inner.end_line - inner.start_line)
            and RISK_ORDER.index(outer.risk) <= RISK_ORDER.index(inner.risk)
            for outer in secrets
        )

    return [f for f in findings if f.category != SECRETS_CATEGORY or not covered(f)]


def _to_finding(
    result: dict[str, Any], lines: list[str], raw_bytes: bytes, workflow: NormalizedWorkflow
) -> Finding:
    extra = result.get("extra", {})
    meta = extra.get("metadata", {}) or {}
    start = int(result["start"]["line"])
    end = int(result["end"]["line"])

    risk = str(meta.get("risk", "")).lower()
    if risk not in RISK_ORDER:
        risk = _SEVERITY_TO_RISK.get(str(extra.get("severity", "")).upper(), "medium")

    category = str(meta.get("category", "general"))
    snippet = _snippet(lines, start, end)
    exposed_value = None
    if category == SECRETS_CATEGORY:
        snippet = _mask_secrets(snippet)
        exposed_value = _exposed_value(raw_bytes, result)

    node = workflow.node_at(start)
    # Semgrep prefixes rule ids with the config path ("rules.n8n-..."); keep the last part.
    rule_id = str(result["check_id"]).rsplit(".", 1)[-1]
    message = " ".join(str(extra.get("message", "")).split())

    return Finding(
        rule_id=rule_id,
        title=str(meta.get("title", rule_id)),
        brief=str(meta.get("brief") or _first_sentence(message)),
        message=message,
        risk=risk,  # type: ignore[arg-type]
        category=category,
        cwe=_first(meta.get("cwe")),
        owasp=_first(meta.get("owasp")),
        remediation=" ".join(str(meta.get("remediation", "Review this configuration.")).split()),
        start_line=start,
        end_line=end,
        snippet=snippet,
        exposed_value=exposed_value,
        node_name=node.name if node else None,
        node_type=node.type if node else None,
    )


_KEY_VALUE_MATCH = re.compile(r'^"(?:[^"\\]|\\.)*"\s*:\s*("(?:[^"\\]|\\.)*")$', re.DOTALL)
MAX_EXPOSED_CHARS = 500


def _exposed_value(raw_bytes: bytes, result: dict[str, Any]) -> str | None:
    """The exact leaked text for a secrets finding, unescaped from JSON.

    * "key": "value" match         -> value
    * {"name": .., "value": ..}   -> the "value" field
    * regex match inside a string -> the matched text (e.g. password = 'x',
      Password=x;, Bearer x, scheme://user:pass@host)
    """
    try:
        start, end = int(result["start"]["offset"]), int(result["end"]["offset"])
        text = raw_bytes[start:end].decode("utf-8").strip()
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        return None
    if not text:
        return None

    value: Any = None
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("value"), str):
            value = obj["value"]
    elif (match := _KEY_VALUE_MATCH.match(text)):
        value = json.loads(match.group(1))
    if value is None:
        try:  # undo JSON string escaping of a fragment (\" -> ", \n -> newline)
            value = json.loads(f'"{text}"')
        except json.JSONDecodeError:
            value = text
    value = str(value)
    return value if len(value) <= MAX_EXPOSED_CHARS else value[:MAX_EXPOSED_CHARS] + "…"


def _first_sentence(text: str) -> str:
    match = re.match(r"(.+?[.!?])(\s|$)", text)
    return match.group(1) if match else text


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None


def _snippet(lines: list[str], start: int, end: int) -> str:
    """Return the matched lines (we compute this ourselves: semgrep OSS
    reports `extra.lines` as "requires login")."""
    chosen = lines[max(start - 1, 0) : min(end, start - 1 + MAX_SNIPPET_LINES)]
    out = [line if len(line) <= MAX_SNIPPET_LINE_CHARS else line[:MAX_SNIPPET_LINE_CHARS] + "…" for line in chosen]
    if end - start + 1 > MAX_SNIPPET_LINES:
        out.append("…")
    return textwrap.dedent("\n".join(out))


_JSON_KEY_VALUE = re.compile(r'"((?:[^"\\]|\\.)*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"')
_URL_USERINFO = re.compile(r"^(=?\s*[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@", re.IGNORECASE)
_URL_SECRET_QUERY = re.compile(
    r"([?&](?:password|passwd|pwd|pass|secret|client_secret|api[_-]?key|apikey|token|access_token|auth_token|key|sig)=)[^&#\s]+",
    re.IGNORECASE,
)
_TEAMS_WEBHOOK_PATH = re.compile(r"(/webhookb2/)\S+", re.IGNORECASE)  # the path is the secret
_URL_PREFIX = re.compile(r"^=?\s*[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# Keys whose values identify a field rather than hold a secret.
_UNMASKED_KEYS = {"name", "type", "id"}


def _mask_value(value: str) -> str:
    if _URL_PREFIX.match(value):  # keep the URL readable, hide only the credentials
        value = _URL_USERINFO.sub(r"\g<1>****@", value)
        value = _TEAMS_WEBHOOK_PATH.sub(r"\g<1>****", value)
        return _URL_SECRET_QUERY.sub(r"\g<1>****", value)
    if len(value) < 8:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


def _mask_secrets(snippet: str) -> str:
    """Mask string values in secret findings so reports can be shared safely.

    Every value is masked (including short passwords and "=" expressions,
    which can embed literals) except field identifiers such as "name".
    """

    def repl(match: re.Match[str]) -> str:
        key, sep, value = match.groups()
        if key in _UNMASKED_KEYS or not value:
            return match.group(0)
        return f'"{key}"{sep}"{_mask_value(value)}"'

    return _JSON_KEY_VALUE.sub(repl, snippet)


def _summarize(findings: list[Finding]) -> ScanSummary:
    summary = ScanSummary(total=len(findings))
    for f in findings:
        setattr(summary, f.risk, getattr(summary, f.risk) + 1)
    return summary


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
