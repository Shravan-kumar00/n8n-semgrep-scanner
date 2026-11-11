"""Semgrep execution and result parsing.

Security properties of a scan:
  * The uploaded workflow / file is written to a private temp dir (0700) as a
    0600 file under a fixed name chosen by the server (never the uploaded
    name), and the whole directory is deleted when the scan finishes.
  * Semgrep is invoked with an argument list (never a shell), local rules only,
    metrics and version checks disabled, and a minimal environment.
  * The process runs in its own process group so a timeout kills Semgrep and
    every helper it spawned (semgrep-core).
  * Concurrency is bounded per worker; excess requests are rejected with 429.
  * Scanned contents are never logged.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings
from .graph import analyze_workflow
from .languages import LANGUAGES, Language
from .models import RISK_ORDER, Finding, ScanProfile, ScanResponse, ScanSummary
from .workflow import NormalizedWorkflow

logger = logging.getLogger(__name__)

SECRETS_CATEGORY = "secrets"  # rules in this category form the "credentials" profile
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


@dataclass(frozen=True)
class ScanTarget:
    """What to scan: the text, its language and the file name Semgrep sees."""

    language: Language
    text: str
    target_filename: str            # chosen by the server (see languages.target_filename)
    display_name: str | None        # workflow name or uploaded file name, for reports
    workflow: NormalizedWorkflow | None = None  # n8n only


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
        for lang in LANGUAGES.values():
            for rule_file in lang.rule_files:
                if not (self.settings.rules_path / rule_file).exists():
                    raise RuntimeError(f"Rules for {lang.label} missing: {rule_file}")
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

    def count_rules(self, rule_files: tuple[str, ...] | None = None) -> int:
        """Rules in the given files/dirs (relative to rules_path), or all rules."""
        root = self.settings.rules_path
        paths = [root / f for f in rule_files] if rule_files else [root]
        files: set[Path] = set()
        for p in paths:
            files.update([p] if p.is_file() else [*p.rglob("*.yml"), *p.rglob("*.yaml")])
        pattern = re.compile(r"^\s*-\s+id:\s*\S", re.MULTILINE)
        return sum(len(pattern.findall(f.read_text(encoding="utf-8"))) for f in files)

    # ------------------------------------------------------------------- scan
    async def scan(self, target: ScanTarget, profile: ScanProfile = "full") -> ScanResponse:
        """Scan a workflow or source file. Raises ScanError subclasses on failure.

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
            configs = [self.settings.rules_path / f for f in target.language.rule_files]
            raw = await asyncio.to_thread(self._scan_in_tempdir, target, scan_id, configs)
        finally:
            self._slots.release()

        findings, warnings = self._parse_results(raw, target)
        workflow = target.workflow
        data_flows = []
        if profile == "credentials":
            findings = [f for f in findings if f.category == SECRETS_CATEGORY]
        elif workflow is not None:
            graph_findings, data_flows = analyze_workflow(workflow)
            findings = sorted(
                findings + graph_findings,
                key=lambda f: (RISK_ORDER.index(f.risk), f.start_line, f.rule_id),
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info("scan %s (%s, %s) finished: %d findings in %d ms",
                    scan_id, target.language.id, profile, len(findings), duration_ms)

        return ScanResponse(
            scan_id=scan_id,
            profile=profile,
            language=target.language.id,
            language_label=target.language.label,
            target_name=target.display_name,
            workflow_name=workflow.name if workflow else None,
            node_count=workflow.node_count if workflow else None,
            line_count=len(target.text.splitlines()),
            duration_ms=duration_ms,
            semgrep_version=self.version,
            summary=_summarize(findings),
            findings=findings,
            data_flows=data_flows,
            warnings=warnings,
        )

    def _scan_in_tempdir(self, target: ScanTarget, scan_id: str, configs: list[Path]) -> dict[str, Any]:
        # mkdtemp creates the directory with mode 0700; it is removed on exit
        # from the `with` block even if semgrep fails or times out.
        with tempfile.TemporaryDirectory(prefix=f"scan-{scan_id[:8]}-") as tmp:
            tmp_path = Path(tmp)
            target_dir = tmp_path / "target"
            home_dir = tmp_path / "home"  # semgrep writes ~/.semgrep here, not in the image
            target_dir.mkdir(mode=0o700)
            home_dir.mkdir(mode=0o700)

            path = target_dir / target.target_filename
            # O_EXCL: fail rather than follow a pre-existing file/symlink.
            # newline="" keeps the file's own line endings so line numbers match.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(target.text)

            return self._run_semgrep(path, home_dir, configs)

    def _run_semgrep(self, target: Path, home_dir: Path, configs: list[Path]) -> dict[str, Any]:
        s = self.settings
        cmd = [s.semgrep_bin, "scan"]
        for config in configs:
            cmd += ["--config", str(config)]
        cmd += [
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
    def _parse_results(self, data: dict[str, Any], target: ScanTarget) -> tuple[list[Finding], list[str]]:
        lines = target.text.splitlines()
        raw_bytes = target.text.encode("utf-8")  # semgrep offsets are byte offsets
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()

        for result in data.get("results", []):
            try:
                finding = _to_finding(result, lines, raw_bytes, target)
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
            message = re.sub(r"/\S*/target/", "", message)
            warnings.append(f"{err.get('type', 'Error')}: {message[:300]}")
        return findings, warnings


# ---------------------------------------------------------------------- helpers
def _drop_nested_secret_findings(findings: list[Finding]) -> list[Finding]:
    """Report one leaked secret once.

    Several secret rules can fire on the same value, e.g. the name/value rule
    matches a whole {"name": "Authorization", "value": "Basic ..."} object
    while the Bearer/Basic rule matches the value line inside it. A secrets
    finding is dropped when another secrets finding covers its line range and
    is either more severe, or equally severe and spans a strictly larger range
    (e.g. a generic "password = '...'" match next to the more specific
    "AWS access key" match on the same line keeps only the latter).
    """
    secrets = [f for f in findings if f.category == SECRETS_CATEGORY]

    def covered(inner: Finding) -> bool:
        for outer in secrets:
            if outer is inner or not (outer.start_line <= inner.start_line and inner.end_line <= outer.end_line):
                continue
            more_severe = RISK_ORDER.index(outer.risk) < RISK_ORDER.index(inner.risk)
            same_risk = outer.risk == inner.risk
            larger = (outer.end_line - outer.start_line) > (inner.end_line - inner.start_line)
            if more_severe or (same_risk and larger):
                return True
        return False

    return [f for f in findings if f.category != SECRETS_CATEGORY or not covered(f)]


def _to_finding(result: dict[str, Any], lines: list[str], raw_bytes: bytes, target: ScanTarget) -> Finding:
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
    workflow = target.workflow
    if category == SECRETS_CATEGORY:
        if workflow is not None:
            snippet = _mask_secrets(snippet)
            exposed_value = _exposed_value(raw_bytes, result)
        else:
            snippet = _mask_code_secrets(snippet)
            exposed_value = _matched_text(raw_bytes, result)

    node = workflow.node_at(start) if workflow is not None else None
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


def _matched_text(raw_bytes: bytes, result: dict[str, Any]) -> str | None:
    """The exact text Semgrep matched (source code: no unescaping needed)."""
    try:
        start, end = int(result["start"]["offset"]), int(result["end"]["offset"])
        text = raw_bytes[start:end].decode("utf-8").strip()
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        return None
    if not text:
        return None
    return text if len(text) <= MAX_EXPOSED_CHARS else text[:MAX_EXPOSED_CHARS] + "…"


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


_CODE_STRING = re.compile(r'"([^"\n]{4,})"|\'([^\'\n]{4,})\'|`([^`\n]{4,})`')
_CONFIG_VALUE = re.compile(r"(?m)^([ \t-]*(?:export[ \t]+)?(?:ENV[ \t]+|ARG[ \t]+)?[\w.-]+[ \t]*[:=][ \t]*)([^\s\"'#`]{4,})")
_CONN_PASSWORD = re.compile(r"(?i)((?:password|pwd)=)[^;\"'\s]+")


def _mask_code_value(value: str) -> str:
    if _URL_PREFIX.match(value):
        return _mask_value(value)
    if _CONN_PASSWORD.search(value):  # keep the connection string readable
        return _CONN_PASSWORD.sub(r"\g<1>****", value)
    return _mask_value(value)


def _mask_code_secrets(snippet: str) -> str:
    """Mask string literals and unquoted config values in a code snippet."""

    def quoted(match: re.Match[str]) -> str:
        quote = match.group(0)[0]
        inner = next(g for g in match.groups() if g is not None)
        return f"{quote}{_mask_code_value(inner)}{quote}"

    snippet = _CODE_STRING.sub(quoted, snippet)
    return _CONFIG_VALUE.sub(lambda m: m.group(1) + _mask_code_value(m.group(2)), snippet)


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
