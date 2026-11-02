"""Runtime configuration, read once from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    """Read a positive integer env var, falling back to `default` on bad input."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Environment variable {name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"Environment variable {name} must be >= {minimum}")
    return value


def _list_env(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # Path (or name on $PATH) of the semgrep executable.
    semgrep_bin: str = field(default_factory=lambda: os.getenv("SEMGREP_BIN", "semgrep"))
    # Rule file or directory. Only local rules are used; nothing is fetched
    # from the Semgrep registry, so workflow content never leaves the host.
    rules_path: Path = field(
        default_factory=lambda: Path(os.getenv("SEMGREP_RULES_PATH", str(PROJECT_ROOT / "rules")))
    )
    # Hard cap on the HTTP request body (bytes).
    max_payload_bytes: int = field(default_factory=lambda: _int_env("MAX_PAYLOAD_BYTES", 2_000_000))
    # Wall-clock limit for the whole semgrep process (seconds).
    scan_timeout_seconds: int = field(default_factory=lambda: _int_env("SCAN_TIMEOUT_SECONDS", 60))
    # Semgrep's own per-rule, per-file timeout (seconds).
    rule_timeout_seconds: int = field(default_factory=lambda: _int_env("SEMGREP_RULE_TIMEOUT", 20))
    # Max simultaneous semgrep processes per worker; extra requests get 429.
    max_concurrent_scans: int = field(default_factory=lambda: _int_env("MAX_CONCURRENT_SCANS", 4))
    # How long a request waits for a free scan slot before 429 (seconds).
    queue_wait_seconds: int = field(default_factory=lambda: _int_env("SCAN_QUEUE_WAIT_SECONDS", 10))
    # Optional CORS allow-list. Empty = same-origin only (the bundled UI).
    cors_origins: list[str] = field(default_factory=lambda: _list_env("CORS_ORIGINS"))
    # Expose /docs and /openapi.json (off by default in production).
    enable_docs: bool = field(
        default_factory=lambda: os.getenv("ENABLE_DOCS", "false").lower() in {"1", "true", "yes"}
    )
    static_dir: Path = PROJECT_ROOT / "static"


@lru_cache
def get_settings() -> Settings:
    return Settings()
