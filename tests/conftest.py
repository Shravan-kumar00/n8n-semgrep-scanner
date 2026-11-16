"""Shared test setup.

Tests that need the real Semgrep binary use the `client` fixture; they are
skipped (not failed) when Semgrep is not installed.
"""

import os
import shutil
import sys
from pathlib import Path

import pytest

# Running .venv/bin/pytest without activating the venv: make the venv's
# semgrep executable visible.
os.environ["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "app" / "static" / "samples"
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def client():
    """FastAPI test client with the app lifespan (semgrep check) running."""
    if shutil.which(os.getenv("SEMGREP_BIN", "semgrep")) is None:
        pytest.skip("semgrep is not installed")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
