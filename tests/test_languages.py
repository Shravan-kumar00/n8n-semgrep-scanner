"""Multi-language scanning: every language's sample is fully detected and its
safe counterpart produces no findings. These run the real semgrep binary."""

import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.languages import LANGUAGES, target_filename

if shutil.which(os.getenv("SEMGREP_BIN", "semgrep")) is None:
    pytest.skip("semgrep is not installed", allow_module_level=True)

from app.main import app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "static" / "samples"
SAFE = Path(__file__).resolve().parent / "fixtures" / "safe"

EXPECTED = {
    "python": {
        "known-secret-format", "hardcoded-password-or-key", "credentials-in-url",
        "python-command-injection", "python-sql-injection", "python-code-eval",
        "python-insecure-deserialization", "python-tls-verification-disabled",
        "python-jwt-signature-not-verified", "python-weak-hash", "python-debug-enabled",
        "python-insecure-temp-file",
    },
    "javascript": {
        "known-secret-format", "hardcoded-password-or-key", "js-command-injection", "js-sql-injection",
        "js-code-eval", "js-tls-verification-disabled", "js-xss-unsafe-html", "js-hardcoded-jwt-secret",
        "js-weak-hash", "js-permissive-cors", "js-insecure-deserialization",
    },
    "typescript": {"known-secret-format", "js-command-injection", "js-tls-verification-disabled", "js-xss-unsafe-html"},
    "java": {
        "known-secret-format", "hardcoded-password-or-key", "java-command-injection", "java-sql-injection",
        "java-insecure-deserialization", "java-tls-trust-all", "java-weak-crypto", "java-spring-csrf-disabled",
    },
    "go": {
        "known-secret-format", "hardcoded-password-or-key", "go-command-injection", "go-sql-injection",
        "go-tls-insecure-skip-verify", "go-weak-hash", "go-unescaped-template-html",
    },
    "csharp": {
        "connection-string-password", "hardcoded-password-or-key", "csharp-command-injection",
        "csharp-sql-injection", "csharp-insecure-deserialization", "csharp-tls-validation-disabled",
        "csharp-weak-crypto",
    },
    "php": {
        "hardcoded-password-or-key", "php-command-injection", "php-code-eval", "php-sql-injection",
        "php-unserialize", "php-file-inclusion", "php-xss-echo-request", "php-tls-verification-disabled",
        "php-weak-hash",
    },
    "ruby": {
        "hardcoded-password-or-key", "ruby-command-injection", "ruby-code-eval", "ruby-sql-injection",
        "ruby-insecure-deserialization", "ruby-tls-verification-disabled", "ruby-weak-hash", "ruby-mass-assignment",
    },
    "bash": {
        "hardcoded-secret-in-config", "hardcoded-password-or-key", "bash-curl-pipe-shell",
        "bash-tls-verification-disabled", "bash-eval-variable", "bash-world-writable",
    },
    "dockerfile": {
        "known-secret-format", "dockerfile-secret-in-env", "dockerfile-latest-tag", "dockerfile-curl-pipe-shell",
        "dockerfile-add-remote-url", "dockerfile-runs-as-root",
    },
    "yaml": {
        "hardcoded-secret-in-config", "hardcoded-password-or-key", "k8s-privileged-container",
        "k8s-host-namespace", "k8s-privilege-escalation-allowed", "docker-socket-mounted",
        "github-actions-script-injection", "github-actions-write-all",
    },
    "terraform": {
        "known-secret-format", "hardcoded-password-or-key", "terraform-public-bucket", "terraform-open-ingress",
        "terraform-iam-wildcard", "terraform-publicly-accessible-db", "terraform-encryption-disabled",
    },
    "generic": {"hardcoded-secret-in-config", "known-secret-format", "credentials-in-url"},
}
SAFE_FILES = {
    "python": "safe.py", "javascript": "safe.js", "java": "Safe.java", "go": "safe.go", "csharp": "Safe.cs",
    "php": "safe.php", "ruby": "safe.rb", "bash": "safe.sh", "dockerfile": "Dockerfile", "yaml": "safe.yaml",
    "terraform": "safe.tf",
}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def scan(client, language, path, **extra):
    body = {"content": path.read_text(), "language": language, "filename": path.name, **extra}
    res = client.post("/api/scan", json=body)
    assert res.status_code == 200, res.text
    return res.json()


def test_every_code_language_has_expectations():
    assert set(EXPECTED) == {k for k in LANGUAGES if k != "n8n"}


@pytest.mark.parametrize("language", sorted(EXPECTED))
def test_sample_is_fully_detected(client, language):
    sample = SAMPLES / LANGUAGES[language].sample
    body = scan(client, language, sample)
    assert {f["rule_id"] for f in body["findings"]} == EXPECTED[language]
    assert body["language"] == language and body["target_name"] == sample.name
    assert body["node_count"] is None and body["line_count"] == len(sample.read_text().splitlines())
    assert body["data_flows"] == []
    assert all(f["brief"] and f["remediation"] for f in body["findings"])


@pytest.mark.parametrize("language", sorted(SAFE_FILES))
def test_safe_code_has_no_findings(client, language):
    body = scan(client, language, SAFE / SAFE_FILES[language])
    assert body["findings"] == [], [(f["rule_id"], f["start_line"]) for f in body["findings"]]


def test_secret_findings_show_exact_value_and_masked_snippet(client):
    body = scan(client, "python", SAMPLES / "code" / "vulnerable.py")
    by_line = {f["start_line"]: f for f in body["findings"] if f["category"] == "secrets"}
    assert by_line[17]["exposed_value"] == 'DB_PASSWORD = "Sup3rS3cret!2026"'
    assert "Sup3rS3cret" not in by_line[17]["snippet"]
    assert by_line[19]["snippet"] == 'DATABASE_URL = "postgresql://admin:****@db.internal:5432/orders"'
    # One finding per leaked secret: the specific Stripe-key rule wins over the generic one.
    assert [f["rule_id"] for f in body["findings"] if f["start_line"] == 18] == ["known-secret-format"]


def test_line_numbers_match_the_original_file(client):
    source = "import os\r\n\r\n\r\nos.system(cmd)\r\n"  # CRLF endings are kept
    body = client.post("/api/scan", json={"content": source, "language": "python"}).json()
    assert [(f["rule_id"], f["start_line"]) for f in body["findings"]] == [("python-command-injection", 4)]


def test_credentials_profile_for_code(client):
    body = scan(client, "terraform", SAMPLES / "code" / "main.tf", profile="credentials")
    assert body["findings"] and {f["category"] for f in body["findings"]} == {"secrets"}


def test_languages_endpoint(client):
    langs = {l["id"]: l for l in client.get("/api/languages").json()}
    assert set(langs) == set(LANGUAGES)
    assert langs["python"]["rules"] > 3 and ".py" in langs["python"]["extensions"]
    for lang in langs.values():
        assert (SAMPLES / lang["sample"]).is_file(), lang["id"]
    health = client.get("/api/health").json()
    assert health["languages"] == len(LANGUAGES) and health["rules_loaded"] >= 100


@pytest.mark.parametrize(
    "body, status, detail",
    [
        ({"content": "x", "language": "cobol"}, 422, "Unknown language"),
        ({"content": "   ", "language": "python"}, 422, "must not be empty"),
        ({"content": "a", "workflow": "b", "language": "python"}, 422, "not both"),
        ({"content": "ab\u0000cd", "language": "python"}, 422, "binary"),
    ],
)
def test_invalid_requests(client, body, status, detail):
    res = client.post("/api/scan", json=body)
    assert res.status_code == status and detail in res.json()["detail"]


def test_pdf_for_code(client):
    res = client.post("/api/report.pdf", json={
        "content": (SAMPLES / "code" / "vulnerable.go").read_text(), "language": "go", "filename": "vulnerable.go"})
    assert res.status_code == 200 and res.content.startswith(b"%PDF")
    assert 'filename="security-report-vulnerable-go-' in res.headers["content-disposition"]


@pytest.mark.parametrize(
    "language, uploaded, expected",
    [
        ("typescript", "src/App.tsx", "source.tsx"),
        ("typescript", "notes.txt", "source.ts"),
        ("python", "../../etc/passwd", "source.py"),
        ("python", None, "source.py"),
        ("dockerfile", "api.Dockerfile", "Dockerfile"),
        ("n8n", "flow.json", "workflow.json"),
        ("generic", ".env", "source.txt"),
    ],
)
def test_target_filename_never_uses_uploaded_name(language, uploaded, expected):
    assert target_filename(LANGUAGES[language], uploaded) == expected
