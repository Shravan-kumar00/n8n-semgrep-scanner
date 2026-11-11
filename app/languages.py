"""Supported scan targets: n8n workflows, source code and config files.

Each language names the rule files it runs (relative to SEMGREP_RULES_PATH)
and how the uploaded text is written to disk so Semgrep picks the right
parser. The uploaded file name is never used as a path: only its extension
(from an allow-list) is reused.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Language:
    id: str
    label: str
    group: str
    short: str                      # badge text in the UI
    extensions: tuple[str, ...]     # lower-case, with dot
    rule_files: tuple[str, ...]
    default_target: str             # file name written for Semgrep
    filenames: tuple[str, ...] = () # exact names, e.g. Dockerfile
    sample: str | None = None       # path under /static/samples/

    @property
    def is_workflow(self) -> bool:
        return self.id == "n8n"


SECRETS = "common/secrets.yml"
CONFIG_SECRETS = "common/config-secrets.yml"

LANGUAGES: dict[str, Language] = {
    lang.id: lang
    for lang in (
        Language("n8n", "n8n workflow", "Automation", "n8n", (".json",), ("n8n",), "workflow.json",
                 sample="ai-agents-m365-workflow.json"),
        Language("python", "Python", "Application code", "PY", (".py", ".pyw"),
                 ("code/python.yml", SECRETS), "source.py", sample="code/vulnerable.py"),
        Language("javascript", "JavaScript", "Application code", "JS", (".js", ".mjs", ".cjs", ".jsx"),
                 ("code/javascript.yml", SECRETS), "source.js", sample="code/vulnerable.js"),
        Language("typescript", "TypeScript", "Application code", "TS", (".ts", ".tsx", ".mts", ".cts"),
                 ("code/javascript.yml", SECRETS), "source.ts", sample="code/vulnerable.ts"),
        Language("java", "Java", "Application code", "JV", (".java",),
                 ("code/java.yml", SECRETS), "Source.java", sample="code/Vulnerable.java"),
        Language("go", "Go", "Application code", "GO", (".go",),
                 ("code/go.yml", SECRETS), "source.go", sample="code/vulnerable.go"),
        Language("csharp", "C#", "Application code", "C#", (".cs",),
                 ("code/csharp.yml", SECRETS), "Source.cs", sample="code/Vulnerable.cs"),
        Language("php", "PHP", "Application code", "PHP", (".php", ".phtml"),
                 ("code/php.yml", SECRETS), "source.php", sample="code/vulnerable.php"),
        Language("ruby", "Ruby", "Application code", "RB", (".rb", ".rake"),
                 ("code/ruby.yml", SECRETS), "source.rb", filenames=("Gemfile", "Rakefile"),
                 sample="code/vulnerable.rb"),
        Language("bash", "Shell script", "Infrastructure & config", "SH", (".sh", ".bash", ".zsh"),
                 ("code/bash.yml", SECRETS, CONFIG_SECRETS), "source.sh", sample="code/deploy.sh"),
        Language("dockerfile", "Dockerfile", "Infrastructure & config", "DK", (".dockerfile",),
                 ("code/dockerfile.yml", SECRETS), "Dockerfile", filenames=("Dockerfile", "Containerfile"),
                 sample="code/Dockerfile"),
        Language("yaml", "YAML (Kubernetes, Compose, GitHub Actions)", "Infrastructure & config", "YML",
                 (".yml", ".yaml"), ("code/yaml.yml", SECRETS, CONFIG_SECRETS), "source.yaml",
                 sample="code/k8s-and-actions.yaml"),
        Language("terraform", "Terraform", "Infrastructure & config", "TF", (".tf", ".tfvars", ".hcl"),
                 ("code/terraform.yml", SECRETS), "source.tf", sample="code/main.tf"),
        Language("generic", "Other text file (secrets only)", "Other", "TXT",
                 (".env", ".properties", ".ini", ".cfg", ".conf", ".toml", ".txt", ".xml", ".json", ".sql",
                  ".kt", ".swift", ".rs", ".c", ".cpp", ".h", ".ps1", ".bat"),
                 (SECRETS, CONFIG_SECRETS), "source.txt", filenames=(".env", ".npmrc", ".pypirc"),
                 sample="code/app.env"),
    )
}


def get_language(language_id: str) -> Language | None:
    return LANGUAGES.get(language_id)


def target_filename(language: Language, uploaded_name: str | None) -> str:
    """File name to write for Semgrep.

    Keeps the uploaded extension only when it is one of the language's
    known extensions (e.g. .tsx vs .ts); everything else falls back to the
    language default. The uploaded name itself is never used.
    """
    if language.is_workflow or language.id in ("dockerfile", "generic") or not uploaded_name:
        return language.default_target
    suffix = PurePosixPath(uploaded_name.replace("\\", "/")).suffix.lower()
    if suffix in language.extensions:
        return PurePosixPath(language.default_target).stem + suffix
    return language.default_target
