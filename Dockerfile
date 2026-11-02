# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# n8n Workflow Security Scanner: FastAPI + Semgrep CLI in one image.
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first for better layer caching. The semgrep wheel bundles the
# semgrep-core binary, so no extra system packages are required.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && semgrep --version \
 && rm -rf /root/.semgrep /root/.cache

# Unprivileged runtime user (no home dir, no login shell).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner

# Application code and rules are owned by root and read-only to the app user.
COPY app ./app
COPY rules ./rules
COPY static ./static

# Semgrep writes settings/logs under $HOME; each scan also gets its own
# throwaway HOME inside its temp dir. /tmp is a tmpfs in docker-compose.
ENV HOME=/tmp \
    TMPDIR=/tmp \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_RULES_PATH=/app/rules \
    WEB_CONCURRENCY=2

USER 10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]

# uvicorn reads the worker count from WEB_CONCURRENCY.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
