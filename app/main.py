"""FastAPI application: HTTP API + static single-page UI."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import __version__
from .config import Settings, get_settings
from .models import ErrorResponse, HealthResponse, ScanRequest, ScanResponse
from .scanner import ScanError, ScannerBusyError, ScanTimeoutError, SemgrepScanner
from .workflow import WorkflowValidationError, normalize_workflow, parse_workflow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("n8n_scanner")

settings = get_settings()

# Tailwind's Play CDN generates CSS at runtime, hence the CDN script source and
# 'unsafe-inline' for styles. All app JS lives in /static/app.js (no inline JS).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    scanner = SemgrepScanner(settings)
    scanner.check_installation()  # refuse to start without a working semgrep
    app.state.scanner = scanner
    app.state.rule_count = scanner.count_rules()
    logger.info("semgrep %s ready, %d rules loaded from %s", scanner.version, app.state.rule_count, settings.rules_path)
    yield


app = FastAPI(
    title="n8n Workflow Security Scanner",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.startswith("/docs"):  # Swagger UI needs its CDN assets
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if request.url.path.startswith("/api/"):
        # Scan results may contain sensitive configuration: never cache them.
        response.headers["Cache-Control"] = "no-store"
    return response


def get_scanner(request: Request) -> SemgrepScanner:
    return request.app.state.scanner


async def read_scan_request(request: Request, cfg: Settings = Depends(get_settings)) -> ScanRequest:
    """Read the body with a hard size cap *before* any JSON parsing.

    Content-Length is checked first, then the stream is counted as it arrives,
    so chunked uploads cannot bypass the limit.
    """
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "Content-Type must be application/json.")

    limit = cfg.max_payload_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"Payload exceeds {limit} bytes.")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, f"Payload exceeds {limit} bytes.")

    try:
        return ScanRequest.model_validate_json(bytes(body))
    except ValidationError:
        raise HTTPException(
            422,
            'Request body must be JSON of the form {"workflow": "<n8n workflow JSON string>"}.',
        ) from None


@app.post(
    "/api/scan",
    response_model=ScanResponse,
    responses={
        413: {"model": ErrorResponse},
        415: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        504: {"model": ErrorResponse},
    },
)
async def scan_workflow(
    payload: ScanRequest = Depends(read_scan_request),
    scanner: SemgrepScanner = Depends(get_scanner),
) -> ScanResponse:
    try:
        workflow = normalize_workflow(parse_workflow(payload.workflow))
    except WorkflowValidationError as exc:
        raise HTTPException(422, str(exc)) from None

    try:
        return await scanner.scan(workflow)
    except ScannerBusyError as exc:
        raise HTTPException(429, str(exc), headers={"Retry-After": "5"}) from None
    except ScanTimeoutError as exc:
        raise HTTPException(504, str(exc)) from None
    except ScanError as exc:
        raise HTTPException(500, str(exc)) from None


@app.get("/api/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    return HealthResponse(
        status="ok",
        semgrep_version=request.app.state.scanner.version,
        rules_loaded=request.app.state.rule_count,
    )


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    # Log the stack trace server-side; never leak internals to the client.
    logger.exception("unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# ----------------------------------------------------------------- static UI
app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(settings.static_dir / "index.html")
