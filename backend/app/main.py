"""
ReconScope FastAPI application entry point.

Creates and configures the FastAPI app with:
- CORS middleware
- Security headers middleware
- API v1 router
- Health check endpoint
- Startup / shutdown lifecycle hooks for the database engine
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.v1.router import router as v1_router
from app.api.v1.websocket import router as ws_router
from app.config import get_settings
from app.core.database import engine
from app.core.logging import configure_logging, get_logger

# ── Constants ────────────────────────────────────────────────────────────────

_HEALTH_CHECK_PATH: str = "/health"

_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


# ── Security Headers Middleware ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that injects security-related HTTP response headers.

    Every outgoing response receives the headers defined in
    ``_SECURITY_HEADERS`` to harden the application against common browser-side
    attacks (MIME sniffing, clickjacking, reflected XSS).
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process the request and append security headers to the response.

        Args:
            request: The incoming HTTP request.
            call_next: Callable that forwards to the next middleware or route.

        Returns:
            The response with additional security headers.
        """
        response: Response = await call_next(request)
        for header_name, header_value in _SECURITY_HEADERS.items():
            response.headers[header_name] = header_value
        return response


# ── Application Factory ─────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Build and return the configured FastAPI application instance.

    Returns:
        A fully configured ``FastAPI`` app ready to serve requests.
    """
    settings = get_settings()

    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Attack Surface Mapping Tool -- automated reconnaissance, "
            "correlation, risk scoring, and attack path inference."
        ),
        version="1.0.0",
        docs_url="/docs" if settings.DEBUG else "/docs",
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json",
    )

    # ── Middleware (order matters: outermost first) ───────────────────────

    application.add_middleware(SecurityHeadersMiddleware)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        max_age=600,
    )

    # ── Routers ──────────────────────────────────────────────────────────

    application.include_router(v1_router, prefix=settings.API_V1_PREFIX)
    application.include_router(ws_router, tags=["websocket"])

    # ── Health Check ─────────────────────────────────────────────────────

    @application.get(
        _HEALTH_CHECK_PATH,
        tags=["health"],
        summary="Application health check",
        response_class=JSONResponse,
    )
    async def health_check() -> dict[str, Any]:
        """Return the current health status of the application.

        Returns:
            A JSON object with ``status``, ``app``, and ``timestamp`` fields.
        """
        return {
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Lifecycle Events ─────────────────────────────────────────────────

    @application.on_event("startup")
    async def on_startup() -> None:
        """Execute startup tasks.

        - Configures structured logging.
        - Verifies that the database engine can connect.
        """
        configure_logging()
        logger = get_logger(__name__)
        logger.info(
            "Application starting",
            extra={"action": "startup", "target": settings.APP_NAME},
        )

        # Verify DB connectivity (will raise on failure).
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        logger.info(
            "Database connection verified",
            extra={"action": "db_check", "target": settings.DATABASE_URL.split("@")[-1]},
        )

    @application.on_event("shutdown")
    async def on_shutdown() -> None:
        """Execute shutdown tasks.

        - Disposes of the async database engine and its connection pool.
        """
        logger = get_logger(__name__)
        logger.info(
            "Application shutting down",
            extra={"action": "shutdown", "target": settings.APP_NAME},
        )
        await engine.dispose()

    return application


# ── Module-Level App Instance ────────────────────────────────────────────────

app: FastAPI = create_app()
