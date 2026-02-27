"""
FastAPI application factory.

Creates and configures the FastAPI app with:
- Webhook endpoint
- Health checks
- CORS middleware
- Startup/shutdown lifecycle hooks
- Structured logging
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager.

    Startup:
    - Initialize database tables
    - Log startup info

    Shutdown:
    - Dispose database engine
    """
    # ── Startup ──────────────────────────────────────────────
    logger.info("AnaYa starting up...")

    try:
        from anaya.db import init_db

        await init_db()
        logger.info("Database initialized")
    except Exception:
        logger.exception("Failed to initialize database")

    logger.info("AnaYa ready")

    yield

    # ── Shutdown ─────────────────────────────────────────────
    logger.info("AnaYa shutting down...")

    try:
        from anaya.db import async_engine

        await async_engine.dispose()
        logger.info("Database connections closed")
    except Exception:
        logger.exception("Failed to close database connections")


def create_app() -> FastAPI:
    """
    Application factory — creates and configures the FastAPI app.

    Used by:
    - uvicorn: `uvicorn anaya.api.app:create_app --factory`
    - docker-compose: same command
    - Tests: `create_app()` for TestClient
    """
    _configure_logging()

    app = FastAPI(
        title="AnaYa",
        description="Compliance-as-code engine — GitHub App that scans PRs against policy rule packs",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ─────────────────────────────────────────────────
    from fastapi.middleware.cors import CORSMiddleware
    from anaya.config import settings as _settings

    # In production, restrict origins; in dev, allow all
    cors_origins = (
        ["*"] if _settings.app_env == "development"
        else ["https://github.com"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ── Routes ───────────────────────────────────────────────
    from anaya.api.health import router as health_router
    from anaya.api.webhooks import router as webhooks_router

    app.include_router(health_router)
    app.include_router(webhooks_router)

    return app


def _configure_logging() -> None:
    """Set up structured logging for the application."""
    from anaya.config import settings

    level = logging.DEBUG if settings.app_env == "development" else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
