"""
Health check endpoints.

Provides /health and /ready endpoints for container orchestration
and load balancer probes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/health")
async def health_check() -> dict:
    """
    Basic liveness probe.

    Returns 200 as long as the process is running.
    Used by Docker HEALTHCHECK and Kubernetes liveness probes.
    """
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check() -> dict:
    """
    Readiness probe — checks that dependencies are reachable.

    Verifies:
    - Database connection (PostgreSQL)
    - Cache connection (Redis)

    Returns 200 if all dependencies are healthy, 503 otherwise.
    """
    checks: dict[str, str] = {}

    # Check PostgreSQL
    try:
        from sqlalchemy import text

        from anaya.db import async_engine

        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        logger.warning("Database health check failed: %s", e)
        checks["database"] = f"error: {e}"

    # Check Redis
    try:
        import redis.asyncio as aioredis

        from anaya.config import settings

        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as e:
        logger.warning("Redis health check failed: %s", e)
        checks["redis"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())

    if not all_ok:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "checks": checks},
        )

    return {"status": "ok", "checks": checks}
