"""
GitHub webhook endpoint.

Receives webhook events from GitHub, validates the signature,
and dispatches to the appropriate handler:

- pull_request → enqueue scan task (via Celery)
- installation → log and store installation info
- ping → respond with pong
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request

from anaya.api.middleware import verify_webhook_signature
from anaya.github.models import (
    InstallationEvent,
    PingEvent,
    PullRequestEvent,
)

router = APIRouter(tags=["webhooks"])
logger = logging.getLogger(__name__)


@router.post("/webhooks/github")
async def github_webhook(request: Request) -> dict:
    """
    Receive and process GitHub webhook events.

    Flow:
    1. Verify HMAC-SHA256 signature
    2. Parse event type from X-GitHub-Event header
    3. Dispatch to appropriate handler

    Returns:
        JSON response with processing status.
    """
    # ── 1. Verify signature ──────────────────────────────────
    body = await verify_webhook_signature(request)
    payload = json.loads(body)

    # ── 2. Get event type ────────────────────────────────────
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")

    logger.info(
        "Webhook received: event=%s delivery=%s",
        event_type,
        delivery_id,
    )

    # ── 3. Dispatch ──────────────────────────────────────────
    if event_type == "ping":
        return _handle_ping(payload)

    if event_type == "pull_request":
        return await _handle_pull_request(payload, delivery_id)

    if event_type == "installation":
        return await _handle_installation(payload)

    logger.debug("Ignoring unhandled event type: %s", event_type)
    return {"status": "ignored", "event": event_type}


def _handle_ping(payload: dict) -> dict:
    """Handle GitHub ping events (app installation verification)."""
    try:
        event = PingEvent.model_validate(payload)
        logger.info("Ping received: %s (hook_id=%d)", event.zen, event.hook_id)
    except Exception:
        logger.debug("Ping payload parsing failed, returning pong anyway")

    return {"status": "pong"}


async def _handle_pull_request(payload: dict, delivery_id: str) -> dict:
    """
    Handle pull_request events.

    Only scans on opened/synchronize/reopened actions for non-draft PRs.
    Enqueues a Celery task for async processing.
    """
    try:
        event = PullRequestEvent.model_validate(payload)
    except Exception:
        logger.exception("Failed to parse pull_request event")
        raise HTTPException(status_code=400, detail="Invalid pull_request payload")

    if not event.should_scan:
        logger.info(
            "Skipping PR #%d: action=%s draft=%s",
            event.pr_number,
            event.action,
            event.pull_request.draft,
        )
        return {
            "status": "skipped",
            "reason": f"action={event.action}, draft={event.pull_request.draft}",
        }

    # Enqueue scan task
    from anaya.worker import tasks as _worker_tasks

    task = _worker_tasks.scan_pr.delay(
        installation_id=event.installation_id,
        repo=event.repo_full_name,
        pr_number=event.pr_number,
        head_sha=event.head_sha,
    )

    logger.info(
        "Enqueued scan: repo=%s pr=#%d sha=%s task_id=%s",
        event.repo_full_name,
        event.pr_number,
        event.head_sha[:8],
        task.id,
    )

    return {
        "status": "queued",
        "task_id": task.id,
        "repo": event.repo_full_name,
        "pr_number": event.pr_number,
    }


async def _handle_installation(payload: dict) -> dict:
    """
    Handle installation events (created, deleted, etc.).

    Logs the installation and stores it in the database.
    """
    try:
        event = InstallationEvent.model_validate(payload)
    except Exception:
        logger.exception("Failed to parse installation event")
        raise HTTPException(status_code=400, detail="Invalid installation payload")

    logger.info(
        "Installation %s: id=%d account=%s (%s)",
        event.action,
        event.installation_id,
        event.account_login,
        event.account_type,
    )

    # Store installation in DB
    if event.action in ("created", "new_permissions_accepted"):
        try:
            from sqlalchemy import text

            from anaya.db import AsyncSessionLocal

            async with AsyncSessionLocal() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO installations (installation_id, account_login, account_type, created_at)
                        VALUES (:id, :login, :type, NOW())
                        ON CONFLICT (installation_id)
                        DO UPDATE SET account_login = :login, account_type = :type
                        """
                    ),
                    {
                        "id": event.installation_id,
                        "login": event.account_login,
                        "type": event.account_type,
                    },
                )
                await session.commit()
        except Exception:
            logger.exception("Failed to store installation")

    return {
        "status": "processed",
        "action": event.action,
        "installation_id": event.installation_id,
    }
