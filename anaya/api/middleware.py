"""
Webhook signature verification middleware.

Validates that incoming webhook requests are genuinely from GitHub
using HMAC-SHA256 signature comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import HTTPException, Request

from anaya.config import settings

logger = logging.getLogger(__name__)


# Maximum webhook payload size (10 MB — GitHub sends at most ~25 MB)
_MAX_BODY_SIZE = 10 * 1024 * 1024


async def verify_webhook_signature(request: Request) -> bytes:
    """
    Verify the GitHub webhook signature (X-Hub-Signature-256).

    Reads the raw body once and returns it for downstream use.
    Raises 401 if signature is missing or invalid.
    Raises 500 if webhook secret is not configured.
    Raises 413 if body exceeds size limit.

    Returns:
        The raw request body bytes (already consumed from the stream).
    """
    # Guard: reject all webhooks if secret is not properly configured
    secret = settings.github_webhook_secret
    if not secret or secret == "__not_set__":
        logger.error("GITHUB_WEBHOOK_SECRET is not configured — rejecting webhook")
        raise HTTPException(
            status_code=500,
            detail="Webhook secret not configured",
        )

    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header")
        raise HTTPException(status_code=401, detail="Missing signature")

    # Enforce body size limit before reading fully into memory
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY_SIZE:
        logger.warning("Webhook payload too large: %s bytes", content_length)
        raise HTTPException(status_code=413, detail="Payload too large")

    body = await request.body()
    if len(body) > _MAX_BODY_SIZE:
        logger.warning("Webhook payload too large: %d bytes", len(body))
        raise HTTPException(status_code=413, detail="Payload too large")

    if not _verify_signature(body, signature_header, secret):
        logger.warning("Invalid webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    return body


def _verify_signature(payload: bytes, signature_header: str, secret: str) -> bool:
    """
    Compare HMAC-SHA256 signature using constant-time comparison.

    Args:
        payload: Raw request body.
        signature_header: "sha256=<hex>" header value.
        secret: Webhook secret configured in the GitHub App.

    Returns:
        True if the signature matches.
    """
    if not signature_header.startswith("sha256="):
        return False

    expected_signature = signature_header[7:]  # strip "sha256=" prefix

    mac = hmac.new(
        secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    )
    calculated = mac.hexdigest()

    return hmac.compare_digest(calculated, expected_signature)
