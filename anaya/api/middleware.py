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


async def verify_webhook_signature(request: Request) -> bytes:
    """
    Verify the GitHub webhook signature (X-Hub-Signature-256).

    Reads the raw body once and returns it for downstream use.
    Raises 401 if signature is missing or invalid.

    Returns:
        The raw request body bytes (already consumed from the stream).
    """
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header")
        raise HTTPException(status_code=401, detail="Missing signature")

    body = await request.body()

    if not _verify_signature(body, signature_header, settings.github_webhook_secret):
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
