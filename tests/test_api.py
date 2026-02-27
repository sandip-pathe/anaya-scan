"""
Integration tests for the API layer.

Tests webhook endpoint, signature verification, health checks,
and end-to-end webhook → task dispatch flow.
Uses httpx.AsyncClient with ASGITransport (compatible with pytest-asyncio auto).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import httpx
import pytest

from anaya.api.middleware import _verify_signature


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

WEBHOOK_SECRET = "test-webhook-secret-12345"


@asynccontextmanager
async def _noop_lifespan(app):
    yield


def _make_app():
    with patch("anaya.api.app.lifespan", _noop_lifespan):
        from anaya.api.app import create_app
        return create_app()


_test_app = _make_app()


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=_test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _sign(payload: dict, secret: str = WEBHOOK_SECRET) -> str:
    body = json.dumps(payload).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _pr_payload(action="opened", pr_number=42, draft=False, head_sha="abc123def456"):
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "number": pr_number, "title": "Add feature", "state": "open",
            "draft": draft,
            "head": {"sha": head_sha, "ref": "feature-branch"},
            "base": {"sha": "base123", "ref": "main"},
            "user": {"id": 1, "login": "dev", "type": "User"},
        },
        "repository": {
            "id": 100, "full_name": "owner/repo", "name": "repo",
            "private": False, "default_branch": "main",
        },
        "installation": {"id": 12345678},
        "sender": {"id": 1, "login": "dev"},
    }


async def _post_webhook(client, payload, event_type="pull_request", secret=WEBHOOK_SECRET):
    """Helper: POST /webhooks/github with proper headers."""
    with patch("anaya.api.middleware.settings") as ms:
        ms.github_webhook_secret = secret
        return await client.post(
            "/webhooks/github",
            content=json.dumps(payload),
            headers={
                "X-GitHub-Event": event_type,
                "X-GitHub-Delivery": "test-delivery",
                "X-Hub-Signature-256": _sign(payload, secret),
                "Content-Type": "application/json",
            },
        )


# ═══════════════════════════════════════════════════════════════
# Test: Signature Verification (pure functions, no client needed)
# ═══════════════════════════════════════════════════════════════

class TestSignatureVerification:
    def test_valid_signature_passes(self):
        payload = b'{"test": "data"}'
        mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
        assert _verify_signature(payload, f"sha256={mac.hexdigest()}", WEBHOOK_SECRET) is True

    def test_invalid_signature_fails(self):
        assert _verify_signature(b'{"test": "data"}', "sha256=invalid", WEBHOOK_SECRET) is False

    def test_missing_sha256_prefix_fails(self):
        assert _verify_signature(b"test", "md5=abc", WEBHOOK_SECRET) is False

    def test_different_payload_fails(self):
        payload = b'{"test": "data"}'
        mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
        assert _verify_signature(b'{"test": "tampered"}', f"sha256={mac.hexdigest()}", WEBHOOK_SECRET) is False


# ═══════════════════════════════════════════════════════════════
# Test: Health Endpoint
# ═══════════════════════════════════════════════════════════════

class TestHealthEndpoints:
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ═══════════════════════════════════════════════════════════════
# Test: Ping Webhook
# ═══════════════════════════════════════════════════════════════

class TestPingWebhook:
    async def test_ping_returns_pong(self, client):
        payload = {"zen": "Keep it awesome.", "hook_id": 12345}
        resp = await _post_webhook(client, payload, event_type="ping")
        assert resp.status_code == 200
        assert resp.json()["status"] == "pong"


# ═══════════════════════════════════════════════════════════════
# Test: Pull Request Webhook
# ═══════════════════════════════════════════════════════════════

class TestPullRequestWebhook:
    async def test_opened_pr_enqueues_task(self, client):
        with patch("anaya.worker.tasks.scan_pr") as mock_scan_pr:
            mock_task = MagicMock()
            mock_task.id = "task-123"
            mock_scan_pr.delay.return_value = mock_task

            payload = _pr_payload(action="opened")
            resp = await _post_webhook(client, payload)

            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "queued"
            assert data["task_id"] == "task-123"
            assert data["repo"] == "owner/repo"
            assert data["pr_number"] == 42

            mock_scan_pr.delay.assert_called_once_with(
                installation_id=12345678,
                repo="owner/repo",
                pr_number=42,
                head_sha="abc123def456",
            )

    async def test_synchronize_enqueues_task(self, client):
        with patch("anaya.worker.tasks.scan_pr") as mock_scan_pr:
            mock_task = MagicMock()
            mock_task.id = "task-456"
            mock_scan_pr.delay.return_value = mock_task

            resp = await _post_webhook(client, _pr_payload(action="synchronize"))
            assert resp.status_code == 200
            assert resp.json()["status"] == "queued"

    async def test_closed_pr_skipped(self, client):
        resp = await _post_webhook(client, _pr_payload(action="closed"))
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

    async def test_draft_pr_skipped(self, client):
        resp = await _post_webhook(client, _pr_payload(action="opened", draft=True))
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

    async def test_missing_signature_returns_401(self, client):
        with patch("anaya.api.middleware.settings") as ms:
            ms.github_webhook_secret = WEBHOOK_SECRET
            resp = await client.post(
                "/webhooks/github",
                content=json.dumps(_pr_payload()),
                headers={"X-GitHub-Event": "pull_request", "Content-Type": "application/json"},
            )
            assert resp.status_code == 401

    async def test_invalid_signature_returns_401(self, client):
        with patch("anaya.api.middleware.settings") as ms:
            ms.github_webhook_secret = WEBHOOK_SECRET
            resp = await client.post(
                "/webhooks/github",
                content=json.dumps(_pr_payload()),
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": "sha256=deadbeef",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════
# Test: Unknown Event
# ═══════════════════════════════════════════════════════════════

class TestUnknownEvent:
    async def test_unknown_event_returns_ignored(self, client):
        resp = await _post_webhook(client, {"action": "test"}, event_type="unknown_event")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
