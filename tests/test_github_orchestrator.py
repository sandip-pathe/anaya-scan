"""
Tests for the GitHub layer and orchestrator.

Uses mocks for GitHub API calls since we can't hit the real API in tests.
Tests cover:
- GitHub auth (JWT generation)
- GitHub webhook models (parsing + should_scan logic)
- Check run payload building
- SARIF upload encoding
- PR comment building
- Orchestrator logic with mocked client
"""

from __future__ import annotations

import base64
import gzip
import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from anaya.engine.models import (
    ScanResult,
    ScanSummary,
    Severity,
    Violation,
)
from anaya.github.client import GitHubClient


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def sample_violations() -> list[Violation]:
    """Create sample violations for testing."""
    return [
        Violation(
            rule_id="generic/secrets-detection/no-hardcoded-api-key",
            rule_name="No Hardcoded API Key",
            severity=Severity.CRITICAL,
            file_path="src/config.py",
            line_start=10,
            line_end=10,
            message="Hardcoded API key found",
            snippet='api_key = "[REDACTED]"',
            fix_hint="Use environment variables",
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        ),
        Violation(
            rule_id="generic/owasp-top10/a03-sql-injection",
            rule_name="SQL Injection Risk",
            severity=Severity.HIGH,
            file_path="src/db.py",
            line_start=25,
            line_end=25,
            message="Possible SQL injection",
            snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            fix_hint="Use parameterized queries",
        ),
    ]


@pytest.fixture
def sample_result(sample_violations) -> ScanResult:
    """Create a sample ScanResult for testing."""
    summary = ScanResult.build_summary(
        violations=sample_violations,
        packs_run=["generic/secrets-detection", "generic/owasp-top10"],
        files_scanned=5,
        fail_on=Severity.CRITICAL,
        warn_on=Severity.HIGH,
    )
    return ScanResult(
        repo="owner/repo",
        pr_number=42,
        commit_sha="abc123def456",
        violations=sample_violations,
        packs_run=["generic/secrets-detection", "generic/owasp-top10"],
        scan_duration_ms=350,
        summary=summary,
    )


# ═══════════════════════════════════════════════════════════════
# Test: GitHub Auth
# ═══════════════════════════════════════════════════════════════

class TestGitHubAuth:
    def test_generate_jwt_with_explicit_params(self):
        """JWT generation with explicit key should work without settings."""
        # Generate a test RSA key
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        from anaya.github.auth import generate_jwt
        import jwt as pyjwt

        token = generate_jwt(app_id="12345", private_key=pem)

        # Verify it's a valid JWT
        assert isinstance(token, str)
        parts = token.split(".")
        assert len(parts) == 3  # header.payload.signature

        # Decode without verification to check claims
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "12345"
        assert "exp" in decoded
        assert "iat" in decoded
        assert decoded["exp"] - decoded["iat"] <= 660  # 10 min + 60s drift

    def test_clear_token_cache(self):
        """Token cache should be clearable."""
        from anaya.github.auth import _token_cache, clear_token_cache

        _token_cache[99999] = ("fake-token", datetime.now(timezone.utc))
        assert 99999 in _token_cache
        clear_token_cache()
        assert 99999 not in _token_cache


# ═══════════════════════════════════════════════════════════════
# Test: GitHub Webhook Models
# ═══════════════════════════════════════════════════════════════

class TestWebhookModels:
    def test_pull_request_event_parses(self):
        """PullRequestEvent should parse a realistic webhook payload."""
        from anaya.github.models import PullRequestEvent

        payload = {
            "action": "opened",
            "number": 42,
            "pull_request": {
                "number": 42,
                "title": "Add feature",
                "state": "open",
                "draft": False,
                "head": {"sha": "abc123", "ref": "feature-branch"},
                "base": {"sha": "def456", "ref": "main"},
                "user": {"id": 1, "login": "dev", "type": "User"},
            },
            "repository": {
                "id": 100,
                "full_name": "owner/repo",
                "name": "repo",
                "private": False,
                "default_branch": "main",
            },
            "installation": {"id": 12345678},
            "sender": {"id": 1, "login": "dev"},
        }

        event = PullRequestEvent.model_validate(payload)
        assert event.action == "opened"
        assert event.pr_number == 42
        assert event.head_sha == "abc123"
        assert event.repo_full_name == "owner/repo"
        assert event.installation_id == 12345678
        assert event.should_scan is True

    def test_should_scan_opened(self):
        """should_scan returns True for opened PRs."""
        from anaya.github.models import PullRequestEvent

        event = PullRequestEvent.model_validate({
            "action": "opened",
            "number": 1,
            "pull_request": {
                "number": 1, "state": "open", "draft": False,
                "head": {"sha": "a", "ref": "b"},
                "base": {"sha": "c", "ref": "main"},
            },
            "repository": {"id": 1, "full_name": "o/r", "name": "r"},
        })
        assert event.should_scan is True

    def test_should_scan_synchronize(self):
        """should_scan returns True for synchronized PRs."""
        from anaya.github.models import PullRequestEvent

        event = PullRequestEvent.model_validate({
            "action": "synchronize",
            "number": 1,
            "pull_request": {
                "number": 1, "state": "open", "draft": False,
                "head": {"sha": "a", "ref": "b"},
                "base": {"sha": "c", "ref": "main"},
            },
            "repository": {"id": 1, "full_name": "o/r", "name": "r"},
        })
        assert event.should_scan is True

    def test_should_scan_false_for_closed(self):
        """should_scan returns False for closed PRs."""
        from anaya.github.models import PullRequestEvent

        event = PullRequestEvent.model_validate({
            "action": "closed",
            "number": 1,
            "pull_request": {
                "number": 1, "state": "closed", "draft": False,
                "head": {"sha": "a", "ref": "b"},
                "base": {"sha": "c", "ref": "main"},
            },
            "repository": {"id": 1, "full_name": "o/r", "name": "r"},
        })
        assert event.should_scan is False

    def test_should_scan_false_for_draft(self):
        """should_scan returns False for draft PRs."""
        from anaya.github.models import PullRequestEvent

        event = PullRequestEvent.model_validate({
            "action": "opened",
            "number": 1,
            "pull_request": {
                "number": 1, "state": "open", "draft": True,
                "head": {"sha": "a", "ref": "b"},
                "base": {"sha": "c", "ref": "main"},
            },
            "repository": {"id": 1, "full_name": "o/r", "name": "r"},
        })
        assert event.should_scan is False

    def test_installation_event_parses(self):
        """InstallationEvent should parse correctly."""
        from anaya.github.models import InstallationEvent

        payload = {
            "action": "created",
            "installation": {
                "id": 12345678,
                "account": {"id": 1, "login": "org", "type": "Organization"},
            },
            "repositories": [
                {"id": 1, "full_name": "org/repo1", "name": "repo1"},
            ],
            "sender": {"id": 2, "login": "admin"},
        }
        event = InstallationEvent.model_validate(payload)
        assert event.installation_id == 12345678
        assert event.account_login == "org"
        assert event.account_type == "Organization"
        assert len(event.repositories) == 1

    def test_ping_event_parses(self):
        """PingEvent should parse correctly."""
        from anaya.github.models import PingEvent

        payload = {
            "zen": "Keep it logically awesome.",
            "hook_id": 12345,
        }
        event = PingEvent.model_validate(payload)
        assert event.zen == "Keep it logically awesome."
        assert event.hook_id == 12345


# ═══════════════════════════════════════════════════════════════
# Test: Check Run Payloads
# ═══════════════════════════════════════════════════════════════

class TestCheckRunPayloads:
    def test_create_payload_structure(self):
        """Create payload should have required fields."""
        from anaya.reporters.check_run import build_create_payload

        payload = build_create_payload(head_sha="abc123")
        assert payload["name"] == "AnaYa Compliance Scan"
        assert payload["head_sha"] == "abc123"
        assert payload["status"] == "in_progress"
        assert "started_at" in payload

    def test_complete_payload_structure(self, sample_result):
        """Complete payload should have conclusion, output, and annotations."""
        from anaya.reporters.check_run import build_complete_payload

        payload = build_complete_payload(sample_result)
        assert payload["status"] == "completed"
        assert payload["conclusion"] == "failure"  # has CRITICAL violation
        assert "output" in payload
        assert "annotations" in payload["output"]
        assert len(payload["output"]["annotations"]) == 2
        assert "summary" in payload["output"]

    def test_complete_payload_passed_conclusion(self):
        """Passed result should have 'success' conclusion."""
        from anaya.reporters.check_run import build_complete_payload

        result = ScanResult(
            repo="o/r", pr_number=1, commit_sha="abc",
            violations=[], packs_run=["p"],
            scan_duration_ms=100,
            summary=ScanSummary(
                total_files_scanned=3, total_violations=0,
                by_severity={s.value: 0 for s in Severity},
                by_pack={}, overall_status="passed",
            ),
        )
        payload = build_complete_payload(result)
        assert payload["conclusion"] == "success"

    def test_annotation_batching(self, sample_violations):
        """Annotations should be batched in groups of 50."""
        from anaya.reporters.check_run import build_annotation_batches

        # Create 120 violations
        many_violations = sample_violations * 60

        batches = build_annotation_batches(many_violations)
        assert len(batches) == 3  # 120 / 50 = 2.4 → 3 batches
        assert len(batches[0]) == 50
        assert len(batches[1]) == 50
        assert len(batches[2]) == 20


# ═══════════════════════════════════════════════════════════════
# Test: SARIF Builder
# ═══════════════════════════════════════════════════════════════

class TestSARIFBuilder:
    def test_sarif_structure(self, sample_result):
        """SARIF output should have valid 2.1.0 structure."""
        from anaya.reporters.sarif_builder import build_sarif

        sarif = build_sarif(sample_result)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "AnaYa"
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 2

    def test_sarif_deduplicates_rules(self):
        """Rules should be deduplicated by rule_id."""
        from anaya.reporters.sarif_builder import build_sarif

        violations = [
            Violation(
                rule_id="pack/rule-a", rule_name="Rule A",
                severity=Severity.HIGH,
                file_path="a.py", line_start=1, line_end=1,
                message="test",
            ),
            Violation(
                rule_id="pack/rule-a", rule_name="Rule A",
                severity=Severity.HIGH,
                file_path="b.py", line_start=5, line_end=5,
                message="test",
            ),
        ]
        result = ScanResult(
            repo="o/r", pr_number=1, commit_sha="abc",
            violations=violations, packs_run=["pack"],
            scan_duration_ms=100,
            summary=ScanSummary(
                total_files_scanned=2, total_violations=2,
                by_severity={s.value: 0 for s in Severity} | {"HIGH": 2},
                by_pack={"pack": 2}, overall_status="failed",
            ),
        )
        sarif = build_sarif(result)
        # Same rule_id → 1 rule descriptor, 2 results
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2


# ═══════════════════════════════════════════════════════════════
# Test: PR Comment Builder
# ═══════════════════════════════════════════════════════════════

class TestCommentBuilder:
    def test_comment_contains_key_info(self, sample_result):
        """Comment should contain status, violations count, pack info."""
        from anaya.reporters.comment import build_comment

        comment = build_comment(sample_result)
        assert "FAILED" in comment
        assert "abc123de" in comment  # commit sha prefix
        assert "5" in comment  # files scanned
        assert "2" in comment  # violations
        assert "generic/secrets-detection" in comment
        assert "no-hardcoded-api-key" in comment

    def test_comment_truncates_violations(self):
        """Comment should truncate at max_violations."""
        from anaya.reporters.comment import build_comment

        violations = [
            Violation(
                rule_id=f"pack/rule-{i}", rule_name=f"Rule {i}",
                severity=Severity.HIGH,
                file_path=f"file{i}.py", line_start=i, line_end=i,
                message=f"Violation {i}",
            )
            for i in range(50)
        ]
        result = ScanResult(
            repo="o/r", pr_number=1, commit_sha="abc123def",
            violations=violations, packs_run=["pack"],
            scan_duration_ms=100,
            summary=ScanSummary(
                total_files_scanned=50, total_violations=50,
                by_severity={s.value: 0 for s in Severity} | {"HIGH": 50},
                by_pack={"pack": 50}, overall_status="failed",
            ),
        )
        comment = build_comment(result, max_violations=10)
        assert "10/50" in comment
        assert "40 more" in comment

    def test_comment_passed_status(self):
        """Passed scan should show checkmark."""
        from anaya.reporters.comment import build_comment

        result = ScanResult(
            repo="o/r", pr_number=1, commit_sha="abc123def",
            violations=[], packs_run=["pack"],
            scan_duration_ms=100,
            summary=ScanSummary(
                total_files_scanned=3, total_violations=0,
                by_severity={s.value: 0 for s in Severity},
                by_pack={}, overall_status="passed",
            ),
        )
        comment = build_comment(result)
        assert "PASSED" in comment


# ═══════════════════════════════════════════════════════════════
# Test: SARIF Upload Encoding
# ═══════════════════════════════════════════════════════════════

class TestSARIFUpload:
    async def test_sarif_gzip_base64_encoding(self, sample_result):
        """SARIF upload should properly gzip + base64 encode."""
        from anaya.reporters.sarif_builder import build_sarif

        sarif = build_sarif(sample_result)
        sarif_json = json.dumps(sarif).encode("utf-8")

        # Simulate the encoding done in sarif.py
        compressed = gzip.compress(sarif_json)
        encoded = base64.b64encode(compressed).decode("ascii")

        # Decode and verify round-trip
        decoded = gzip.decompress(base64.b64decode(encoded))
        assert json.loads(decoded) == sarif


# ═══════════════════════════════════════════════════════════════
# Test: Orchestrator (mocked)
# ═══════════════════════════════════════════════════════════════

class TestOrchestrator:
    async def test_execute_scan_with_mocked_client(self):
        """Orchestrator should coordinate scanners and produce results."""
        from anaya.engine.orchestrator import _execute_scan

        # Create a mock client
        mock_client = AsyncMock(spec=GitHubClient)

        # Mock get_default_branch
        mock_client.get_default_branch.return_value = "main"

        # Mock get_file_content for anaya.yml → returns None (use defaults)
        mock_client.get_file_content.return_value = None

        # Mock get_pr_files → return 2 changed Python files
        mock_client.get_pr_files.return_value = [
            {"filename": "src/config.py", "status": "modified"},
            {"filename": "src/README.md", "status": "modified"},  # not scannable
        ]

        # Mock get_file_content for actual files
        async def mock_get_content(repo, path, ref):
            if path == "src/config.py":
                return 'API_KEY = "sk-hardcoded-key-12345"\n'
            return None

        mock_client.get_file_content.side_effect = mock_get_content

        result = await _execute_scan(
            mock_client,
            "owner/repo",
            42,
            "abc123",
            time.time(),
        )

        assert isinstance(result, ScanResult)
        assert result.repo == "owner/repo"
        assert result.pr_number == 42
        assert result.commit_sha == "abc123"
        assert result.summary.total_files_scanned >= 1
        # Should find violations from the hardcoded key
        assert result.summary.total_violations > 0

    async def test_execute_scan_no_scannable_files(self):
        """Orchestrator should handle PRs with no scannable files."""
        from anaya.engine.orchestrator import _execute_scan

        mock_client = AsyncMock(spec=GitHubClient)
        mock_client.get_default_branch.return_value = "main"
        mock_client.get_file_content.return_value = None  # no anaya.yml
        mock_client.get_pr_files.return_value = [
            {"filename": "README.md", "status": "modified"},
            {"filename": "docs/guide.md", "status": "added"},
        ]

        result = await _execute_scan(
            mock_client, "owner/repo", 1, "sha123", time.time()
        )

        assert result.summary.total_violations == 0
        assert result.summary.overall_status == "passed"

    async def test_execute_scan_with_anaya_config(self):
        """Orchestrator should respect anaya.yml configuration."""
        from anaya.engine.orchestrator import _execute_scan

        mock_client = AsyncMock(spec=GitHubClient)
        mock_client.get_default_branch.return_value = "main"

        # Return anaya.yml with custom ignore paths
        anaya_yml = """
version: "1"
ignore:
  paths:
    - "vendor/*"
    - "generated/*"
"""
        call_count = 0
        async def mock_get_content(repo, path, ref):
            nonlocal call_count
            call_count += 1
            if path == "anaya.yml":
                return anaya_yml
            if path == "vendor/lib.py":
                return 'secret = "should-be-ignored"\n'
            if path == "src/app.py":
                return 'x = 1\n'  # clean file
            return None

        mock_client.get_file_content.side_effect = mock_get_content
        mock_client.get_pr_files.return_value = [
            {"filename": "vendor/lib.py", "status": "modified"},
            {"filename": "src/app.py", "status": "modified"},
        ]

        result = await _execute_scan(
            mock_client, "owner/repo", 1, "sha123", time.time()
        )

        # vendor/lib.py should be ignored, src/app.py is clean
        assert result.summary.total_violations == 0

    async def test_execute_scan_skips_deleted_files(self):
        """Orchestrator should skip deleted files."""
        from anaya.engine.orchestrator import _execute_scan

        mock_client = AsyncMock(spec=GitHubClient)
        mock_client.get_default_branch.return_value = "main"
        mock_client.get_file_content.return_value = None
        mock_client.get_pr_files.return_value = [
            {"filename": "src/old.py", "status": "removed"},
        ]

        result = await _execute_scan(
            mock_client, "owner/repo", 1, "sha123", time.time()
        )

        assert result.summary.total_files_scanned == 0
        assert result.summary.total_violations == 0
