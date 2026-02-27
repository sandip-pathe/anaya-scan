"""
Tests for inline suppression and confidence scoring.

Covers:
- anaya:disable inline suppression (pattern, AST, blanket, specific)
- Test file / migration confidence scoring
- Baseline fingerprinting and filtering
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from anaya.engine.models import PatternRule, Severity, Violation
from anaya.engine.scanners.pattern import PatternScanner
from anaya.engine.utils import (
    CONFIDENCE_PATTERN_MIGRATION,
    CONFIDENCE_PATTERN_PROD,
    CONFIDENCE_PATTERN_TEST,
    get_confidence,
    is_line_suppressed,
    is_migration_file,
    is_test_file,
)


@pytest.fixture
def scanner() -> PatternScanner:
    return PatternScanner()


@pytest.fixture
def password_rule() -> PatternRule:
    return PatternRule(
        id="no-hardcoded-password",
        name="No Hardcoded Passwords",
        type="pattern",
        severity=Severity.HIGH,
        message="Hardcoded password detected",
        languages=["python"],
        patterns=[r'(?i)password\s*=\s*["\'][^"\']{3,}["\']'],
    )


# ═══════════════════════════════════════════════════════════════
# is_line_suppressed
# ═══════════════════════════════════════════════════════════════

class TestInlineSuppression:
    def test_blanket_disable(self):
        """# anaya:disable without rule ID suppresses everything."""
        line = 'password = "hunter2"  # anaya:disable'
        assert is_line_suppressed(line, "generic/secrets/no-hardcoded-password")

    def test_specific_disable_match(self):
        """# anaya:disable=rule-id suppresses that exact rule."""
        line = 'password = "hunter2"  # anaya:disable=no-hardcoded-password'
        assert is_line_suppressed(line, "generic/secrets/no-hardcoded-password")

    def test_specific_disable_no_match(self):
        """# anaya:disable=other-rule does NOT suppress a different rule."""
        line = 'password = "hunter2"  # anaya:disable=some-other-rule'
        assert not is_line_suppressed(line, "generic/secrets/no-hardcoded-password")

    def test_fully_qualified_disable(self):
        """# anaya:disable=pack/rule-id matches fully-qualified."""
        line = 'x = eval(data)  # anaya:disable=generic/owasp-top10/a03-sql-injection'
        assert is_line_suppressed(line, "generic/owasp-top10/a03-sql-injection")

    def test_multiple_rules_disable(self):
        """# anaya:disable=rule1, rule2 disables multiple rules."""
        line = 'x = "http://foo"  # anaya:disable=no-hardcoded-http-url, http-no-tls'
        assert is_line_suppressed(line, "generic/tls/no-hardcoded-http-url")
        assert is_line_suppressed(line, "generic/dpdp/http-no-tls")

    def test_js_comment_style(self):
        """// anaya:disable works for JS-style comments."""
        line = 'const pass = "test123";  // anaya:disable'
        assert is_line_suppressed(line, "some-rule")

    def test_no_disable_comment(self):
        """Lines without anaya:disable are not suppressed."""
        line = 'password = "hunter2"'
        assert not is_line_suppressed(line, "some-rule")

    def test_case_insensitive(self):
        """anaya:disable is case-insensitive."""
        line = 'password = "hunter2"  # ANAYA:DISABLE'
        assert is_line_suppressed(line, "some-rule")


class TestPatternScannerSuppression:
    def test_anaya_disable_suppresses_violation(self, scanner, password_rule):
        """Pattern scanner respects # anaya:disable."""
        content = 'password = "hunter2"  # anaya:disable=no-hardcoded-password\n'
        violations = scanner.scan_file("app.py", content, [password_rule], "pack")
        assert len(violations) == 0

    def test_anaya_disable_blanket(self, scanner, password_rule):
        """Pattern scanner respects blanket # anaya:disable."""
        content = 'password = "hunter2"  # anaya:disable\n'
        violations = scanner.scan_file("app.py", content, [password_rule], "pack")
        assert len(violations) == 0

    def test_anaya_disable_wrong_rule(self, scanner, password_rule):
        """Pattern scanner fires when anaya:disable targets a different rule."""
        content = 'password = "hunter2"  # anaya:disable=other-rule\n'
        violations = scanner.scan_file("app.py", content, [password_rule], "pack")
        assert len(violations) == 1


# ═══════════════════════════════════════════════════════════════
# Test file detection + confidence
# ═══════════════════════════════════════════════════════════════

class TestTestFileDetection:
    @pytest.mark.parametrize("path", [
        "tests/test_api.py",
        "care/emr/tests/test_payment.py",
        "app/__tests__/Button.test.tsx",
        "spec/models/user_spec.rb",
        "go/pkg/handler_test.go",
        "conftest.py",
        "tests/fixtures/data.json",
        "test/mocks/api.js",
        # Filename-based detection
        "care/management/commands/load_fixtures.py",
        "scripts/seed_test_data.py",
        "app/factories.py",
    ])
    def test_detects_test_files(self, path):
        assert is_test_file(path), f"Expected {path} to be detected as test file"

    @pytest.mark.parametrize("path", [
        "app/models.py",
        "care/emr/api/viewsets/patient.py",
        "src/utils/helpers.ts",
        "config/settings/base.py",
        "care/emr/utils/expression_evaluator.py",
    ])
    def test_rejects_non_test_files(self, path):
        assert not is_test_file(path), f"Expected {path} NOT to be a test file"


class TestMigrationDetection:
    @pytest.mark.parametrize("path", [
        "care/facility/migrations/0466_camera_presets.py",
        "alembic/versions/abc123_add_table.py",
    ])
    def test_detects_migrations(self, path):
        assert is_migration_file(path)

    def test_rejects_non_migration(self):
        assert not is_migration_file("app/models.py")


class TestConfidenceScoring:
    def test_prod_file_gets_base_confidence(self):
        assert get_confidence("app/models.py") == CONFIDENCE_PATTERN_PROD

    def test_test_file_gets_low_confidence(self):
        assert get_confidence("tests/test_api.py") == CONFIDENCE_PATTERN_TEST

    def test_migration_gets_migration_confidence(self):
        c = get_confidence("care/facility/migrations/0001_initial.py")
        assert c == CONFIDENCE_PATTERN_MIGRATION

    def test_fixture_filename_gets_test_confidence(self):
        c = get_confidence("care/management/commands/load_fixtures.py")
        assert c == CONFIDENCE_PATTERN_TEST

    def test_pattern_scanner_applies_test_confidence(self, scanner, password_rule):
        """Violations in test files should get low confidence."""
        content = 'password = "testpass123"\n'
        violations = scanner.scan_file(
            "tests/test_auth.py", content, [password_rule], "pack"
        )
        assert len(violations) == 1
        assert violations[0].confidence == CONFIDENCE_PATTERN_TEST

    def test_pattern_scanner_applies_prod_confidence(self, scanner, password_rule):
        """Violations in production files should get prod confidence."""
        content = 'password = "hunter2"\n'
        violations = scanner.scan_file(
            "app/auth.py", content, [password_rule], "pack"
        )
        assert len(violations) == 1
        assert violations[0].confidence == CONFIDENCE_PATTERN_PROD


# ═══════════════════════════════════════════════════════════════
# Baseline fingerprint + filtering
# ═══════════════════════════════════════════════════════════════

class TestBaseline:
    def _make_violation(self, rule_id="pack/rule", file_path="app.py",
                        line=10, snippet="bad code"):
        return Violation(
            rule_id=rule_id,
            rule_name="Test Rule",
            severity=Severity.HIGH,
            file_path=file_path,
            line_start=line,
            line_end=line,
            message="Test message",
            snippet=snippet,
        )

    def test_fingerprint_stable(self):
        """Same violation produces same fingerprint."""
        from cli.main import _violation_fingerprint
        v1 = self._make_violation()
        v2 = self._make_violation()
        assert _violation_fingerprint(v1) == _violation_fingerprint(v2)

    def test_fingerprint_differs_for_different_rules(self):
        from cli.main import _violation_fingerprint
        v1 = self._make_violation(rule_id="pack/rule-a")
        v2 = self._make_violation(rule_id="pack/rule-b")
        assert _violation_fingerprint(v1) != _violation_fingerprint(v2)

    def test_fingerprint_survives_line_shift(self):
        """Fingerprint should be stable even if line number changes."""
        from cli.main import _violation_fingerprint
        v1 = self._make_violation(line=10)
        v2 = self._make_violation(line=12)
        # Same snippet, same rule, same file → same fingerprint
        assert _violation_fingerprint(v1) == _violation_fingerprint(v2)

    def test_baseline_filter(self):
        """Violations in baseline should be filtered out."""
        from cli.main import _violation_fingerprint, _filter_baseline

        v_old = self._make_violation(snippet="old bad code")
        v_new = self._make_violation(snippet="new bad code")

        # Create baseline with v_old
        baseline = {
            "version": 1,
            "violations": [
                {"fingerprint": _violation_fingerprint(v_old)},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(baseline, f)
            f.flush()

            result = _filter_baseline([v_old, v_new], f.name)

        assert len(result) == 1
        assert result[0].snippet == "new bad code"
