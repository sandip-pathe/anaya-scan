"""
Tests for anaya.engine.scanners.pattern — PatternScanner.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from anaya.engine.models import PatternRule, Severity, Violation
from anaya.engine.scanners.base import BaseScanner
from anaya.engine.scanners.pattern import PatternScanner


@pytest.fixture
def scanner() -> PatternScanner:
    return PatternScanner()


@pytest.fixture
def sample_rule() -> PatternRule:
    return PatternRule(
        id="no-hardcoded-password",
        name="No Hardcoded Passwords",
        type="pattern",
        severity=Severity.HIGH,
        message="Hardcoded password detected at {file}:{line}",
        fix_hint="Use environment variables",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        tags=["secrets"],
        languages=["python", "javascript"],
        patterns=[r'(?i)password\s*=\s*["\'][^"\']{3,}["\']'],
        exclude_patterns=[r"os\.getenv", r"process\.env", r"environ\["],
    )


class TestPatternScanner:
    """Core pattern scanner behavior."""

    def test_dirty_secrets_fixture_triggers(self, scanner: PatternScanner) -> None:
        """Dirty secrets fixture must produce violations."""
        content = Path("tests/fixtures/python/dirty/secrets.py").read_text()
        rules = [
            PatternRule(
                id="no-hardcoded-api-key",
                name="No Hardcoded API Keys",
                type="pattern",
                severity=Severity.CRITICAL,
                message="Hardcoded API key at {file}:{line}",
                tags=["secrets"],
                languages=["python"],
                patterns=[r'(?i)(?:api[_-]?key|apikey)\s*=\s*["\'][^"\']{8,}["\']'],
                exclude_patterns=[r"os\.getenv", r"os\.environ", r"environ\["],
            ),
        ]
        violations = scanner.scan_file(
            "tests/fixtures/python/dirty/secrets.py",
            content,
            rules,
            "generic/secrets-detection",
        )
        assert len(violations) > 0
        assert violations[0].rule_id == "generic/secrets-detection/no-hardcoded-api-key"

    def test_clean_secrets_fixture_has_zero_violations(self, scanner: PatternScanner) -> None:
        """Clean secrets fixture must produce zero violations (exclude_patterns work)."""
        content = Path("tests/fixtures/python/clean/secrets.py").read_text()
        rules = [
            PatternRule(
                id="no-hardcoded-api-key",
                name="No Hardcoded API Keys",
                type="pattern",
                severity=Severity.CRITICAL,
                message="Hardcoded API key",
                tags=["secrets"],
                languages=["python"],
                patterns=[r'(?i)(?:api[_-]?key|apikey)\s*=\s*["\'][^"\']{8,}["\']'],
                exclude_patterns=[r"os\.getenv", r"os\.environ", r"environ\["],
            ),
        ]
        violations = scanner.scan_file(
            "tests/fixtures/python/clean/secrets.py",
            content,
            rules,
            "generic/secrets-detection",
        )
        assert len(violations) == 0

    def test_noqa_blanket_suppresses_all_rules(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """A bare '# noqa' suppresses ALL rules on that line."""
        content = 'PASSWORD = "supersecret123"  # noqa\n'
        violations = scanner.scan_file("test.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_noqa_specific_suppresses_named_rule(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """'# noqa: pack/rule-id' suppresses only that specific rule."""
        content = 'PASSWORD = "supersecret123"  # noqa: test/pack/no-hardcoded-password\n'
        violations = scanner.scan_file("test.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_noqa_wrong_rule_does_not_suppress(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """'# noqa: other/rule' does NOT suppress a different rule."""
        content = 'PASSWORD = "supersecret123"  # noqa: other/pack/other-rule\n'
        violations = scanner.scan_file("test.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1

    def test_exclude_patterns_suppress_matching_lines(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """exclude_patterns on a rule suppress matching lines."""
        content = 'password = os.getenv("DB_PASSWORD")\n'
        violations = scanner.scan_file("test.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_malformed_regex_logs_warning_no_crash(
        self, scanner: PatternScanner, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Malformed regex logs a warning, does not crash, other rules still run."""
        bad_rule = PatternRule(
            id="bad-regex",
            name="Bad Regex Rule",
            type="pattern",
            severity=Severity.LOW,
            message="Should not fire",
            languages=["python"],
            patterns=["[invalid(regex"],  # malformed
        )
        good_rule = PatternRule(
            id="good-rule",
            name="Good Rule",
            type="pattern",
            severity=Severity.LOW,
            message="TODO found",
            languages=["python"],
            patterns=[r"#\s*TODO"],
        )
        content = "x = 1\n# TODO fix this\n"
        with caplog.at_level("WARNING"):
            violations = scanner.scan_file("test.py", content, [bad_rule, good_rule], "test/pack")

        # Bad regex logged a warning
        assert any("Malformed regex" in r.message for r in caplog.records)
        # Good rule still ran
        assert len(violations) == 1
        assert violations[0].rule_id == "test/pack/good-rule"

    def test_disabled_rule_does_not_fire(self, scanner: PatternScanner) -> None:
        """Rules with enabled=False must not produce violations."""
        disabled_rule = PatternRule(
            id="disabled",
            name="Disabled Rule",
            type="pattern",
            severity=Severity.HIGH,
            enabled=False,
            message="Should not fire",
            languages=["python"],
            patterns=[r".*"],
        )
        violations = scanner.scan_file("test.py", "anything", [disabled_rule], "test/pack")
        assert len(violations) == 0

    def test_snippet_redaction_for_secrets(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """Secret values must be redacted in snippets."""
        content = 'password = "my_actual_secret_value"\n'
        violations = scanner.scan_file("test.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1
        assert "[REDACTED]" in violations[0].snippet
        assert "my_actual_secret_value" not in violations[0].snippet

    def test_language_filtering(self, scanner: PatternScanner, sample_rule: PatternRule) -> None:
        """Rules should not fire on files with non-matching languages."""
        content = 'password = "supersecret123"\n'
        violations = scanner.scan_file("test.go", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_wildcard_language_matches_all(self, scanner: PatternScanner) -> None:
        """Rules with '*' in languages match all file types."""
        rule = PatternRule(
            id="catch-all",
            name="Catch All",
            type="pattern",
            severity=Severity.INFO,
            message="Found",
            languages=["*"],
            patterns=[r"TODO"],
        )
        content = "# TODO fix this\n"
        violations = scanner.scan_file("test.rs", content, [rule], "test/pack")
        assert len(violations) == 1


class TestDetectLanguage:
    """Tests for BaseScanner.detect_language()."""

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("test.py", "python"),
            ("src/app.js", "javascript"),
            ("component.tsx", "typescript"),
            ("main.go", "go"),
            ("lib.rs", "rust"),
            ("config.yml", "yaml"),
            ("data.json", "json"),
            (".env", "env"),
            ("settings.toml", "toml"),
            ("app.conf", "conf"),
            ("Makefile", None),
            ("README.md", None),
        ],
    )
    def test_detect_language(self, path: str, expected: str | None) -> None:
        assert BaseScanner.detect_language(path) == expected


# ═══════════════════════════════════════════════════════════════
# Inline suppression: anaya:disable
# ═══════════════════════════════════════════════════════════════

class TestAnayaDisableSuppression:
    """Tests for # anaya:disable inline suppression."""

    def test_blanket_anaya_disable(self, scanner, sample_rule):
        """# anaya:disable (no rule) suppresses all rules on the line."""
        content = 'password = "secret123"  # anaya:disable\n'
        violations = scanner.scan_file("app.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_specific_anaya_disable(self, scanner, sample_rule):
        """# anaya:disable=rule-id suppresses only that rule."""
        content = 'password = "secret123"  # anaya:disable=test/pack/no-hardcoded-password\n'
        violations = scanner.scan_file("app.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_anaya_disable_slug_only(self, scanner, sample_rule):
        """# anaya:disable=slug works without the pack prefix."""
        content = 'password = "secret123"  # anaya:disable=no-hardcoded-password\n'
        violations = scanner.scan_file("app.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_anaya_disable_wrong_rule(self, scanner, sample_rule):
        """# anaya:disable=other-rule does NOT suppress this rule."""
        content = 'password = "secret123"  # anaya:disable=some-other-rule\n'
        violations = scanner.scan_file("app.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1

    def test_anaya_disable_multiple_rules(self, scanner, sample_rule):
        """# anaya:disable=rule1, rule2 suppresses both."""
        content = 'password = "secret123"  # anaya:disable=no-hardcoded-password, other-rule\n'
        violations = scanner.scan_file("app.py", content, [sample_rule], "test/pack")
        assert len(violations) == 0

    def test_anaya_disable_js_comment(self, scanner, sample_rule):
        """// anaya:disable works for JS-style comments."""
        content = 'const password = "secret123"; // anaya:disable\n'
        violations = scanner.scan_file("app.js", content, [sample_rule], "test/pack")
        assert len(violations) == 0


# ═══════════════════════════════════════════════════════════════
# Confidence scoring
# ═══════════════════════════════════════════════════════════════

class TestConfidenceScoring:
    """Tests for file-path-based confidence scoring."""

    def test_prod_file_gets_high_confidence(self, scanner, sample_rule):
        content = 'password = "secret123"\n'
        violations = scanner.scan_file("src/config.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1
        assert violations[0].confidence == 0.85

    def test_test_file_gets_low_confidence(self, scanner, sample_rule):
        content = 'password = "secret123"\n'
        violations = scanner.scan_file("tests/test_auth.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1
        assert violations[0].confidence == 0.3

    def test_migration_file_gets_medium_confidence(self, scanner, sample_rule):
        content = 'password = "secret123"\n'
        violations = scanner.scan_file("app/migrations/0001_initial.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1
        assert violations[0].confidence == 0.4

    def test_fixture_filename_detected(self, scanner, sample_rule):
        content = 'password = "secret123"\n'
        violations = scanner.scan_file("data/load_fixtures.py", content, [sample_rule], "test/pack")
        assert len(violations) == 1
        assert violations[0].confidence == 0.3


# ═══════════════════════════════════════════════════════════════
# Utils unit tests
# ═══════════════════════════════════════════════════════════════

class TestUtilsFunctions:
    """Tests for anaya.engine.utils module."""

    def test_is_line_suppressed_blanket(self):
        from anaya.engine.utils import is_line_suppressed
        assert is_line_suppressed('x = 1  # anaya:disable', 'any/rule') is True

    def test_is_line_suppressed_specific(self):
        from anaya.engine.utils import is_line_suppressed
        assert is_line_suppressed('x = 1  # anaya:disable=pack/rule-a', 'pack/rule-a') is True
        assert is_line_suppressed('x = 1  # anaya:disable=pack/rule-a', 'pack/rule-b') is False

    def test_is_line_suppressed_slug(self):
        from anaya.engine.utils import is_line_suppressed
        assert is_line_suppressed('x = 1  # anaya:disable=rule-a', 'pack/rule-a') is True

    def test_is_line_suppressed_no_comment(self):
        from anaya.engine.utils import is_line_suppressed
        assert is_line_suppressed('x = 1', 'pack/rule-a') is False

    def test_is_test_file_fixtures_filename(self):
        from anaya.engine.utils import is_test_file
        assert is_test_file("data/load_fixtures.py") is True
        assert is_test_file("management/commands/load_fixtures.py") is True

    def test_is_test_file_standard_patterns(self):
        from anaya.engine.utils import is_test_file
        assert is_test_file("tests/test_auth.py") is True
        assert is_test_file("src/__tests__/foo.js") is True
        assert is_test_file("app.spec.ts") is True
        assert is_test_file("lib/payment.py") is False
