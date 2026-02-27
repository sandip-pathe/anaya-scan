"""
Tests for the AST scanner.

Covers:
- Python dirty fixtures trigger violations (financial functions without audit logs)
- Python clean fixtures have zero violations
- JavaScript dirty fixtures trigger violations
- JavaScript clean fixtures have zero violations
- name_regex filtering
- must_not_contain filtering
- Invalid query handling
- Disabled rule skipping
- Language filtering
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from anaya.engine.models import ASTRule, Severity, Violation
from anaya.engine.rule_loader import load_pack
from anaya.engine.scanners.ast_scanner import ASTScanner

from conftest import (
    JS_CLEAN_DIR,
    JS_DIRTY_DIR,
    PYTHON_CLEAN_DIR,
    PYTHON_DIRTY_DIR,
)


# ── Test fixtures ─────────────────────────────────────────────

AUDIT_PACK_PATH = str(Path(__file__).parent.parent / "anaya" / "packs" / "generic" / "audit-logging.yml")


@pytest.fixture
def ast_scanner() -> ASTScanner:
    return ASTScanner()


@pytest.fixture
def audit_pack():
    return load_pack(AUDIT_PACK_PATH)


@pytest.fixture
def python_ast_rule() -> ASTRule:
    """A standalone Python AST rule for unit tests."""
    return ASTRule(
        id="test-missing-audit",
        name="Test Missing Audit",
        severity=Severity.HIGH,
        enabled=True,
        message="Function at {file}:{line} missing audit log",
        languages=["python"],
        query="(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
        name_regex="(?i)(transfer|disburse|debit|credit|repay)",
        must_not_contain="(?i)(audit_log|logger\\.audit)",
    )


@pytest.fixture
def js_ast_rule() -> ASTRule:
    """A standalone JavaScript AST rule for unit tests."""
    return ASTRule(
        id="test-missing-audit-js",
        name="Test Missing Audit JS",
        severity=Severity.HIGH,
        enabled=True,
        message="Function at {file}:{line} missing audit log",
        languages=["javascript"],
        query="(function_declaration name: (identifier) @fn_name body: (statement_block) @fn_body)",
        name_regex="(?i)(transfer|disburse|debit|credit|repay)",
        must_not_contain="(?i)(auditLog|audit_log|logger\\.audit)",
    )


# ═══════════════════════════════════════════════════════════════
# Test: Python dirty fixture triggers violations
# ═══════════════════════════════════════════════════════════════

class TestASTScannerPython:
    def test_dirty_audit_fixture_triggers(self, ast_scanner, python_ast_rule):
        """Financial functions without audit_log should fire."""
        fixture = PYTHON_DIRTY_DIR / "audit.py"
        content = fixture.read_text(encoding="utf-8")
        violations = ast_scanner.scan_file(
            str(fixture), content, [python_ast_rule], "test/pack"
        )
        # The dirty fixture has: transfer_funds, disburse_loan, debit_account,
        # credit_account, repay_loan — all without audit_log
        assert len(violations) >= 4, f"Expected >=4 violations, got {len(violations)}"

        # All violations should be HIGH
        for v in violations:
            assert v.severity == Severity.HIGH

        # Check function names are in the expected set
        fn_names_in_violations = set()
        for v in violations:
            # Extract fn name from snippet
            for name in ["transfer_funds", "disburse_loan", "debit_account", "credit_account", "repay_loan"]:
                if name in (v.snippet or ""):
                    fn_names_in_violations.add(name)

        assert "transfer_funds" in fn_names_in_violations
        assert "debit_account" in fn_names_in_violations

    def test_clean_audit_fixture_has_zero_violations(self, ast_scanner, python_ast_rule):
        """Functions with proper audit_log calls should not fire."""
        fixture = PYTHON_CLEAN_DIR / "audit.py"
        content = fixture.read_text(encoding="utf-8")
        violations = ast_scanner.scan_file(
            str(fixture), content, [python_ast_rule], "test/pack"
        )
        assert len(violations) == 0, f"Expected 0 violations, got {len(violations)}: {[v.snippet for v in violations]}"

    def test_name_regex_filters_non_financial_functions(self, ast_scanner):
        """Functions not matching name_regex should not fire."""
        rule = ASTRule(
            id="test-name-filter",
            name="Test Name Filter",
            severity=Severity.HIGH,
            enabled=True,
            message="Test at {file}:{line}",
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
            name_regex="(?i)(transfer|disburse)",
            must_not_contain=None,
        )
        code = "def helper():\n    pass\n\ndef transfer():\n    pass\n"
        violations = ast_scanner.scan_file("test.py", code, [rule], "test/pack")
        # Only transfer() should match name_regex
        assert len(violations) == 1
        assert "transfer" in violations[0].snippet

    def test_must_not_contain_suppresses_when_present(self, ast_scanner):
        """Functions containing the required pattern should NOT fire."""
        rule = ASTRule(
            id="test-contain-filter",
            name="Test Contain Filter",
            severity=Severity.HIGH,
            enabled=True,
            message="Missing at {file}:{line}",
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
            name_regex="(?i)transfer",
            must_not_contain="(?i)audit_log",
        )
        code = "def transfer():\n    audit_log('done')\n"
        violations = ast_scanner.scan_file("test.py", code, [rule], "test/pack")
        assert len(violations) == 0


# ═══════════════════════════════════════════════════════════════
# Test: JavaScript dirty fixture triggers violations
# ═══════════════════════════════════════════════════════════════

class TestASTScannerJavaScript:
    def test_dirty_audit_fixture_triggers(self, ast_scanner, js_ast_rule):
        """JavaScript financial functions without auditLog should fire."""
        fixture = JS_DIRTY_DIR / "audit.js"
        content = fixture.read_text(encoding="utf-8")
        violations = ast_scanner.scan_file(
            str(fixture), content, [js_ast_rule], "test/pack"
        )
        assert len(violations) >= 4, f"Expected >=4 violations, got {len(violations)}"

    def test_clean_audit_fixture_has_zero_violations(self, ast_scanner, js_ast_rule):
        """JavaScript functions with proper auditLog calls should not fire."""
        fixture = JS_CLEAN_DIR / "audit.js"
        content = fixture.read_text(encoding="utf-8")
        violations = ast_scanner.scan_file(
            str(fixture), content, [js_ast_rule], "test/pack"
        )
        assert len(violations) == 0, f"Expected 0 violations, got {len(violations)}: {[v.snippet for v in violations]}"


# ═══════════════════════════════════════════════════════════════
# Test: Edge cases
# ═══════════════════════════════════════════════════════════════

class TestASTScannerEdgeCases:
    def test_disabled_rule_does_not_fire(self, ast_scanner):
        """Disabled AST rules should be skipped."""
        rule = ASTRule(
            id="disabled-rule",
            name="Disabled Rule",
            severity=Severity.HIGH,
            enabled=False,
            message="Should not fire",
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name)",
        )
        code = "def transfer():\n    pass\n"
        violations = ast_scanner.scan_file("test.py", code, [rule], "test/pack")
        assert len(violations) == 0

    def test_invalid_query_logs_warning(self, ast_scanner, caplog):
        """Invalid tree-sitter queries should log a warning, not crash."""
        rule = ASTRule(
            id="bad-query",
            name="Bad Query",
            severity=Severity.HIGH,
            enabled=True,
            message="Test",
            languages=["python"],
            query="(this_is_not_valid @cap)",
        )
        code = "def foo():\n    pass\n"
        with caplog.at_level(logging.WARNING):
            violations = ast_scanner.scan_file("test.py", code, [rule], "test/pack")
        assert len(violations) == 0
        # Should have logged a warning about invalid query
        assert any("Invalid" in r.message or "invalid" in r.message.lower() or "query" in r.message.lower() for r in caplog.records)

    def test_language_filtering(self, ast_scanner):
        """Python rules should not run on JavaScript files."""
        rule = ASTRule(
            id="python-only",
            name="Python Only",
            severity=Severity.HIGH,
            enabled=True,
            message="Test",
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name)",
        )
        code = "function foo() { return 1; }\n"
        violations = ast_scanner.scan_file("test.js", code, [rule], "test/pack")
        assert len(violations) == 0

    def test_unsupported_language_skipped(self, ast_scanner):
        """Rules for unsupported languages should be gracefully skipped."""
        rule = ASTRule(
            id="go-rule",
            name="Go Rule",
            severity=Severity.HIGH,
            enabled=True,
            message="Test",
            languages=["go"],
            query="(function_declaration name: (identifier) @fn_name)",
        )
        code = "package main\nfunc foo() {}\n"
        violations = ast_scanner.scan_file("test.go", code, [rule], "test/pack")
        assert len(violations) == 0

    def test_violation_has_correct_fields(self, ast_scanner):
        """Verify violation objects have expected field values."""
        rule = ASTRule(
            id="field-check",
            name="Field Check Rule",
            severity=Severity.MEDIUM,
            enabled=True,
            message="Found at {file}:{line}",
            fix_hint="Add audit logging",
            references=["https://example.com"],
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
            name_regex="(?i)transfer",
        )
        code = "def transfer(a):\n    a.do_stuff()\n"
        violations = ast_scanner.scan_file("app/payment.py", code, [rule], "test/pack")
        assert len(violations) == 1
        v = violations[0]
        assert v.rule_id == "test/pack/field-check"
        assert v.severity == Severity.MEDIUM
        assert v.file_path == "app/payment.py"
        assert v.line_start == 1
        assert v.message == "Found at app/payment.py:1"
        assert v.fix_hint == "Add audit logging"
        assert v.references == ["https://example.com"]
        assert v.confidence == 0.9  # CONFIDENCE_AST for production files

    def test_query_without_named_captures(self, ast_scanner):
        """Query with only @fn_name (no @fn_body) should still work."""
        rule = ASTRule(
            id="name-only",
            name="Name Only",
            severity=Severity.LOW,
            enabled=True,
            message="Function at {file}:{line}",
            languages=["python"],
            query="(function_definition name: (identifier) @fn_name)",
        )
        code = "def foo():\n    pass\ndef bar():\n    pass\n"
        violations = ast_scanner.scan_file("test.py", code, [rule], "test/pack")
        assert len(violations) == 2


# ═══════════════════════════════════════════════════════════════
# Test: Full pack loading
# ═══════════════════════════════════════════════════════════════

class TestASTScannerWithPack:
    def test_audit_pack_loads_ast_rules(self, audit_pack):
        """The audit-logging pack should contain 2 AST rules."""
        ast_rules = [r for r in audit_pack.rules if isinstance(r, ASTRule)]
        assert len(ast_rules) == 2
        assert ast_rules[0].name_regex is not None
        assert ast_rules[0].must_not_contain is not None
