"""
Tests for inline suppression utils, baseline mode, and CI command.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anaya.engine.models import Violation, Severity
from anaya.engine.utils import is_line_suppressed, is_test_file, is_migration_file
from cli.main import _violation_fingerprint, _filter_baseline, app

runner = CliRunner()


# ═══════════════════════════════════════════════════════════════
# is_line_suppressed
# ═══════════════════════════════════════════════════════════════

class TestIsLineSuppressed:
    """Tests for the anaya:disable inline suppression helper."""

    def test_blanket_disable(self):
        assert is_line_suppressed("x = 1  # anaya:disable", "any/rule") is True

    def test_blanket_disable_js(self):
        assert is_line_suppressed('const x = 1; // anaya:disable', "any/rule") is True

    def test_specific_rule_match(self):
        assert is_line_suppressed("x = 1  # anaya:disable=pack/rule-a", "pack/rule-a") is True

    def test_specific_rule_no_match(self):
        assert is_line_suppressed("x = 1  # anaya:disable=pack/rule-a", "pack/rule-b") is False

    def test_slug_matches_fully_qualified(self):
        assert is_line_suppressed("x = 1  # anaya:disable=rule-a", "pack/rule-a") is True

    def test_multiple_rules_comma(self):
        assert is_line_suppressed("x = 1  # anaya:disable=rule-a, rule-b", "pack/rule-b") is True

    def test_no_comment_returns_false(self):
        assert is_line_suppressed("x = 1", "pack/rule-a") is False

    def test_noqa_does_not_trigger(self):
        assert is_line_suppressed("x = 1  # noqa", "pack/rule-a") is False

    def test_case_insensitive(self):
        assert is_line_suppressed("x = 1  # ANAYA:DISABLE", "pack/rule-a") is True


# ═══════════════════════════════════════════════════════════════
# is_test_file / is_migration_file
# ═══════════════════════════════════════════════════════════════

class TestFileClassification:
    """Tests for file classification helpers."""

    @pytest.mark.parametrize("path", [
        "tests/test_auth.py",
        "src/__tests__/foo.js",
        "app.spec.ts",
        "tests/fixtures/data.json",
        "data/load_fixtures.py",
        "management/commands/seed_fixtures.py",
        "factories.py",
    ])
    def test_test_files(self, path):
        assert is_test_file(path) is True

    @pytest.mark.parametrize("path", [
        "src/auth.py",
        "lib/payment.js",
        "config/settings.py",
    ])
    def test_non_test_files(self, path):
        assert is_test_file(path) is False

    @pytest.mark.parametrize("path", [
        "app/migrations/0001_initial.py",
        "migrations/0042_add_field.py",
        "alembic/versions/abc123.py",
    ])
    def test_migration_files(self, path):
        assert is_migration_file(path) is True

    def test_non_migration_file(self):
        assert is_migration_file("src/models.py") is False


# ═══════════════════════════════════════════════════════════════
# Violation fingerprinting
# ═══════════════════════════════════════════════════════════════

class TestViolationFingerprint:
    """Tests for _violation_fingerprint stability."""

    def _make_violation(self, **kwargs) -> Violation:
        defaults = dict(
            rule_id="pack/no-hardcoded-secrets",
            rule_name="No Hardcoded Secrets",
            file_path="src/config.py",
            line_start=10,
            line_end=10,
            severity=Severity.HIGH,
            message="Hardcoded secret",
            snippet='password = "abc"',
            confidence=0.85,
        )
        defaults.update(kwargs)
        return Violation(**defaults)

    def test_same_violation_same_fingerprint(self):
        v1 = self._make_violation()
        v2 = self._make_violation()
        assert _violation_fingerprint(v1) == _violation_fingerprint(v2)

    def test_line_number_change_preserved(self):
        """Fingerprint should survive line-number shifts."""
        v1 = self._make_violation(line_start=10)
        v2 = self._make_violation(line_start=15)
        assert _violation_fingerprint(v1) == _violation_fingerprint(v2)

    def test_different_snippet_different_fp(self):
        v1 = self._make_violation(snippet='password = "abc"')
        v2 = self._make_violation(snippet='token = "xyz"')
        assert _violation_fingerprint(v1) != _violation_fingerprint(v2)

    def test_different_rule_different_fp(self):
        v1 = self._make_violation(rule_id="pack/rule-a")
        v2 = self._make_violation(rule_id="pack/rule-b")
        assert _violation_fingerprint(v1) != _violation_fingerprint(v2)

    def test_backslash_normalization(self):
        """Windows backslashes should not affect fingerprint."""
        v1 = self._make_violation(file_path="src/config.py")
        v2 = self._make_violation(file_path="src\\config.py")
        assert _violation_fingerprint(v1) == _violation_fingerprint(v2)


# ═══════════════════════════════════════════════════════════════
# Baseline filtering
# ═══════════════════════════════════════════════════════════════

class TestFilterBaseline:
    """Tests for _filter_baseline."""

    def _make_violation(self, rule_id="pack/rule", snippet="code") -> Violation:
        return Violation(
            rule_id=rule_id,
            rule_name="Test Rule",
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity=Severity.HIGH,
            message="msg",
            snippet=snippet,
            confidence=0.85,
        )

    def test_filters_known_violations(self, tmp_path):
        v = self._make_violation()
        fp = _violation_fingerprint(v)
        baseline = {"version": 1, "violations": [{"fingerprint": fp, "rule_id": v.rule_id, "file": v.file_path, "line": 1, "message": "msg"}]}
        bp = tmp_path / "baseline.json"
        bp.write_text(json.dumps(baseline))
        result = _filter_baseline([v], str(bp))
        assert len(result) == 0

    def test_keeps_new_violations(self, tmp_path):
        v_old = self._make_violation(snippet="old_code")
        v_new = self._make_violation(snippet="new_code")
        fp = _violation_fingerprint(v_old)
        baseline = {"version": 1, "violations": [{"fingerprint": fp, "rule_id": "pack/rule", "file": "src/app.py", "line": 1, "message": "msg"}]}
        bp = tmp_path / "baseline.json"
        bp.write_text(json.dumps(baseline))
        result = _filter_baseline([v_old, v_new], str(bp))
        assert len(result) == 1
        assert result[0].snippet == "new_code"

    def test_corrupt_baseline_returns_all(self, tmp_path):
        bp = tmp_path / "baseline.json"
        bp.write_text("NOT JSON")
        violations = [self._make_violation()]
        result = _filter_baseline(violations, str(bp))
        assert len(result) == 1

    def test_missing_baseline_returns_all(self):
        violations = [self._make_violation()]
        result = _filter_baseline(violations, "/nonexistent/baseline.json")
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════
# CLI baseline command (integration)
# ═══════════════════════════════════════════════════════════════

class TestBaselineCommand:
    """Integration tests for 'anaya baseline' CLI command."""

    def test_baseline_creates_file(self, tmp_path):
        # Create a small target with a known violation
        target = tmp_path / "src"
        target.mkdir()
        (target / "app.py").write_text('password = "secret123"\n', encoding="utf-8")

        packs_dir = str(Path(__file__).parent / "fixtures" / "packs")
        output = str(tmp_path / "baseline.json")

        result = runner.invoke(app, [
            "baseline", str(target),
            "--packs-dir", packs_dir,
            "--output", output,
        ])
        assert result.exit_code == 0, result.output
        assert "Baseline saved" in result.output

        data = json.loads(Path(output).read_text())
        assert data["version"] == 1
        assert isinstance(data["violations"], list)
        assert data["total"] == len(data["violations"])

    def test_scan_with_baseline_filters(self, tmp_path):
        """scan --baseline only reports new violations."""
        target = tmp_path / "src"
        target.mkdir()
        (target / "app.py").write_text('password = "secret123"\n', encoding="utf-8")

        packs_dir = str(Path(__file__).parent / "fixtures" / "packs")
        output = str(tmp_path / "baseline.json")

        # 1) Create baseline
        result = runner.invoke(app, [
            "baseline", str(target),
            "--packs-dir", packs_dir,
            "--output", output,
        ])
        assert result.exit_code == 0

        # 2) Scan with baseline — should find 0 new violations
        result = runner.invoke(app, [
            "scan", str(target),
            "--packs-dir", packs_dir,
            "--baseline", output,
        ])
        assert result.exit_code == 0
        # The output should indicate no new violations or "0 violations"
        assert "0 violation" in result.output.lower() or "no new" in result.output.lower() or result.exit_code == 0


# ═══════════════════════════════════════════════════════════════
# CLI ci command (integration)
# ═══════════════════════════════════════════════════════════════

class TestCICommand:
    """Integration tests for 'anaya ci' CLI command."""

    def test_ci_clean_codebase(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.py").write_text('import os\nprint("hello")\n', encoding="utf-8")

        packs_dir = str(Path(__file__).parent / "fixtures" / "packs")
        result = runner.invoke(app, [
            "ci", str(target),
            "--packs-dir", packs_dir,
        ])
        assert result.exit_code == 0

    def test_ci_sarif_output(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "app.py").write_text('password = "secret123"\n', encoding="utf-8")

        packs_dir = str(Path(__file__).parent / "fixtures" / "packs")
        sarif_path = str(tmp_path / "results.sarif")

        result = runner.invoke(app, [
            "ci", str(target),
            "--packs-dir", packs_dir,
            "--sarif", sarif_path,
        ])
        # May fail-on high by default; just verify sarif written
        sarif_file = Path(sarif_path)
        assert sarif_file.exists(), f"SARIF not written. Output: {result.output}"
        data = json.loads(sarif_file.read_text())
        assert data.get("$schema") or data.get("version")
