"""
Tests for anaya.engine.scanners.llm_scanner — LLMScanner (two-phase Auditor/Critic).

All tests mock the OpenAI client so no real API calls are made.
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from anaya.engine.models import LLMRule, PatternRule, Severity, Violation
from anaya.engine.scanners.llm_scanner import (
    LLMScanner,
    _build_numbered_source,
    _build_rules_description,
)


# ─── Helpers ─────────────────────────────────────────────────


def _make_llm_rule(**overrides) -> LLMRule:
    """Build an LLMRule with sensible defaults."""
    defaults = dict(
        id="test-rule",
        name="Test Rule",
        type="llm",
        severity=Severity.HIGH,
        message="Test violation at {file}:{line}",
        fix_hint="Fix this issue",
        references=["https://example.com"],
        tags=["test"],
        languages=["python"],
        prompt="Check for test violations",
        examples=[],
    )
    defaults.update(overrides)
    return LLMRule(**defaults)


def _make_response(content: str):
    """Build a mock OpenAI ChatCompletion response."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def _auditor_response(violations: list[dict]):
    """Build a mock auditor JSON response."""
    return _make_response(json.dumps({"violations": violations}))


def _critic_response(reviewed: list[dict]):
    """Build a mock critic JSON response."""
    return _make_response(json.dumps({"reviewed": reviewed}))


# ─── Fixtures ────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_openai_key(monkeypatch):
    """Ensure OPENAI_API_KEY is available for Settings."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-12345")


@pytest.fixture
def mock_openai():
    """Patch OpenAI client and return the mock create method."""
    with patch("openai.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        yield mock_client.chat.completions.create


@pytest.fixture
def scanner(mock_openai) -> LLMScanner:
    """Build an LLMScanner with a mocked OpenAI client."""
    return LLMScanner()


@pytest.fixture
def sample_rule() -> LLMRule:
    return _make_llm_rule(
        id="no-consent-before-processing",
        name="No Consent Before Processing",
        severity=Severity.CRITICAL,
        prompt="Check if personal data is processed without obtaining user consent first.",
        languages=["python"],
    )


SAMPLE_PYTHON_CODE = """\
import db

def save_user_data(request):
    name = request.json["name"]
    email = request.json["email"]
    aadhaar = request.json["aadhaar"]
    db.users.insert({"name": name, "email": email, "aadhaar": aadhaar})
    return {"status": "saved"}
"""


# ─── Unit tests for helpers ──────────────────────────────────


class TestHelpers:
    def test_build_numbered_source(self):
        content = "line one\nline two\nline three"
        result = _build_numbered_source(content)
        lines = result.splitlines()
        assert len(lines) == 3
        assert "   1 | line one" in lines[0]
        assert "   2 | line two" in lines[1]
        assert "   3 | line three" in lines[2]

    def test_build_rules_description(self):
        rule = _make_llm_rule(
            id="my-rule",
            name="My Rule",
            severity=Severity.HIGH,
            prompt="Check something specific",
            examples=["Example 1", "Example 2"],
        )
        result = _build_rules_description([rule], "test-pack")
        assert "Rule ID: test-pack/my-rule" in result
        assert "Name: My Rule" in result
        assert "Severity: HIGH" in result
        assert "Check something specific" in result
        assert "Example 1" in result
        assert "Example 2" in result

    def test_build_rules_description_no_examples(self):
        rule = _make_llm_rule(examples=[])
        result = _build_rules_description([rule], "pack")
        assert "Example violations" not in result


# ─── Scanner initialization ─────────────────────────────────


class TestLLMScannerInit:
    def test_requires_api_key(self, mock_openai):
        with patch("anaya.config.settings") as mock_settings:
            mock_settings.openai_api_key = None
            with pytest.raises(ValueError, match="OPENAI_API_KEY"):
                LLMScanner()

    def test_creates_client_with_key(self, mock_openai):
        scanner = LLMScanner()
        assert scanner is not None
        assert scanner._model == "gpt-4o-mini"


# ─── Scan file: rule filtering ──────────────────────────────


class TestRuleFiltering:
    def test_skips_when_no_llm_rules(self, scanner, mock_openai):
        """Pattern rules should be ignored by LLM scanner."""
        pattern_rule = PatternRule(
            id="pat",
            name="Pattern",
            type="pattern",
            severity=Severity.HIGH,
            message="msg",
            tags=["t"],
            languages=["python"],
            patterns=[r"test"],
        )
        result = scanner.scan_file("app.py", "code", [pattern_rule], "pack")
        assert result == []
        mock_openai.assert_not_called()

    def test_skips_disabled_rules(self, scanner, mock_openai):
        """Disabled LLM rules should be filtered out."""
        rule = _make_llm_rule(enabled=False)
        result = scanner.scan_file("app.py", "code", [rule], "pack")
        assert result == []
        mock_openai.assert_not_called()

    def test_skips_wrong_language(self, scanner, mock_openai):
        """Rules that don't match file language should be skipped."""
        rule = _make_llm_rule(languages=["java"])
        result = scanner.scan_file("app.py", "x = 1", [rule], "pack")
        assert result == []
        mock_openai.assert_not_called()

    def test_wildcard_language_matches_all(self, scanner, mock_openai):
        """A rule with languages=["*"] should match any file."""
        rule = _make_llm_rule(languages=["*"])
        mock_openai.return_value = _auditor_response([])
        result = scanner.scan_file("app.py", "x = 1", [rule], "pack")
        assert result == []
        mock_openai.assert_called_once()  # Auditor was called


# ─── Token budget ────────────────────────────────────────────


class TestTokenBudget:
    def test_skips_oversized_files(self, scanner, mock_openai):
        """Files exceeding token budget should be skipped."""
        # Default max is 4000 tokens, ~16KB of code
        huge_content = "x = 1\n" * 10_000  # ~60K chars = ~15K tokens
        rule = _make_llm_rule()
        result = scanner.scan_file("big.py", huge_content, [rule], "pack")
        assert result == []
        mock_openai.assert_not_called()

    def test_small_files_proceed(self, scanner, mock_openai):
        rule = _make_llm_rule()
        mock_openai.return_value = _auditor_response([])
        result = scanner.scan_file("small.py", "x = 1", [rule], "pack")
        assert result == []
        mock_openai.assert_called_once()


# ─── Two-phase scanning ─────────────────────────────────────


class TestTwoPhaseScanning:
    def test_auditor_no_violations(self, scanner, mock_openai):
        """When auditor finds nothing, critic is not called."""
        rule = _make_llm_rule()
        mock_openai.return_value = _auditor_response([])
        result = scanner.scan_file("app.py", SAMPLE_PYTHON_CODE, [rule], "pack")
        assert result == []
        assert mock_openai.call_count == 1  # Only auditor

    def test_full_pipeline_finds_violation(self, scanner, mock_openai, sample_rule):
        """End-to-end: auditor finds, critic keeps, violation returned."""
        candidate = {
            "rule_id": "pack/no-consent-before-processing",
            "line_start": 7,
            "line_end": 7,
            "message": "Personal data inserted into DB without consent check",
            "confidence": 0.85,
            "snippet": 'db.users.insert({"name": name, "email": email, "aadhaar": aadhaar})',
        }
        critic_item = {
            "rule_id": "pack/no-consent-before-processing",
            "line_start": 7,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "No consent check before data processing",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]

        result = scanner.scan_file("app.py", SAMPLE_PYTHON_CODE, [sample_rule], "pack")

        assert len(result) == 1
        v = result[0]
        assert v.rule_id == "pack/no-consent-before-processing"
        assert v.line_start == 7
        assert v.confidence == 0.9
        assert v.severity == Severity.CRITICAL
        assert mock_openai.call_count == 2  # Auditor + Critic

    def test_critic_rejects_false_positive(self, scanner, mock_openai, sample_rule):
        """Critic can reject a finding — it should not appear in results."""
        candidate = {
            "rule_id": "pack/no-consent-before-processing",
            "line_start": 7,
            "line_end": 7,
            "message": "Violation",
            "confidence": 0.75,
            "snippet": "snippet",
        }
        critic_item = {
            "rule_id": "pack/no-consent-before-processing",
            "line_start": 7,
            "verdict": "reject",
            "adjusted_confidence": 0.3,
            "reason": "Consent is checked upstream",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]

        result = scanner.scan_file("app.py", SAMPLE_PYTHON_CODE, [sample_rule], "pack")
        assert result == []

    def test_multiple_violations_partial_keep(self, scanner, mock_openai):
        """Critic keeps some, rejects others."""
        rule_a = _make_llm_rule(id="rule-a")
        rule_b = _make_llm_rule(id="rule-b")

        candidates = [
            {"rule_id": "pack/rule-a", "line_start": 3, "line_end": 3,
             "message": "Issue A", "confidence": 0.8, "snippet": "x"},
            {"rule_id": "pack/rule-b", "line_start": 5, "line_end": 5,
             "message": "Issue B", "confidence": 0.7, "snippet": "y"},
        ]
        reviewed = [
            {"rule_id": "pack/rule-a", "line_start": 3,
             "verdict": "keep", "adjusted_confidence": 0.85, "reason": "Real"},
            {"rule_id": "pack/rule-b", "line_start": 5,
             "verdict": "reject", "adjusted_confidence": 0.3, "reason": "False"},
        ]
        mock_openai.side_effect = [
            _auditor_response(candidates),
            _critic_response(reviewed),
        ]

        result = scanner.scan_file(
            "app.py", SAMPLE_PYTHON_CODE, [rule_a, rule_b], "pack"
        )
        assert len(result) == 1
        assert result[0].rule_id == "pack/rule-a"


# ─── Confidence filtering ───────────────────────────────────


class TestConfidenceFiltering:
    def test_low_confidence_filtered_out(self, scanner, mock_openai):
        """Violations with confidence < 0.6 should be dropped."""
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Low confidence issue",
            "confidence": 0.5,
            "snippet": "x",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.5,
            "reason": "Uncertain",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []

    def test_high_confidence_kept(self, scanner, mock_openai):
        """Violations with confidence >= 0.6 should be kept."""
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Valid issue",
            "confidence": 0.8,
            "snippet": "x = 1",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.8,
            "reason": "Confirmed",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert len(result) == 1
        assert result[0].confidence == 0.8


# ─── Noqa suppression ───────────────────────────────────────


class TestNoqaSuppression:
    def test_blanket_noqa_suppresses(self, scanner, mock_openai):
        """A # noqa comment on the violation line should suppress it."""
        code = "x = 1  # noqa\n"
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.9,
            "snippet": "x = 1",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "Confirmed",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", code, [rule], "pack")
        assert result == []

    def test_targeted_noqa_suppresses_matching_rule(self, scanner, mock_openai):
        """# noqa: pack/test-rule should suppress only that rule."""
        code = "x = 1  # noqa: pack/test-rule\n"
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.9,
            "snippet": "x = 1",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "ok",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", code, [rule], "pack")
        assert result == []

    def test_targeted_noqa_does_not_suppress_other_rule(self, scanner, mock_openai):
        """# noqa: other-rule should NOT suppress test-rule."""
        code = "x = 1  # noqa: pack/other-rule\n"
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.9,
            "snippet": "x = 1",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "ok",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", code, [rule], "pack")
        assert len(result) == 1


# ─── Error handling ──────────────────────────────────────────


class TestErrorHandling:
    def test_auditor_invalid_json_returns_empty(self, scanner, mock_openai):
        """Invalid JSON from auditor should not crash."""
        rule = _make_llm_rule()
        mock_openai.return_value = _make_response("not json at all")
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []

    def test_critic_invalid_json_returns_empty(self, scanner, mock_openai):
        """Invalid JSON from critic should return empty (all candidates dropped)."""
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.8,
            "snippet": "x",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _make_response("broken json {{"),
        ]
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []

    def test_openai_exception_returns_empty(self, scanner, mock_openai):
        """Any OpenAI API exception should be caught and return empty."""
        rule = _make_llm_rule()
        mock_openai.side_effect = Exception("API timeout")
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []

    def test_empty_auditor_content_returns_empty(self, scanner, mock_openai):
        """Auditor returning None/empty content should return empty list."""
        rule = _make_llm_rule()
        mock_openai.return_value = _make_response("")
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []

    def test_empty_critic_content_returns_empty(self, scanner, mock_openai):
        """Critic returning empty content should drop all candidates."""
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.8,
            "snippet": "x",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _make_response(""),
        ]
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []


# ─── Violation construction ──────────────────────────────────


class TestViolationConstruction:
    def test_violation_fields_correct(self, scanner, mock_openai):
        """Verify all fields on the produced Violation object."""
        rule = _make_llm_rule(
            id="my-id",
            name="My Rule",
            severity=Severity.CRITICAL,
            fix_hint="Do something",
            references=["https://example.com"],
        )
        candidate = {
            "rule_id": "pack/my-id",
            "line_start": 1,
            "line_end": 1,
            "message": "Problem at {file}:{line}",
            "confidence": 0.9,
            "snippet": "x = 1",
        }
        critic_item = {
            "rule_id": "pack/my-id",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.95,
            "reason": "confirmed",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("main.py", "x = 1\n", [rule], "pack")
        assert len(result) == 1
        v = result[0]
        assert v.rule_id == "pack/my-id"
        assert v.rule_name == "My Rule"
        assert v.severity == Severity.CRITICAL
        assert v.file_path == "main.py"
        assert v.line_start == 1
        assert v.line_end == 1
        assert v.confidence == 0.95
        assert v.fix_hint == "Do something"
        assert v.references == ["https://example.com"]
        # Check placeholder substitution
        assert "main.py" in v.message
        assert "1" in v.message

    def test_line_clamping(self, scanner, mock_openai):
        """Out-of-range line numbers should be clamped."""
        rule = _make_llm_rule()
        # 2-line file, but auditor says line 999
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 999,
            "line_end": 1000,
            "message": "Issue",
            "confidence": 0.9,
            "snippet": "x",
        }
        critic_item = {
            "rule_id": "pack/test-rule",
            "line_start": 999,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "ok",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        code = "line1\nline2\n"
        result = scanner.scan_file("app.py", code, [rule], "pack")
        assert len(result) == 1
        assert result[0].line_start == 2  # Clamped to max line
        assert result[0].line_end == 2

    def test_unknown_rule_id_skipped(self, scanner, mock_openai):
        """Findings referencing a non-existent rule should be dropped."""
        rule = _make_llm_rule(id="known-rule")
        candidate = {
            "rule_id": "pack/unknown-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.9,
            "snippet": "x",
        }
        critic_item = {
            "rule_id": "pack/unknown-rule",
            "line_start": 1,
            "verdict": "keep",
            "adjusted_confidence": 0.9,
            "reason": "ok",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([critic_item]),
        ]
        result = scanner.scan_file("app.py", "x = 1\n", [rule], "pack")
        assert result == []


# ─── LLM prompt structure ───────────────────────────────────


class TestPromptStructure:
    def test_auditor_receives_numbered_source_and_rules(self, scanner, mock_openai):
        """Verify the auditor prompt contains numbered source and rule descriptions."""
        rule = _make_llm_rule(id="my-rule", prompt="Check for X")
        mock_openai.return_value = _auditor_response([])

        scanner.scan_file("app.py", "line1\nline2\n", [rule], "pack")

        call_args = mock_openai.call_args
        messages = call_args.kwargs.get("messages") or call_args[1].get("messages")
        user_msg = messages[1]["content"]

        # Numbered source
        assert "   1 | line1" in user_msg
        assert "   2 | line2" in user_msg

        # Rule description
        assert "Rule ID: pack/my-rule" in user_msg
        assert "Check for X" in user_msg

    def test_auditor_uses_low_temperature(self, scanner, mock_openai):
        rule = _make_llm_rule()
        mock_openai.return_value = _auditor_response([])
        scanner.scan_file("app.py", "x = 1\n", [rule], "pack")

        call_args = mock_openai.call_args
        temperature = call_args.kwargs.get("temperature") or call_args[1].get("temperature")
        assert temperature == 0.1

    def test_critic_uses_zero_temperature(self, scanner, mock_openai):
        rule = _make_llm_rule()
        candidate = {
            "rule_id": "pack/test-rule",
            "line_start": 1,
            "line_end": 1,
            "message": "Issue",
            "confidence": 0.8,
            "snippet": "x",
        }
        mock_openai.side_effect = [
            _auditor_response([candidate]),
            _critic_response([{
                "rule_id": "pack/test-rule", "line_start": 1,
                "verdict": "keep", "adjusted_confidence": 0.9, "reason": "ok",
            }]),
        ]
        scanner.scan_file("app.py", "x = 1\n", [rule], "pack")

        # Second call is critic
        critic_call = mock_openai.call_args_list[1]
        temperature = critic_call.kwargs.get("temperature") or critic_call[1].get("temperature")
        assert temperature == 0.0

    def test_json_response_format_requested(self, scanner, mock_openai):
        rule = _make_llm_rule()
        mock_openai.return_value = _auditor_response([])
        scanner.scan_file("app.py", "x = 1\n", [rule], "pack")

        call_args = mock_openai.call_args
        response_format = call_args.kwargs.get("response_format") or call_args[1].get("response_format")
        assert response_format == {"type": "json_object"}
