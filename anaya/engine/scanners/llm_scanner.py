"""
LLM scanner — two-phase Auditor/Critic contextual analysis.

Phase 1 (Auditor): Sends file content + all LLM rules to the model.
                   Asks it to identify potential violations.
Phase 2 (Critic):  Sends the Auditor's findings back to the model and asks
                   it to verify each one. Only violations the Critic confirms
                   survive. This dramatically reduces false positives.

Uses the sync OpenAI client to fit inside the BaseScanner interface
(scan_file is synchronous). Falls back gracefully on any error — never
crashes the scan pipeline.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from anaya.engine.llm_guard import (
    LLMCallBlocked,
    guard_llm_call,
    record_llm_failure,
    record_llm_success,
    redact_secrets,
)
from anaya.engine.models import LLMRule, Severity, Violation
from anaya.engine.scanners.base import BaseScanner

if TYPE_CHECKING:
    from anaya.engine.models import Rule

logger = logging.getLogger(__name__)

# Matches: # noqa  |  // noqa  |  # noqa: rule-id
NOQA_PATTERN = re.compile(
    r"(?:#|//)\s*noqa(?::\s*([\w/,.\-\s]+))?", re.IGNORECASE
)

# ─── System prompts ─────────────────────────────────────────

AUDITOR_SYSTEM = """\
You are a compliance code auditor. You analyze source code for policy violations.

You will be given:
1. A source code file with numbered lines
2. A list of compliance rules to check

For each rule, examine the code carefully and identify violations.
Focus on INTENT and CONTEXT — not just string matching.
Look for ABSENT safeguards (missing consent, missing encryption, missing auth)
as well as PRESENT violations (hardcoded secrets, unvalidated input).

Respond with a JSON object:
{
  "violations": [
    {
      "rule_id": "the-rule-id",
      "line_start": 10,
      "line_end": 15,
      "message": "Specific explanation of what is wrong",
      "confidence": 0.85,
      "snippet": "the offending line of code"
    }
  ]
}

If no violations found, return: {"violations": []}

IMPORTANT:
- Only report violations you are genuinely confident about (>0.6)
- Line numbers must reference actual lines in the provided code
- Be specific in your message — explain WHY it's a violation
- Do NOT report violations on lines with "# noqa" or "// noqa" comments
"""

CRITIC_SYSTEM = """\
You are a compliance review critic. Your job is to verify violations
found by an auditor. You must be STRICT — reject anything uncertain.

You will be given:
1. The original source code
2. A list of candidate violations from the auditor

For each violation, decide:
- "keep": this is a real violation with clear evidence in the code
- "reject": this is a false positive, speculative, or not supported by the code

Respond with a JSON object:
{
  "reviewed": [
    {
      "rule_id": "the-rule-id",
      "line_start": 10,
      "verdict": "keep",
      "adjusted_confidence": 0.9,
      "reason": "Brief justification"
    }
  ]
}

Rejection criteria (reject if ANY apply):
- The violation is speculative ("might", "could", "possibly")
- The relevant safeguard exists elsewhere in the file
- The line does not actually do what the auditor claims
- The code is test/mock/fixture code, not production logic
- The confidence should be below 0.6
"""


def _build_numbered_source(content: str) -> str:
    """Add line numbers to source code for the LLM prompt."""
    lines = content.splitlines()
    numbered = []
    for i, line in enumerate(lines, 1):
        numbered.append(f"{i:4d} | {line}")
    return "\n".join(numbered)


def _build_rules_description(rules: list[LLMRule], pack_id: str) -> str:
    """Build a structured description of all LLM rules for the prompt."""
    parts = []
    for rule in rules:
        section = f"Rule ID: {pack_id}/{rule.id}\n"
        section += f"Name: {rule.name}\n"
        section += f"Severity: {rule.severity.value}\n"
        section += f"What to check: {rule.prompt}\n"
        if rule.examples:
            section += "Example violations:\n"
            for ex in rule.examples:
                section += f"  - {ex}\n"
        parts.append(section)
    return "\n---\n".join(parts)


class LLMScanner(BaseScanner):
    """
    Two-phase LLM scanner: Auditor finds violations, Critic verifies them.

    Uses the sync OpenAI client. Falls back gracefully on any error.
    """

    def __init__(self) -> None:
        from anaya.config import settings

        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for LLM scanner")

        from openai import OpenAI

        kwargs: dict[str, Any] = {
            "api_key": settings.openai_api_key,
            "timeout": settings.llm_timeout,
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url

        self._client = OpenAI(**kwargs)
        self._model = settings.openai_model
        self._max_file_tokens = settings.llm_max_file_tokens

    def scan_file(
        self,
        file_path: str,
        content: str,
        rules: list[Rule],
        pack_id: str,
    ) -> list[Violation]:
        """
        Scan a file using two-phase LLM analysis.

        1. Filter to LLMRule instances only
        2. Check token budget (skip oversized files)
        3. Phase 1: Auditor pass — find candidate violations
        4. Phase 2: Critic pass — verify candidates
        5. Build Violation objects from surviving findings
        """
        # Filter to only LLM rules
        llm_rules = [r for r in rules if isinstance(r, LLMRule) and r.enabled]
        if not llm_rules:
            return []

        # Check language match
        language = self.detect_language(file_path)
        applicable_rules = [
            r for r in llm_rules
            if "*" in r.languages or language in (r.languages if r.languages else [])
        ]
        if not applicable_rules:
            return []

        # Token budget check (rough: ~4 chars per token)
        estimated_tokens = len(content) // 4
        if estimated_tokens > self._max_file_tokens:
            logger.info(
                "Skipping LLM scan for %s (~%d tokens, limit %d)",
                file_path, estimated_tokens, self._max_file_tokens,
            )
            return []

        try:
            # Phase 1: Auditor
            candidates = self._auditor_pass(content, applicable_rules, pack_id, file_path)
            if not candidates:
                return []

            logger.info(
                "LLM Auditor found %d candidate(s) in %s",
                len(candidates), file_path,
            )

            # Phase 2: Critic
            verified = self._critic_pass(content, candidates, file_path)

            logger.info(
                "LLM Critic kept %d/%d violation(s) in %s",
                len(verified), len(candidates), file_path,
            )

            # Build Violation objects
            return self._build_violations(
                verified, applicable_rules, pack_id, file_path, content,
            )

        except LLMCallBlocked as exc:
            logger.warning("LLM scanner blocked for %s: %s", file_path, exc)
            return []
        except Exception:
            logger.exception("LLM scanner error for %s — skipping", file_path)
            return []

    def _auditor_pass(
        self,
        content: str,
        rules: list[LLMRule],
        pack_id: str,
        file_path: str,
    ) -> list[dict]:
        """Phase 1: Ask the LLM to find potential violations."""
        guard_llm_call()  # circuit breaker + rate limiter

        numbered_source = _build_numbered_source(content)
        rules_desc = _build_rules_description(rules, pack_id)

        user_message = (
            f"## File: {file_path}\n\n"
            f"```\n{numbered_source}\n```\n\n"
            f"## Rules to check:\n\n{rules_desc}"
        )

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": AUDITOR_SYSTEM},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # Low temperature for consistent analysis
            )
            record_llm_success()
        except Exception:
            record_llm_failure()
            raise

        if not response.choices:
            logger.warning("Auditor returned empty choices for %s", file_path)
            return []

        raw = response.choices[0].message.content
        if not raw:
            return []

        try:
            data = json.loads(raw)
            return data.get("violations", [])
        except json.JSONDecodeError:
            logger.warning("Auditor returned invalid JSON for %s", file_path)
            return []

    def _critic_pass(
        self,
        content: str,
        candidates: list[dict],
        file_path: str,
    ) -> list[dict]:
        """Phase 2: Ask the LLM to verify each candidate violation."""
        guard_llm_call()  # circuit breaker + rate limiter

        numbered_source = _build_numbered_source(content)

        candidates_json = json.dumps(candidates, indent=2)
        user_message = (
            f"## File: {file_path}\n\n"
            f"```\n{numbered_source}\n```\n\n"
            f"## Candidate violations to review:\n\n"
            f"```json\n{candidates_json}\n```"
        )

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": CRITIC_SYSTEM},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,  # Zero temperature for strict verification
            )
            record_llm_success()
        except Exception:
            record_llm_failure()
            raise

        if not response.choices:
            logger.warning("Critic returned empty choices for %s", file_path)
            return []

        raw = response.choices[0].message.content
        if not raw:
            return []

        try:
            data = json.loads(raw)
            reviewed = data.get("reviewed", [])
        except json.JSONDecodeError:
            logger.warning("Critic returned invalid JSON for %s", file_path)
            return []

        # Build a lookup of kept violations
        kept_keys = set()
        confidence_map: dict[str, float] = {}
        for item in reviewed:
            if item.get("verdict") == "keep":
                key = (item.get("rule_id", ""), item.get("line_start", 0))
                kept_keys.add(key)
                confidence_map[f"{item.get('rule_id')}:{item.get('line_start')}"] = (
                    item.get("adjusted_confidence", 0.7)
                )

        # Filter candidates to only kept ones, update confidence
        verified = []
        for c in candidates:
            key = (c.get("rule_id", ""), c.get("line_start", 0))
            if key in kept_keys:
                conf_key = f"{c.get('rule_id')}:{c.get('line_start')}"
                c["confidence"] = confidence_map.get(conf_key, c.get("confidence", 0.7))
                verified.append(c)

        return verified

    def _build_violations(
        self,
        verified: list[dict],
        rules: list[LLMRule],
        pack_id: str,
        file_path: str,
        content: str,
    ) -> list[Violation]:
        """Convert verified LLM findings into Violation objects."""
        # Build rule lookup
        rule_map: dict[str, LLMRule] = {}
        for r in rules:
            rule_map[f"{pack_id}/{r.id}"] = r

        lines = content.splitlines()
        if not lines:
            return []
        violations: list[Violation] = []

        for finding in verified:
            rule_id = finding.get("rule_id", "")
            rule = rule_map.get(rule_id)
            if not rule:
                continue

            line_start = finding.get("line_start", 1)
            line_end = finding.get("line_end", line_start)

            # Clamp line numbers to valid range
            line_start = max(1, min(line_start, len(lines)))
            line_end = max(line_start, min(line_end, len(lines)))

            # Check noqa / anaya:disable suppression
            if line_start <= len(lines):
                source_line = lines[line_start - 1]
                noqa_match = NOQA_PATTERN.search(source_line)
                if noqa_match:
                    noqa_rules_str = noqa_match.group(1)
                    if noqa_rules_str is None:
                        continue  # Blanket noqa
                    suppressed = [r.strip() for r in noqa_rules_str.split(",")]
                    if rule_id in suppressed:
                        continue

                from anaya.engine.utils import is_line_suppressed
                if is_line_suppressed(source_line, rule_id):
                    continue

            # Get snippet — redact any secrets before storing
            snippet = finding.get("snippet", "")
            if not snippet and line_start <= len(lines):
                snippet = lines[line_start - 1].strip()[:200]
            snippet = redact_secrets(snippet)

            confidence = finding.get("confidence", 0.7)
            # Adjust confidence for test files / migrations
            from anaya.engine.utils import is_test_file, is_migration_file
            if is_test_file(file_path):
                confidence = min(confidence, 0.3)
            elif is_migration_file(file_path):
                confidence = min(confidence, 0.4)
            # Only include findings with confidence >= 0.6 (unless test/migration)
            if confidence < 0.6 and not is_test_file(file_path) and not is_migration_file(file_path):
                continue

            message = finding.get("message", rule.message)
            # Substitute placeholders
            message = message.replace("{file}", file_path)
            message = message.replace("{line}", str(line_start))

            violations.append(
                Violation(
                    rule_id=rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    message=message,
                    snippet=snippet[:200],
                    fix_hint=rule.fix_hint,
                    references=rule.references,
                    confidence=confidence,
                )
            )

        return violations
