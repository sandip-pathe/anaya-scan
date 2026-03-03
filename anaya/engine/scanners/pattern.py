"""
Pattern scanner — regex-based rule matching.

Handles:
- Line-by-line regex matching
- exclude_patterns suppression (fires BEFORE noqa)
- Inline noqa suppression (# noqa / // noqa)
- Snippet redaction for secrets
- Malformed regex graceful handling
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from anaya.engine.models import PatternRule, Severity, Violation
from anaya.engine.scanners.base import BaseScanner
from anaya.engine.utils import get_confidence, is_line_suppressed, is_test_file, CONFIDENCE_PATTERN_PROD

if TYPE_CHECKING:
    from anaya.engine.models import Rule

logger = logging.getLogger(__name__)

# Matches: # noqa  |  // noqa  |  # noqa: rule-id  |  # noqa: rule1, rule2
NOQA_PATTERN = re.compile(
    r"(?:#|//)\s*noqa(?::\s*([\w/,.\-\s]+))?", re.IGNORECASE
)


class PatternScanner(BaseScanner):
    """Regex-based pattern matching scanner."""

    def scan_file(
        self,
        file_path: str,
        content: str,
        rules: list[Rule],
        pack_id: str,
    ) -> list[Violation]:
        """
        Scan file content line-by-line against pattern rules.

        Only processes PatternRule instances. Other rule types are skipped.
        """
        language = self.detect_language(file_path)
        lines = content.splitlines()
        violations: list[Violation] = []
        _is_test = is_test_file(file_path)

        # Filter to only PatternRules
        pattern_rules = [r for r in rules if isinstance(r, PatternRule)]

        for rule in pattern_rules:
            # Skip disabled rules
            if not rule.enabled:
                continue

            # skip_tests: silently drop this rule for test/spec/fixture files
            if rule.skip_tests and _is_test:
                continue

            # Check language match
            if "*" not in rule.languages and language not in rule.languages:
                continue

            # Pre-compile patterns, skip malformed ones
            compiled_patterns: list[re.Pattern] = []
            for pat_str in rule.patterns:
                try:
                    compiled_patterns.append(re.compile(pat_str, re.IGNORECASE))
                except re.error as e:
                    logger.warning(
                        "Malformed regex in rule '%s' (pack '%s'): pattern '%s' — %s",
                        rule.id,
                        pack_id,
                        pat_str,
                        e,
                    )

            # Pre-compile exclude patterns
            compiled_excludes: list[re.Pattern] = []
            for ep_str in rule.exclude_patterns:
                try:
                    compiled_excludes.append(re.compile(ep_str, re.IGNORECASE))
                except re.error as e:
                    logger.warning(
                        "Malformed exclude regex in rule '%s' (pack '%s'): pattern '%s' — %s",
                        rule.id,
                        pack_id,
                        ep_str,
                        e,
                    )

            if not compiled_patterns:
                continue

            fully_qualified_id = f"{pack_id}/{rule.id}"

            for line_num, line in enumerate(lines, start=1):
                for compiled_pat in compiled_patterns:
                    match = compiled_pat.search(line)
                    if match is None:
                        continue

                    # ── 1. exclude_patterns check (fires BEFORE noqa) ────
                    if any(ep.search(line) for ep in compiled_excludes):
                        break  # Line is excluded, skip all patterns for this rule

                    # ── 2. noqa / anaya:disable suppression ─────────────
                    noqa_match = NOQA_PATTERN.search(line)
                    if noqa_match:
                        noqa_rules_str = noqa_match.group(1)
                        if noqa_rules_str is None:
                            # Blanket noqa — suppress all rules on this line
                            break
                        else:
                            # Specific noqa — check if this rule is listed
                            suppressed_rules = [
                                r.strip() for r in noqa_rules_str.split(",")
                            ]
                            if fully_qualified_id in suppressed_rules:
                                break

                    if is_line_suppressed(line, fully_qualified_id):
                        break

                    # ── 3. Build snippet with redaction ──────────────────
                    snippet = _build_snippet(line, match, rule)

                    # ── 4. Build message with placeholder substitution ───
                    message = rule.message.replace("{file}", file_path)
                    message = message.replace("{line}", str(line_num))
                    message = message.replace("{match}", match.group(0))

                    # Cap severity at MEDIUM for test-file violations so they
                    # never trigger a build failure on their own (CRITICAL/HIGH
                    # secrets in test fixtures are common and intentional).
                    effective_severity = (
                        Severity.MEDIUM
                        if _is_test and rule.severity > Severity.MEDIUM
                        else rule.severity
                    )

                    violations.append(
                        Violation(
                            rule_id=fully_qualified_id,
                            rule_name=rule.name,
                            severity=effective_severity,
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            col_start=match.start() + 1,
                            col_end=match.end() + 1,
                            message=message,
                            snippet=snippet,
                            fix_hint=rule.fix_hint,
                            references=rule.references,
                            confidence=get_confidence(file_path),
                            in_test_file=_is_test,
                        )
                    )
                    # One violation per line per rule (don't double-count)
                    break

        return violations


def _build_snippet(line: str, match: re.Match, rule: PatternRule) -> str:
    """
    Build a display snippet from the matched line.

    For rules tagged with 'secrets' or containing 'secret' / 'password' / 'key'
    in the rule ID, redact the matched portion to avoid persisting credentials.
    """
    is_secrets_rule = (
        "secrets" in rule.tags
        or any(
            kw in rule.id.lower()
            for kw in ("secret", "password", "key", "token", "credential", "pem", "jwt")
        )
    )

    if is_secrets_rule:
        snippet = (
            line[: match.start()] + "[REDACTED]" + line[match.end() :]
        ).strip()
    else:
        snippet = line.strip()

    # Truncate to 200 chars
    return snippet[:200]
