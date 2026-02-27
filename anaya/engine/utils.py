"""
Utility functions for the scan engine.

Includes:
- Test file detection (framework-agnostic)
- Confidence adjustment for test files
- Inline suppression via `# anaya:disable=rule-id`
"""

from __future__ import annotations

import re


# ═══════════════════════════════════════════════════════════════
# Inline suppression: # anaya:disable=rule-id[,rule-id2]
# ═══════════════════════════════════════════════════════════════

# Matches:
#   # anaya:disable=generic/owasp-top10/a03-sql-injection
#   // anaya:disable=rule1, rule2
#   # anaya:disable  (blanket — suppresses ALL rules on this line)
ANAYA_DISABLE_PATTERN = re.compile(
    r"(?:#|//)\s*anaya:disable(?:=\s*([\w/,.\-\s]+))?", re.IGNORECASE
)


def is_line_suppressed(line: str, rule_id: str) -> bool:
    """
    Check if a source line has an anaya:disable comment suppressing this rule.

    Supports:
      # anaya:disable               — blanket suppress all rules
      # anaya:disable=rule-id       — suppress one specific rule
      # anaya:disable=rule1, rule2  — suppress multiple rules
    """
    m = ANAYA_DISABLE_PATTERN.search(line)
    if not m:
        return False
    rules_str = m.group(1)
    if rules_str is None:
        return True  # blanket disable
    suppressed = [r.strip() for r in rules_str.split(",")]
    # Match fully-qualified ID or just the rule slug
    rule_slug = rule_id.rsplit("/", 1)[-1]
    return rule_id in suppressed or rule_slug in suppressed

# Patterns that indicate a file is a test file (framework-agnostic)
_TEST_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[\\/])tests?[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])__tests__[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])spec[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])test_[^/\\]+$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])[^/\\]+_test\.(?:py|go|rs|js|ts)$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])conftest\.py$", re.IGNORECASE),
    re.compile(r"\.(?:test|spec)\.(?:js|ts|jsx|tsx)$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])fixtures?[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])mocks?[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])testing[\\/]", re.IGNORECASE),
    # Filename-based detection (e.g. load_fixtures.py, test_data.json)
    re.compile(r"(?:^|[\\/])(?:load_|seed_|create_)?(?:fixtures?|test_data|fake_data|factory|factories)\.", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])(?:conftest|factories|test_helpers|test_utils)\.", re.IGNORECASE),
]

# Patterns that indicate a file is a migration (auto-generated)
_MIGRATION_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[\\/])migrations?[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])alembic[\\/]", re.IGNORECASE),
]

# Confidence levels
CONFIDENCE_PATTERN_PROD = 0.85
CONFIDENCE_PATTERN_TEST = 0.3
CONFIDENCE_PATTERN_MIGRATION = 0.4
CONFIDENCE_AST = 0.90
CONFIDENCE_LLM_DEFAULT = 0.75
CONFIDENCE_TEST_THRESHOLD = 0.5  # Below this, violations are "low confidence"


def is_test_file(file_path: str) -> bool:
    """
    Detect whether a file is a test file.

    Checks path patterns used by common frameworks:
    - Python: tests/, test_*.py, conftest.py
    - JavaScript/TypeScript: __tests__/, *.test.js, *.spec.ts
    - Go: *_test.go
    - General: fixtures/, mocks/, spec/
    """
    normalized = file_path.replace("\\", "/")
    return any(pat.search(normalized) for pat in _TEST_PATH_PATTERNS)


def is_migration_file(file_path: str) -> bool:
    """Detect whether a file is a database migration (auto-generated)."""
    normalized = file_path.replace("\\", "/")
    return any(pat.search(normalized) for pat in _MIGRATION_PATH_PATTERNS)


def get_confidence(file_path: str, base_confidence: float = CONFIDENCE_PATTERN_PROD) -> float:
    """
    Calculate confidence based on file path context.

    Test files and migrations get lower confidence since violations
    in them are less actionable.
    """
    if is_test_file(file_path):
        return CONFIDENCE_PATTERN_TEST
    if is_migration_file(file_path):
        return CONFIDENCE_PATTERN_MIGRATION
    return base_confidence
