"""
AST-based scanner using tree-sitter.

Handles:
- Tree-sitter S-expression queries against parsed ASTs
- @fn_name capture filtering via name_regex
- @fn_body absence checks via must_not_contain
- Lazy language/parser loading
- Graceful handling of invalid queries and missing parsers
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from anaya.engine.models import ASTRule, Severity, Violation
from anaya.engine.scanners.base import BaseScanner
from anaya.engine.utils import get_confidence, is_line_suppressed, is_test_file, CONFIDENCE_AST

if TYPE_CHECKING:
    from tree_sitter import Language, Node, Parser
    from anaya.engine.models import Rule

logger = logging.getLogger(__name__)

# ── Lazy language registry ───────────────────────────────────

_LANGUAGES: dict[str, Language] = {}
_PARSERS: dict[str, Parser] = {}


def _get_language(lang: str) -> Language | None:
    """Lazily load a tree-sitter language object."""
    if lang in _LANGUAGES:
        return _LANGUAGES[lang]

    try:
        from tree_sitter import Language as TSLanguage  # noqa: N811

        if lang == "python":
            import tree_sitter_python as tsp

            _LANGUAGES[lang] = TSLanguage(tsp.language())
        elif lang == "javascript":
            import tree_sitter_javascript as tsjs

            _LANGUAGES[lang] = TSLanguage(tsjs.language())
        else:
            logger.debug("No tree-sitter grammar installed for language '%s'", lang)
            return None
    except ImportError:
        logger.warning("tree-sitter-%s package is not installed", lang)
        return None

    return _LANGUAGES[lang]


def _get_parser(lang: str) -> Parser | None:
    """Lazily create a tree-sitter parser for the given language."""
    if lang in _PARSERS:
        return _PARSERS[lang]

    ts_language = _get_language(lang)
    if ts_language is None:
        return None

    from tree_sitter import Parser as TSParser

    parser = TSParser(ts_language)
    _PARSERS[lang] = parser
    return parser


def _as_node(capture):
    """Normalize a capture value to a single Node (handles list or Node)."""
    if isinstance(capture, list):
        return capture[0] if capture else None
    return capture


# ═══════════════════════════════════════════════════════════════

class ASTScanner(BaseScanner):
    """Tree-sitter AST query scanner."""

    def scan_file(
        self,
        file_path: str,
        content: str,
        rules: list[Rule],
        pack_id: str,
    ) -> list[Violation]:
        """
        Scan file content against AST rules using tree-sitter.

        Only processes ASTRule instances. Other rule types are skipped.
        """
        language = self.detect_language(file_path)
        violations: list[Violation] = []
        _is_test = is_test_file(file_path)

        # Filter to only ASTRules
        ast_rules = [r for r in rules if isinstance(r, ASTRule)]

        for rule in ast_rules:
            # Skip disabled rules
            if not rule.enabled:
                continue

            # skip_tests: silently drop this rule for test/spec/fixture files
            if rule.skip_tests and _is_test:
                continue

            # Check language match
            if "*" not in rule.languages and language not in rule.languages:
                continue

            # Get parser for this language
            parser = _get_parser(language)
            if parser is None:
                continue

            ts_language = _get_language(language)
            if ts_language is None:
                continue

            # Parse the file
            tree = parser.parse(content.encode("utf-8"))

            # Compile and execute the query
            try:
                from tree_sitter import Query, QueryCursor

                query = Query(ts_language, rule.query)
                cursor = QueryCursor(query)
                matches = cursor.matches(tree.root_node)
            except Exception as e:
                logger.warning(
                    "Invalid tree-sitter query in rule '%s' (pack '%s'): %s",
                    rule.id,
                    pack_id,
                    e,
                )
                continue

            fully_qualified_id = f"{pack_id}/{rule.id}"
            lines = content.splitlines()

            for _pattern_idx, captures in matches:
                # Extract captured nodes
                fn_name_node = _as_node(captures.get("fn_name"))
                fn_body_node = _as_node(captures.get("fn_body"))

                # Determine the primary node for violation location
                primary_node = fn_name_node
                if primary_node is None:
                    # Use the first available capture
                    for _cap_name, cap_val in captures.items():
                        primary_node = _as_node(cap_val)
                        if primary_node is not None:
                            break

                if primary_node is None:
                    continue

                # ── 1. name_regex filter ─────────────────────────
                if rule.name_regex and fn_name_node is not None:
                    fn_name_text = fn_name_node.text.decode("utf-8")
                    if not re.search(rule.name_regex, fn_name_text):
                        continue  # Name doesn't match filter

                # ── 2. must_not_contain filter (absence = violation) ─
                if rule.must_not_contain and fn_body_node is not None:
                    fn_body_text = fn_body_node.text.decode("utf-8")
                    if re.search(rule.must_not_contain, fn_body_text):
                        continue  # Body DOES contain it — not a violation

                # ── 3. anaya:disable suppression ────────────────
                line_start = primary_node.start_point[0] + 1  # 0-indexed → 1-indexed
                line_end = primary_node.end_point[0] + 1

                if line_start <= len(lines) and is_line_suppressed(lines[line_start - 1], fully_qualified_id):
                    continue

                snippet = lines[line_start - 1].strip()[:200] if line_start <= len(lines) else ""

                message = (
                    rule.message.replace("{file}", file_path)
                    .replace("{line}", str(line_start))
                )

                # Cap severity at MEDIUM for test-file violations.
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
                        line_start=line_start,
                        line_end=line_end,
                        col_start=primary_node.start_point[1] + 1,
                        col_end=primary_node.end_point[1] + 1,
                        message=message,
                        snippet=snippet,
                        fix_hint=rule.fix_hint,
                        references=rule.references,
                        confidence=get_confidence(file_path, CONFIDENCE_AST),
                        in_test_file=_is_test,
                    )
                )

        return violations
