"""
Inline PR Review reporter — posts violations as line-by-line review comments.

This is how Semgrep, CodeQL, and SonarQube present findings in GitHub.
Each violation appears as a comment on the specific line in the PR diff.
Developers can resolve each inline, giving natural HITL workflow.

Uses GitHub's Pull Request Review API:
POST /repos/{owner}/{repo}/pulls/{pr}/reviews
"""

from __future__ import annotations

import logging
from typing import Any

from anaya.engine.models import Severity, Violation
from anaya.engine.utils import CONFIDENCE_TEST_THRESHOLD, is_test_file

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

# GitHub limits review comments to 40 per review
MAX_INLINE_COMMENTS = 40


def build_review_payload(
    violations: list[Violation],
    commit_sha: str,
    *,
    confidence_threshold: float = CONFIDENCE_TEST_THRESHOLD,
    max_comments: int = MAX_INLINE_COMMENTS,
) -> dict[str, Any] | None:
    """
    Build a GitHub PR Review payload with inline comments per violation.

    Only includes violations above the confidence threshold.
    Returns None if no violations to post.

    Args:
        violations: List of violations from the scan.
        commit_sha: The HEAD commit SHA of the PR.
        confidence_threshold: Min confidence to include (default 0.5).
        max_comments: Max inline comments per review (GitHub limit: 40-50).

    Returns:
        Dict payload for POST /repos/{owner}/{repo}/pulls/{pr}/reviews,
        or None if no qualifying violations.
    """
    # Filter to high-confidence violations only
    high_conf = [v for v in violations if v.confidence >= confidence_threshold]

    if not high_conf:
        return None

    # Sort by severity (most severe first), then by file path
    severity_order = {s: i for i, s in enumerate(Severity)}
    high_conf.sort(key=lambda v: (severity_order.get(v.severity, 99), v.file_path, v.line_start))

    # Limit to max_comments
    to_post = high_conf[:max_comments]
    omitted = len(high_conf) - len(to_post)

    # Build inline comments
    comments: list[dict[str, Any]] = []
    for v in to_post:
        comments.append({
            "path": v.file_path.replace("\\", "/"),
            "line": v.line_start,
            "body": _format_inline_comment(v),
        })

    # Determine review event type
    has_critical_or_high = any(
        v.severity in (Severity.CRITICAL, Severity.HIGH) for v in to_post
    )
    event = "REQUEST_CHANGES" if has_critical_or_high else "COMMENT"

    # Build review body (summary)
    body = _build_review_summary(high_conf, omitted)

    return {
        "commit_id": commit_sha,
        "event": event,
        "body": body,
        "comments": comments,
    }


def _format_inline_comment(v: Violation) -> str:
    """Format a single violation as an inline review comment."""
    emoji = _SEVERITY_EMOJI.get(v.severity.value, "")
    test_badge = " `TEST`" if is_test_file(v.file_path) else ""

    lines = [
        f"{emoji} **{v.severity.value}**{test_badge} — {v.rule_name}",
        "",
        v.message,
    ]

    if v.fix_hint:
        lines.extend(["", f"💡 **Fix:** {v.fix_hint}"])

    if v.references:
        lines.append("")
        lines.append("📚 " + " · ".join(f"[ref]({r})" for r in v.references[:3]))

    lines.extend([
        "",
        f"<sub>Rule: `{v.rule_id}` · Confidence: {v.confidence:.0%}</sub>",
    ])

    return "\n".join(lines)


def _build_review_summary(violations: list[Violation], omitted: int) -> str:
    """Build the review body summary."""
    by_severity: dict[str, int] = {}
    for v in violations:
        by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1

    lines = [
        "## 🔍 AnaYa Compliance Review",
        "",
        f"Found **{len(violations)}** violation(s) above confidence threshold:",
    ]

    for sev in Severity:
        count = by_severity.get(sev.value, 0)
        if count > 0:
            emoji = _SEVERITY_EMOJI[sev.value]
            lines.append(f"- {emoji} **{sev.value}**: {count}")

    if omitted > 0:
        lines.extend([
            "",
            f"*{omitted} additional violation(s) omitted (GitHub limit). See Check Run for full list.*",
        ])

    test_count = sum(1 for v in violations if is_test_file(v.file_path))
    if test_count:
        lines.extend([
            "",
            f"ℹ️ {test_count} of these are in test files (marked with `TEST` badge).",
        ])

    lines.extend([
        "",
        "---",
        "*Resolve each comment after addressing or reviewing the finding.*",
        "*Powered by [AnaYa](https://github.com/anaya-compliance/anaya)*",
    ])

    return "\n".join(lines)
