"""
GitHub Check Run reporter — builds API payloads for the Checks API.

Converts ScanResult into the JSON body expected by
POST /repos/{owner}/{repo}/check-runs and PATCH updates.

See: https://docs.github.com/en/rest/checks/runs
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from anaya.engine.models import ScanResult, Violation


# GitHub Check Run annotation levels
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "failure",
    "HIGH": "failure",
    "MEDIUM": "warning",
    "LOW": "warning",
    "INFO": "notice",
}

# GitHub limits annotations to 50 per API call
MAX_ANNOTATIONS_PER_UPDATE = 50


def _violation_to_annotation(violation: Violation) -> dict[str, Any]:
    """Convert a Violation to a GitHub Check Run annotation dict."""
    # Normalize Windows backslashes to forward slashes for GitHub API
    normalized_path = violation.file_path.replace("\\", "/")
    annotation: dict[str, Any] = {
        "path": normalized_path,
        "start_line": violation.line_start,
        "end_line": violation.line_end,
        "annotation_level": _SEVERITY_TO_LEVEL.get(violation.severity.value, "warning"),
        "title": f"[{violation.severity.value}] {violation.rule_name}",
        "message": violation.message,
    }
    if violation.fix_hint:
        annotation["raw_details"] = f"Fix: {violation.fix_hint}"
    return annotation


def build_create_payload(
    name: str = "AnaYa Compliance Scan",
    head_sha: str = "",
) -> dict[str, Any]:
    """
    Build the initial POST payload to create a check run (status=in_progress).

    Args:
        name: The check run name.
        head_sha: The commit SHA to associate with.

    Returns:
        Dict ready for JSON serialization.
    """
    return {
        "name": name,
        "head_sha": head_sha,
        "status": "in_progress",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


def build_complete_payload(result: ScanResult) -> dict[str, Any]:
    """
    Build the PATCH payload to complete a check run with results.

    Args:
        result: The completed ScanResult.

    Returns:
        Dict ready for JSON serialization.
    """
    summary = result.summary

    # Build summary text
    lines = [
        f"## AnaYa Compliance Scan — {summary.overall_status.upper()}",
        "",
        f"**Files scanned:** {summary.total_files_scanned}",
        f"**Total violations:** {summary.total_violations}",
        f"**Duration:** {result.scan_duration_ms}ms",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev_name, count in summary.by_severity.items():
        if count > 0:
            lines.append(f"| {sev_name} | {count} |")

    if summary.by_pack:
        lines.extend([
            "",
            "### By Pack",
            "",
            "| Pack | Violations |",
            "|------|-----------|",
        ])
        for pack_id, count in summary.by_pack.items():
            lines.append(f"| {pack_id} | {count} |")

    summary_text = "\n".join(lines)

    # GitHub limits summary text to 65535 characters
    if len(summary_text) > 65_000:
        summary_text = summary_text[:65_000] + "\n\n... (truncated)"

    # Build annotations (first batch — may need multiple PATCH calls for >50)
    annotations = [
        _violation_to_annotation(v)
        for v in result.violations[:MAX_ANNOTATIONS_PER_UPDATE]
    ]

    # Map overall_status to check run conclusion
    conclusion_map = {
        "passed": "success",
        "warned": "neutral",
        "failed": "failure",
    }
    conclusion = conclusion_map.get(summary.overall_status, "neutral")

    return {
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "output": {
            "title": f"AnaYa: {summary.total_violations} violation(s) found",
            "summary": summary_text,
            "annotations": annotations,
        },
    }


def build_annotation_batches(
    violations: list[Violation],
) -> list[list[dict[str, Any]]]:
    """
    Split violations into annotation batches of MAX_ANNOTATIONS_PER_UPDATE.

    GitHub limits annotations to 50 per API call. If there are more,
    subsequent PATCH calls are needed.

    Returns:
        List of annotation lists, each at most 50 items.
    """
    annotations = [_violation_to_annotation(v) for v in violations]
    batches = []
    for i in range(0, len(annotations), MAX_ANNOTATIONS_PER_UPDATE):
        batches.append(annotations[i : i + MAX_ANNOTATIONS_PER_UPDATE])
    return batches
