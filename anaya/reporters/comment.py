"""
PR comment reporter — builds markdown summary comments for pull requests.

Generates a severity-grouped, collapsible markdown comment with:
- Critical/High violations shown prominently
- Test file violations collapsed
- Low-confidence findings collapsed
- References and remediation included
"""

from __future__ import annotations

from anaya.engine.models import ScanResult, Severity, Violation
from anaya.engine.utils import CONFIDENCE_TEST_THRESHOLD, is_test_file


_SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

_STATUS_EMOJI: dict[str, str] = {
    "passed": "✅",
    "warned": "⚠️",
    "failed": "❌",
}


def build_comment(result: ScanResult, *, max_violations: int = 30) -> str:
    """
    Build a markdown PR comment from a ScanResult.

    Groups violations by severity, collapses test files and
    low-confidence findings.

    Args:
        result: The completed scan result.
        max_violations: Maximum violations to list in detail.

    Returns:
        Markdown string ready for the GitHub PR comment API body.
    """
    summary = result.summary
    status_emoji = _STATUS_EMOJI.get(summary.overall_status, "")
    lines: list[str] = []

    # Header
    lines.append(f"## {status_emoji} AnaYa Compliance Scan — **{summary.overall_status.upper()}**")
    lines.append("")

    # Quick stats
    lines.append(f"**Commit:** `{result.commit_sha[:8]}`  ")
    lines.append(f"**Files scanned:** {summary.total_files_scanned}  ")
    lines.append(f"**Violations:** {summary.total_violations}  ")
    lines.append(f"**Duration:** {result.scan_duration_ms}ms  ")
    lines.append("")

    # Severity table
    lines.append("### Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        count = summary.by_severity.get(sev.value, 0)
        emoji = _SEVERITY_EMOJI.get(sev.value, "")
        lines.append(f"| {emoji} {sev.value} | {count} |")
    lines.append("")

    # Pack breakdown
    if summary.by_pack:
        lines.append("### By Pack")
        lines.append("")
        lines.append("| Pack | Violations |")
        lines.append("|------|-----------|")
        for pack_id, count in sorted(summary.by_pack.items()):
            lines.append(f"| `{pack_id}` | {count} |")
        lines.append("")

    if not result.violations:
        lines.append("---")
        lines.append("*Powered by [AnaYa](https://github.com/anaya-compliance/anaya) v1.0.0*")
        return "\n".join(lines)

    # Partition violations
    prod_violations: list[Violation] = []
    test_violations: list[Violation] = []
    low_conf_violations: list[Violation] = []

    for v in result.violations:
        if v.confidence < CONFIDENCE_TEST_THRESHOLD:
            low_conf_violations.append(v)
        elif is_test_file(v.file_path):
            test_violations.append(v)
        else:
            prod_violations.append(v)

    # ── Production violations by severity ────────────────────
    shown_count = 0
    if prod_violations:
        by_sev: dict[Severity, list[Violation]] = {}
        for v in prod_violations:
            by_sev.setdefault(v.severity, []).append(v)

        for sev in Severity:
            vlist = by_sev.get(sev, [])
            if not vlist:
                continue

            # Stop listing if we've already shown max_violations
            remaining = max_violations - shown_count
            if remaining <= 0:
                break

            emoji = _SEVERITY_EMOJI[sev.value]
            lines.append(f"### {emoji} {sev.value} ({len(vlist)})")
            lines.append("")
            lines.append("| Rule | File | Line | Confidence |")
            lines.append("|------|------|------|------------|")

            for v in vlist[:remaining]:
                rule_short = v.rule_id.rsplit("/", 1)[-1]
                fp = v.file_path.replace("\\", "/")
                lines.append(
                    f"| `{rule_short}` | `{fp}` | {v.line_start} | {v.confidence:.0%} |"
                )
                shown_count += 1
            lines.append("")

            # Show details for critical/high
            if sev in (Severity.CRITICAL, Severity.HIGH):
                for v in vlist[:10]:
                    _append_violation_detail(lines, v)

        if shown_count < len(prod_violations):
            remaining_total = len(prod_violations) - shown_count
            lines.append(
                f"*Showing {shown_count}/{len(prod_violations)} violations "
                f"— {remaining_total} more not shown.*"
            )
            lines.append("")

    # ── Test file violations (collapsed) ─────────────────────
    if test_violations:
        lines.append("<details>")
        lines.append(f"<summary>🧪 <strong>Test File Findings ({len(test_violations)})</strong> — click to expand</summary>")
        lines.append("")
        lines.append("| Rule | File | Line |")
        lines.append("|------|------|------|")
        for v in test_violations[:20]:
            rule_short = v.rule_id.rsplit("/", 1)[-1]
            fp = v.file_path.replace("\\", "/")
            lines.append(f"| `{rule_short}` | `{fp}` | {v.line_start} |")
        if len(test_violations) > 20:
            lines.append(f"| ... | *{len(test_violations) - 20} more* | |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # ── Low confidence (collapsed) ──────────────────────────
    if low_conf_violations:
        lines.append("<details>")
        lines.append(f"<summary>🔽 <strong>Low Confidence ({len(low_conf_violations)})</strong> — click to expand</summary>")
        lines.append("")
        lines.append("| Rule | File | Line | Confidence |")
        lines.append("|------|------|------|------------|")
        for v in low_conf_violations[:15]:
            rule_short = v.rule_id.rsplit("/", 1)[-1]
            fp = v.file_path.replace("\\", "/")
            lines.append(
                f"| `{rule_short}` | `{fp}` | {v.line_start} | {v.confidence:.0%} |"
            )
        if len(low_conf_violations) > 15:
            lines.append(f"| ... | *{len(low_conf_violations) - 15} more* | | |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Powered by [AnaYa](https://github.com/anaya-compliance/anaya) v1.0.0*")

    return "\n".join(lines)


def _append_violation_detail(lines: list[str], v: Violation) -> None:
    """Append detailed violation info (for critical/high findings)."""
    emoji = _SEVERITY_EMOJI.get(v.severity.value, "")

    lines.append(f"#### {emoji} `{v.rule_id}`")
    lines.append(f"**{v.file_path.replace(chr(92), '/')}:{v.line_start}** — {v.message}")

    if v.snippet:
        lines.append(f"```\n{v.snippet}\n```")

    if v.fix_hint:
        lines.append(f"> 💡 **Fix:** {v.fix_hint}")

    if v.references:
        refs = " · ".join(f"[{i+1}]({r})" for i, r in enumerate(v.references[:3]))
        lines.append(f"> 📚 {refs}")

    lines.append("")
