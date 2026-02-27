"""
Compliance PR comment reporter — builds markdown for DPDP compliance findings.

Generates a structured markdown comment showing compliance status for each
DPDP section, with evidence, blockers, and remediation steps.
"""

from __future__ import annotations

from anaya.engine.compliance.analyzers.runner import ComplianceReport

_STATUS_EMOJI = {
    "COMPLIANT": "✅",
    "PARTIAL": "⚠️",
    "NON_COMPLIANT": "❌",
    "UNKNOWN": "❓",
}

_STATUS_LABEL = {
    "COMPLIANT": "Compliant",
    "PARTIAL": "Partially Compliant",
    "NON_COMPLIANT": "Non-Compliant",
    "UNKNOWN": "Unknown",
}


def build_compliance_comment(report: ComplianceReport) -> str:
    """
    Build a markdown PR comment from a ComplianceReport.

    Produces a clear, actionable summary with:
    - Overall compliance scorecard
    - Per-section status with evidence/blockers
    - Remediation steps for non-compliant sections

    Args:
        report: Completed DPDP compliance report.

    Returns:
        Markdown string ready for GitHub PR comment API.
    """
    lines: list[str] = []

    # ── Header ───────────────────────────────────────────────
    non_compliant = report.summary.get("NON_COMPLIANT", 0)
    partial = report.summary.get("PARTIAL", 0)
    compliant = report.summary.get("COMPLIANT", 0)

    if non_compliant == 0 and partial == 0:
        overall = "✅ COMPLIANT"
    elif non_compliant == 0:
        overall = "⚠️ PARTIALLY COMPLIANT"
    else:
        overall = "❌ NON-COMPLIANT"

    lines.append(f"## 🇮🇳 DPDP Compliance — **{overall}**")
    lines.append("")
    lines.append(
        f"**Repository:** `{report.repo_root}`  \n"
        f"**Commit:** `{(report.git_sha or 'unknown')[:12]}`  \n"
        f"**Sections analysed:** {len(report.sections)}  \n"
        f"**LLM calls:** {report.total_llm_calls}  \n"
        f"**Duration:** {report.elapsed_seconds:.1f}s"
    )
    lines.append("")

    # ── Scorecard table ──────────────────────────────────────
    lines.append("### Scorecard")
    lines.append("")
    lines.append("| Section | Title | Status |")
    lines.append("|---------|-------|--------|")

    for section in report.sections:
        emoji = _STATUS_EMOJI.get(section.status, "❓")
        lines.append(f"| {section.section} | {section.title} | {emoji} {_STATUS_LABEL.get(section.status, section.status)} |")

    lines.append("")

    # ── Summary counts ───────────────────────────────────────
    parts = []
    for status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT"):
        count = report.summary.get(status, 0)
        if count:
            parts.append(f"{_STATUS_EMOJI[status]} {count} {_STATUS_LABEL[status]}")
    if parts:
        lines.append(" · ".join(parts))
        lines.append("")

    # ── Details for non-compliant/partial sections ───────────
    flagged = [s for s in report.sections if s.status in ("NON_COMPLIANT", "PARTIAL")]
    if flagged:
        lines.append("### Findings")
        lines.append("")

        for section in flagged:
            emoji = _STATUS_EMOJI.get(section.status, "❓")
            lines.append(f"<details>")
            lines.append(
                f"<summary>{emoji} <strong>{section.section} {section.title}</strong> "
                f"— {_STATUS_LABEL.get(section.status, section.status)}</summary>"
            )
            lines.append("")

            if section.evidence:
                lines.append("**Evidence:**")
                for ev in section.evidence[:10]:
                    lines.append(f"- {ev}")
                lines.append("")

            if section.blockers:
                lines.append("**Blockers:**")
                for bl in section.blockers[:10]:
                    lines.append(f"- 🚫 {bl}")
                lines.append("")

            if section.remediation:
                lines.append("**Remediation:**")
                for rm in section.remediation[:5]:
                    lines.append(f"- 💡 {rm}")
                lines.append("")

            lines.append("</details>")
            lines.append("")

    # ── Compliant sections (collapsed) ───────────────────────
    ok_sections = [s for s in report.sections if s.status == "COMPLIANT"]
    if ok_sections:
        lines.append("<details>")
        lines.append(f"<summary>✅ <strong>{len(ok_sections)} Compliant Section(s)</strong> — click to expand</summary>")
        lines.append("")
        for section in ok_sections:
            lines.append(f"**{section.section} {section.title}**")
            if section.evidence:
                for ev in section.evidence[:5]:
                    lines.append(f"- {ev}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    # ── Footer ───────────────────────────────────────────────
    lines.append("---")
    lines.append(
        "*DPDP compliance analysis by [AnaYa](https://github.com/anaya-compliance/anaya) v1.0.0 "
        "· [Digital Personal Data Protection Act, 2023](https://www.meity.gov.in/data-protection-framework)*"
    )

    return "\n".join(lines)
