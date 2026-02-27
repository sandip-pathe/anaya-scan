"""
DPDP Compliance Runner.

Orchestrates all section analyzers, runs them concurrently, and produces
a structured ComplianceReport.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from pydantic import BaseModel, Field

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.analyzers.breach_notification import BreachNotificationAnalyzer
from anaya.engine.compliance.analyzers.children_data import ChildrenDataAnalyzer
from anaya.engine.compliance.analyzers.consent import ConsentAnalyzer
from anaya.engine.compliance.analyzers.data_localisation import DataLocalisationAnalyzer
from anaya.engine.compliance.analyzers.data_minimisation import DataMinimisationAnalyzer
from anaya.engine.compliance.analyzers.data_retention import DataRetentionAnalyzer
from anaya.engine.compliance.analyzers.encryption import EncryptionAnalyzer
from anaya.engine.compliance.analyzers.erasure import ErasureAnalyzer
from anaya.engine.compliance.models import CodebaseMap
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)

# Status display symbols
_STATUS_ICON = {
    "COMPLIANT": "\u2705",       # ✅
    "PARTIAL": "\u26a0\ufe0f",   # ⚠️
    "NON_COMPLIANT": "\u274c",   # ❌
    "UNKNOWN": "\u2753",         # ❓
}


class ComplianceReport(BaseModel):
    """Full DPDP compliance report for a codebase."""

    repo_root: str
    git_sha: str | None = None
    sections: list[SectionResult] = Field(default_factory=list)
    total_llm_calls: int = 0
    elapsed_seconds: float = 0.0
    summary: dict[str, int] = Field(default_factory=dict)

    def compute_summary(self) -> None:
        self.total_llm_calls = sum(s.llm_calls_made for s in self.sections)
        self.summary = {
            "COMPLIANT": sum(1 for s in self.sections if s.status == "COMPLIANT"),
            "PARTIAL": sum(1 for s in self.sections if s.status == "PARTIAL"),
            "NON_COMPLIANT": sum(1 for s in self.sections if s.status == "NON_COMPLIANT"),
            "UNKNOWN": sum(1 for s in self.sections if s.status == "UNKNOWN"),
        }

    def render_text(self) -> str:
        """Render a human-readable compliance report."""
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append("  DPDP COMPLIANCE REPORT")
        lines.append("=" * 72)
        lines.append(f"  Repository: {self.repo_root}")
        if self.git_sha:
            lines.append(f"  Commit:     {self.git_sha[:12]}")
        lines.append(
            f"  Sections:   {len(self.sections)}  |  "
            f"LLM calls: {self.total_llm_calls}  |  "
            f"Time: {self.elapsed_seconds:.1f}s"
        )
        lines.append("=" * 72)
        lines.append("")

        for section in self.sections:
            icon = _STATUS_ICON.get(section.status, "?")
            header = f"{section.section} {section.title}"
            lines.append(f"{icon} {header:<50} {section.status}")
            lines.append("-" * 72)

            if section.evidence:
                lines.append("  Evidence:")
                for ev in section.evidence:
                    # Wrap long lines
                    wrapped = _wrap(ev, indent=4, width=68)
                    lines.append(wrapped)

            if section.blockers:
                lines.append("")
                lines.append("  Blockers:")
                for bl in section.blockers:
                    wrapped = _wrap(bl, indent=4, width=68)
                    lines.append(wrapped)

            if section.remediation:
                lines.append("")
                lines.append("  Remediation:")
                for rm in section.remediation:
                    wrapped = _wrap(rm, indent=4, width=68)
                    lines.append(wrapped)

            lines.append("")
            lines.append("")

        # Summary bar
        lines.append("=" * 72)
        lines.append("  SUMMARY")
        lines.append("=" * 72)
        for status, count in self.summary.items():
            if count > 0:
                icon = _STATUS_ICON.get(status, "?")
                lines.append(f"  {icon} {status}: {count}")
        lines.append(f"  Total LLM calls: {self.total_llm_calls}")
        lines.append(f"  Total time: {self.elapsed_seconds:.1f}s")
        lines.append("=" * 72)

        return "\n".join(lines)


def _wrap(text: str, indent: int = 4, width: int = 68) -> str:
    """Simple line wrapping with indent."""
    prefix = " " * indent + "- "
    if len(text) + indent + 2 <= width:
        return prefix + text
    # Just return with prefix, let terminal wrap
    return prefix + text


class DPDPComplianceRunner:
    """
    Run all registered DPDP section analyzers and produce a ComplianceReport.

    Usage:
        runner = DPDPComplianceRunner()
        report = await runner.run(cmap, pii_map)
        print(report.render_text())
    """

    def __init__(self, analyzers: list[BaseAnalyzer] | None = None):
        """
        Args:
            analyzers: List of analyzers to run. If None, uses the default
                       set (§8(4), §7(3), §4).
        """
        if analyzers is not None:
            self._analyzers = analyzers
        else:
            self._analyzers: list[BaseAnalyzer] = [
                ConsentAnalyzer(),          # §4
                DataMinimisationAnalyzer(),  # §5
                ErasureAnalyzer(),           # §7(3)
                EncryptionAnalyzer(),        # §8(4)
                DataRetentionAnalyzer(),     # §8(5)
                BreachNotificationAnalyzer(),# §8(6)
                ChildrenDataAnalyzer(),      # §9
                DataLocalisationAnalyzer(),  # §11
            ]

    async def run(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> ComplianceReport:
        """Run all analyzers concurrently and produce a report."""
        t0 = time.perf_counter()

        logger.info(
            "Running %d DPDP section analyzers…", len(self._analyzers)
        )

        # Run all analyzers concurrently
        tasks = [
            analyzer.analyze(cmap, pii_map) for analyzer in self._analyzers
        ]
        results: list[SectionResult] = await asyncio.gather(*tasks)

        # Sort by section number
        results.sort(key=lambda r: r.section)

        elapsed = time.perf_counter() - t0

        report = ComplianceReport(
            repo_root=cmap.root,
            git_sha=cmap.git_sha,
            sections=results,
            elapsed_seconds=round(elapsed, 1),
        )
        report.compute_summary()

        logger.info(
            "Compliance analysis complete: %d sections, %d LLM calls, %.1fs",
            len(results),
            report.total_llm_calls,
            elapsed,
        )

        return report
