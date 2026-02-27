"""
Rich table reporter — formats scan results as a terminal table.

Used by the CLI `scan` command for human-readable output.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from anaya.engine.models import ScanResult, Severity, Violation


_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _severity_text(severity: Severity) -> Text:
    """Create a styled Rich Text for a severity level."""
    style = _SEVERITY_STYLES.get(severity.value, "")
    return Text(severity.value, style=style)


def render_violations_table(
    violations: list[Violation],
    *,
    console: Console | None = None,
    title: str = "AnaYa Scan Results",
) -> None:
    """
    Print a Rich table of violations to the console.

    Args:
        violations: List of Violation objects to display.
        console: Optional Rich Console (defaults to stderr).
        title: Table title.
    """
    if console is None:
        console = Console(stderr=True)

    if not violations:
        console.print("[bold green]✓ No violations found[/bold green]")
        return

    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Rule", style="bold", min_width=20)
    table.add_column("File", min_width=20)
    table.add_column("Line", width=6, justify="right")
    table.add_column("Message", ratio=2)

    for i, v in enumerate(violations, start=1):
        table.add_row(
            str(i),
            _severity_text(v.severity),
            v.rule_id,
            v.file_path,
            str(v.line_start),
            v.message,
        )

    console.print(table)


def render_summary(result: ScanResult, *, console: Console | None = None) -> None:
    """
    Print a summary block after the violations table.

    Shows severity counts, packs run, and overall status with color.
    """
    if console is None:
        console = Console(stderr=True)

    summary = result.summary

    # Status line
    status_style = {
        "passed": "bold green",
        "warned": "bold yellow",
        "failed": "bold red",
    }.get(summary.overall_status, "")

    console.print()
    console.print(f"[bold]Scan Summary[/bold]  ({result.scan_duration_ms}ms)")
    console.print(f"  Files scanned:    {summary.total_files_scanned}")
    console.print(f"  Total violations: {summary.total_violations}")

    # Severity breakdown
    for sev in Severity:
        count = summary.by_severity.get(sev.value, 0)
        if count > 0:
            style = _SEVERITY_STYLES.get(sev.value, "")
            console.print(f"    [{style}]{sev.value}: {count}[/{style}]")

    # Packs
    if result.packs_run:
        console.print(f"  Packs:            {', '.join(result.packs_run)}")

    console.print(f"  Status:           [{status_style}]{summary.overall_status.upper()}[/{status_style}]")
    console.print()
