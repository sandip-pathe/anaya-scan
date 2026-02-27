"""
AnaYa CLI — compliance-as-code command line interface.

Commands:
  scan           Scan a directory or file against rule packs
  compliance     Run DPDP compliance analysis on a codebase
  init           Create an anaya.yml config file
  packs list     List available rule packs
  validate-pack  Validate a rule pack YAML file
  test-rule      Test a single rule against a file
  test-pack      Test a pack against fixture directories
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from anaya.engine.models import (
    AnaYaConfig,
    ASTRule,
    LLMRule,
    PatternRule,
    ScanResult,
    Severity,
    Violation,
)
from anaya.engine.rule_loader import RuleLoadError, load_pack, load_pack_directory
from anaya.engine.scanners.base import BaseScanner
from anaya.engine.scanners.pattern import PatternScanner
from anaya.reporters.table import render_summary, render_violations_table

app = typer.Typer(
    name="anaya",
    help="AnaYa — compliance-as-code engine",
    no_args_is_help=True,
)
packs_app = typer.Typer(help="Manage rule packs")
app.add_typer(packs_app, name="packs")

console = Console(stderr=True)
err_console = Console(stderr=True, style="red")


# ═══════════════════════════════════════════════════════════════
# scan
# ═══════════════════════════════════════════════════════════════

@app.command()
def scan(
    target: str = typer.Argument(".", help="Directory or file to scan"),
    packs_dir: str = typer.Option("./anaya/packs", "--packs-dir", "-p", help="Rule packs directory"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, sarif"),
    fail_on: str = typer.Option("CRITICAL", "--fail-on", help="Minimum severity to fail (exit 1)"),
    warn_on: str = typer.Option("HIGH", "--warn-on", help="Minimum severity to warn"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to anaya.yml"),
    enable_llm: bool = typer.Option(False, "--enable-llm", help="Enable LLM-powered scanning (requires OPENAI_API_KEY)"),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b", help="Path to baseline JSON file — only report NEW violations"),
    enable_compliance: bool = typer.Option(False, "--compliance", help="Also run DPDP compliance analysis on the target directory"),
) -> None:
    """Scan files against compliance rule packs."""
    start_ms = time.time()

    # Load config
    if config_file and Path(config_file).exists():
        import yaml

        raw = yaml.safe_load(Path(config_file).read_text(encoding="utf-8"))
        config = AnaYaConfig.model_validate(raw)
    else:
        config = AnaYaConfig.default()

    # Override thresholds from CLI flags
    try:
        fail_severity = Severity(fail_on.upper())
        warn_severity = Severity(warn_on.upper())
    except ValueError:
        err_console.print(f"Invalid severity: {fail_on} or {warn_on}")
        raise typer.Exit(code=2)

    # Load packs
    try:
        packs = load_pack_directory(packs_dir)
    except Exception as e:
        err_console.print(f"Failed to load packs: {e}")
        raise typer.Exit(code=2)

    if not packs:
        err_console.print(f"No rule packs found in {packs_dir}")
        raise typer.Exit(code=2)

    # Collect files
    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    elif target_path.is_dir():
        files = _collect_files(target_path, config)
    else:
        err_console.print(f"Target not found: {target}")
        raise typer.Exit(code=2)

    # Initialize scanners
    pattern_scanner = PatternScanner()
    ast_scanner: BaseScanner | None = None
    try:
        from anaya.engine.scanners.ast_scanner import ASTScanner

        ast_scanner = ASTScanner()
    except ImportError:
        pass

    llm_scanner: BaseScanner | None = None
    if enable_llm:
        try:
            from anaya.engine.scanners.llm_scanner import LLMScanner

            llm_scanner = LLMScanner()
            console.print("[dim]LLM scanner enabled[/dim]")
        except Exception as e:
            err_console.print(f"LLM scanner not available: {e}")

    # Run scan
    all_violations: list[Violation] = []
    file_contents: dict[str, str] = {}  # keep for LLM enhancer
    packs_run: list[str] = []

    for pack in packs:
        packs_run.append(pack.manifest.id)
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Use relative path for ignore matching and reporting
            try:
                rel_path = str(file_path.relative_to(target_path)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")

            # Check ignore paths
            if _is_ignored(rel_path, config):
                continue

            file_contents[rel_path] = content

            # Pattern rules
            violations = pattern_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id)
            all_violations.extend(violations)

            # AST rules
            if ast_scanner:
                ast_violations = ast_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id)
                all_violations.extend(ast_violations)

            # LLM rules
            if llm_scanner:
                llm_violations = llm_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id)
                all_violations.extend(llm_violations)

    # LLM violation enhancer (enrich pattern/AST findings)
    if enable_llm and all_violations:
        try:
            from anaya.engine.scanners.llm_enhancer import LLMViolationEnhancer

            enhancer = LLMViolationEnhancer()
            by_file: dict[str, list[Violation]] = {}
            for v in all_violations:
                by_file.setdefault(v.file, []).append(v)

            for fpath, file_violations in by_file.items():
                fcontent = file_contents.get(fpath, "")
                if fcontent:
                    enhancer.enhance_violations(fpath, fcontent, file_violations)

            console.print(f"[dim]LLM enhancer processed {len(by_file)} files[/dim]")
        except Exception as e:
            err_console.print(f"LLM enhancer failed: {e}")

    # Baseline filtering — only keep NEW violations
    if baseline and Path(baseline).exists():
        all_violations = _filter_baseline(all_violations, baseline)
        if not all_violations:
            console.print(f"[dim]All violations are in baseline ({baseline})[/dim]")

    # Build summary
    duration_ms = int((time.time() - start_ms) * 1000)
    summary = ScanResult.build_summary(
        violations=all_violations,
        packs_run=packs_run,
        files_scanned=len(files),
        fail_on=fail_severity,
        warn_on=warn_severity,
    )

    result = ScanResult(
        repo="local",
        pr_number=0,
        commit_sha="local",
        violations=all_violations,
        packs_run=packs_run,
        scan_duration_ms=duration_ms,
        summary=summary,
    )

    # Output
    if output_format == "json":
        typer.echo(result.model_dump_json(indent=2))
    elif output_format == "sarif":
        from anaya.reporters.sarif_builder import build_sarif

        typer.echo(json.dumps(build_sarif(result), indent=2))
    else:
        render_violations_table(all_violations, console=console)
        render_summary(result, console=console)

    # ── Optional: DPDP compliance analysis ───────────────────
    if enable_compliance and target_path.is_dir():
        console.print("\n[bold]Running DPDP compliance analysis…[/bold]")
        try:
            from anaya.engine.compliance.indexer import CodebaseIndexer
            from anaya.engine.compliance.analyzers.runner import DPDPComplianceRunner

            indexer = CodebaseIndexer(str(target_path))
            cmap = indexer.build()

            import os
            if os.environ.get("OPENAI_API_KEY"):
                from anaya.engine.compliance.pii_mapper import PersonalDataMapper
                mapper = PersonalDataMapper()
                pii_map = mapper.map(cmap)
            else:
                from anaya.engine.compliance.pii_mapper import PersonalDataMap
                pii_map = PersonalDataMap(
                    pii_models=[], sensitive_models=[], aadhaar_fields=[],
                    health_fields=[], financial_fields=[],
                )
                console.print("[dim]No OPENAI_API_KEY — structural checks only[/dim]")

            runner = DPDPComplianceRunner()
            report = asyncio.run(runner.run(cmap, pii_map))
            typer.echo(report.render_text())
        except Exception as e:
            err_console.print(f"Compliance analysis failed: {e}")

    # Exit code
    if summary.overall_status == "failed":
        raise typer.Exit(code=1)
    elif summary.overall_status == "warned":
        raise typer.Exit(code=0)


def _collect_files(
    directory: Path,
    config: AnaYaConfig,
) -> list[Path]:
    """Collect scannable files from a directory, respecting ignore patterns."""
    from anaya.engine.scanners.base import LANGUAGE_MAP

    scannable_exts = set(LANGUAGE_MAP.keys())
    files: list[Path] = []

    for p in directory.rglob("*"):
        if not p.is_file():
            continue
        # Skip hidden directories (e.g. .git, .venv)
        parts = p.relative_to(directory).parts
        if any(part.startswith(".") for part in parts):
            continue
        # Skip __pycache__
        if "__pycache__" in parts:
            continue
        # Check extension
        ext = p.suffix.lower()
        if ext in scannable_exts:
            files.append(p)

    return sorted(files)


def _is_ignored(file_path: str, config: AnaYaConfig) -> bool:
    """Check if a file path matches any ignore patterns."""
    import fnmatch

    for pattern in config.ignore.paths:
        if fnmatch.fnmatch(file_path, pattern):
            return True
    return False


# ═══════════════════════════════════════════════════════════════
# compliance — DPDP compliance analysis
# ═══════════════════════════════════════════════════════════════

@app.command()
def compliance(
    target: str = typer.Argument(".", help="Root directory of the codebase to analyse"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text, json"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file instead of stdout"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM-powered analysis (PII classification, consent, etc.)"),
) -> None:
    """Run DPDP (Digital Personal Data Protection Act) compliance analysis.

    Analyses an entire codebase for compliance with the Indian DPDP Act 2023.
    Covers 8 sections: consent (§4), data minimisation (§5), erasure (§7),
    encryption (§8.4), retention (§8.5), breach notification (§8.6),
    children's data (§9), and data localisation (§11).

    Examples:

        anaya compliance ./my-django-app

        anaya compliance /path/to/repo --format json -o report.json

        anaya compliance . --no-llm   # structural checks only, no OpenAI calls
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn

    target_path = Path(target).resolve()
    if not target_path.is_dir():
        err_console.print(f"Target must be a directory: {target}")
        raise typer.Exit(code=2)

    # ── Step 1: Index codebase ───────────────────────────────
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("Indexing codebase (AST + grep)…", total=None)
        from anaya.engine.compliance.indexer import CodebaseIndexer
        indexer = CodebaseIndexer(str(target_path))
        cmap = indexer.build()

    cmap.compute_stats()
    console.print(
        f"[bold]Indexed:[/bold] {cmap.stats.get('total_models', 0)} models, "
        f"{cmap.stats.get('total_fields', 0)} fields, "
        f"{cmap.stats.get('total_endpoints', 0)} endpoints, "
        f"framework={cmap.framework.primary.value if cmap.framework else 'unknown'}"
    )

    if no_llm:
        # Run with empty PII map — structural checks only
        from anaya.engine.compliance.pii_mapper import PersonalDataMap
        pii_map = PersonalDataMap(
            pii_models=[],
            sensitive_models=[],
            aadhaar_fields=[],
            health_fields=[],
            financial_fields=[],
        )
        console.print("[dim]Skipping LLM analysis (--no-llm)[/dim]")
    else:
        # ── Step 2: Classify PII fields ──────────────────────
        import os
        if not os.environ.get("OPENAI_API_KEY"):
            err_console.print(
                "[red]OPENAI_API_KEY not set.[/red] "
                "Use --no-llm for structural checks only, or set the env var."
            )
            raise typer.Exit(code=2)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task("Classifying PII fields (LLM)…", total=None)
            from anaya.engine.compliance.pii_mapper import PersonalDataMapper
            mapper = PersonalDataMapper()
            pii_map = mapper.map(cmap)

        console.print(
            f"[bold]PII:[/bold] {len(pii_map.pii_models)} PII models, "
            f"{len(pii_map.aadhaar_fields)} Aadhaar, "
            f"{len(pii_map.health_fields)} health, "
            f"{len(pii_map.financial_fields)} financial"
        )

    # ── Step 3: Run section analyzers ────────────────────────
    from anaya.engine.compliance.analyzers.runner import DPDPComplianceRunner

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("Running 8 DPDP section analysers…", total=None)
        runner = DPDPComplianceRunner()
        report = asyncio.run(runner.run(cmap, pii_map))

    # ── Output ───────────────────────────────────────────────
    if output_format == "json":
        output_text = report.model_dump_json(indent=2)
    else:
        output_text = report.render_text()

    if output_file:
        Path(output_file).write_text(output_text, encoding="utf-8")
        console.print(f"[green]✓[/green] Report written to {output_file}")
    else:
        # Print to stdout (not stderr console)
        typer.echo(output_text)

    # ── Exit code ────────────────────────────────────────────
    non_compliant = report.summary.get("NON_COMPLIANT", 0)
    if non_compliant > 0:
        console.print(f"\n[yellow]{non_compliant} section(s) NON_COMPLIANT — exit 1[/yellow]")
        raise typer.Exit(code=1)
    else:
        console.print(f"\n[green]All sections compliant or partial — exit 0[/green]")


# ═══════════════════════════════════════════════════════════════
# init
# ═══════════════════════════════════════════════════════════════

@app.command()
def init(
    output: str = typer.Option("anaya.yml", "--output", "-o", help="Output file path"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file"),
) -> None:
    """Create a default anaya.yml configuration file."""
    out_path = Path(output)
    if out_path.exists() and not force:
        err_console.print(f"{output} already exists. Use --force to overwrite.")
        raise typer.Exit(code=1)

    import yaml

    config = AnaYaConfig.default()
    config_dict = config.model_dump(mode="json")
    yaml_str = yaml.dump(config_dict, default_flow_style=False, sort_keys=False)

    out_path.write_text(yaml_str, encoding="utf-8")
    console.print(f"[green]✓[/green] Created {output}")


# ═══════════════════════════════════════════════════════════════
# packs list
# ═══════════════════════════════════════════════════════════════

@packs_app.command("list")
def packs_list(
    packs_dir: str = typer.Option("./anaya/packs", "--packs-dir", "-p", help="Rule packs directory"),
) -> None:
    """List available rule packs."""
    try:
        packs = load_pack_directory(packs_dir)
    except Exception as e:
        err_console.print(f"Failed to load packs: {e}")
        raise typer.Exit(code=2)

    if not packs:
        console.print("No packs found.")
        return

    from rich.table import Table

    table = Table(title="Available Rule Packs", show_lines=True)
    table.add_column("Pack ID", style="bold")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Rules", justify="right")
    table.add_column("Description")

    for pack in sorted(packs, key=lambda p: p.manifest.id):
        table.add_row(
            pack.manifest.id,
            pack.manifest.name,
            pack.manifest.version,
            str(len(pack.rules)),
            pack.manifest.description,
        )

    console.print(table)


# ═══════════════════════════════════════════════════════════════
# validate-pack
# ═══════════════════════════════════════════════════════════════

@app.command("validate-pack")
def validate_pack(
    pack_file: str = typer.Argument(..., help="Path to rule pack YAML file"),
) -> None:
    """Validate a rule pack YAML file."""
    try:
        pack = load_pack(pack_file)
    except RuleLoadError as e:
        err_console.print(f"[red]✗[/red] Validation failed: {e}")
        raise typer.Exit(code=1)

    enabled = sum(1 for r in pack.rules if r.enabled)
    disabled = len(pack.rules) - enabled
    console.print(f"[green]✓[/green] Pack '{pack.manifest.id}' v{pack.manifest.version} is valid")
    console.print(f"  Rules: {len(pack.rules)} total ({enabled} enabled, {disabled} disabled)")

    # List rules
    from rich.table import Table

    table = Table(show_lines=False)
    table.add_column("ID", style="dim")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Enabled")

    for rule in pack.rules:
        enabled_str = "[green]✓[/green]" if rule.enabled else "[red]✗[/red]"
        table.add_row(rule.id, rule.type, rule.severity.value, enabled_str)

    console.print(table)


# ═══════════════════════════════════════════════════════════════
# test-rule
# ═══════════════════════════════════════════════════════════════

@app.command("test-rule")
def test_rule(
    pack_file: str = typer.Argument(..., help="Path to rule pack YAML file"),
    rule_id: str = typer.Argument(..., help="Rule ID to test"),
    target_file: str = typer.Argument(..., help="File to test against"),
) -> None:
    """Test a single rule against a target file."""
    try:
        pack = load_pack(pack_file)
    except RuleLoadError as e:
        err_console.print(f"Failed to load pack: {e}")
        raise typer.Exit(code=2)

    # Find the rule
    matching_rules = [r for r in pack.rules if r.id == rule_id]
    if not matching_rules:
        err_console.print(f"Rule '{rule_id}' not found in pack '{pack.manifest.id}'")
        available = ", ".join(r.id for r in pack.rules)
        err_console.print(f"Available rules: {available}")
        raise typer.Exit(code=2)

    rule = matching_rules[0]
    target = Path(target_file)
    if not target.exists():
        err_console.print(f"File not found: {target_file}")
        raise typer.Exit(code=2)

    content = target.read_text(encoding="utf-8", errors="replace")

    # Run appropriate scanner
    violations: list[Violation] = []
    if isinstance(rule, PatternRule):
        scanner = PatternScanner()
        violations = scanner.scan_file(str(target), content, [rule], pack.manifest.id)
    elif isinstance(rule, ASTRule):
        try:
            from anaya.engine.scanners.ast_scanner import ASTScanner

            scanner = ASTScanner()
            violations = scanner.scan_file(str(target), content, [rule], pack.manifest.id)
        except ImportError:
            err_console.print("AST scanner requires tree-sitter packages")
            raise typer.Exit(code=2)
    elif isinstance(rule, LLMRule):
        try:
            from anaya.engine.scanners.llm_scanner import LLMScanner

            scanner = LLMScanner()
            violations = scanner.scan_file(str(target), content, [rule], pack.manifest.id)
        except Exception as e:
            err_console.print(f"LLM scanner error: {e}")
            raise typer.Exit(code=2)

    if violations:
        render_violations_table(violations, console=console, title=f"Rule: {rule_id}")
        console.print(f"\n[yellow]{len(violations)} violation(s) found[/yellow]")
    else:
        console.print(f"[green]✓[/green] No violations for rule '{rule_id}'")


# ═══════════════════════════════════════════════════════════════
# test-pack
# ═══════════════════════════════════════════════════════════════

@app.command("test-pack")
def test_pack(
    pack_file: str = typer.Argument(..., help="Path to rule pack YAML file"),
    dirty_dir: str = typer.Argument(..., help="Directory with files that SHOULD trigger violations"),
    clean_dir: str = typer.Argument(..., help="Directory with files that should NOT trigger violations"),
) -> None:
    """Test a pack against dirty (should-fire) and clean (should-not-fire) fixture directories."""
    try:
        pack = load_pack(pack_file)
    except RuleLoadError as e:
        err_console.print(f"Failed to load pack: {e}")
        raise typer.Exit(code=2)

    pattern_scanner = PatternScanner()
    ast_scanner_inst: BaseScanner | None = None
    try:
        from anaya.engine.scanners.ast_scanner import ASTScanner

        ast_scanner_inst = ASTScanner()
    except ImportError:
        pass

    passed = True

    # Test dirty dir
    dirty_path = Path(dirty_dir)
    if dirty_path.exists():
        console.print(f"\n[bold]Testing dirty fixtures: {dirty_dir}[/bold]")
        for f in sorted(dirty_path.iterdir()):
            if not f.is_file():
                continue
            content = f.read_text(encoding="utf-8", errors="replace")
            violations = pattern_scanner.scan_file(str(f), content, pack.rules, pack.manifest.id)
            if ast_scanner_inst:
                violations.extend(
                    ast_scanner_inst.scan_file(str(f), content, pack.rules, pack.manifest.id)
                )
            if violations:
                console.print(f"  [green]✓[/green] {f.name}: {len(violations)} violation(s)")
            else:
                console.print(f"  [red]✗[/red] {f.name}: expected violations but got 0")
                passed = False
    else:
        err_console.print(f"Dirty dir not found: {dirty_dir}")
        passed = False

    # Test clean dir
    clean_path = Path(clean_dir)
    if clean_path.exists():
        console.print(f"\n[bold]Testing clean fixtures: {clean_dir}[/bold]")
        for f in sorted(clean_path.iterdir()):
            if not f.is_file():
                continue
            content = f.read_text(encoding="utf-8", errors="replace")
            violations = pattern_scanner.scan_file(str(f), content, pack.rules, pack.manifest.id)
            if ast_scanner_inst:
                violations.extend(
                    ast_scanner_inst.scan_file(str(f), content, pack.rules, pack.manifest.id)
                )
            if violations:
                console.print(f"  [red]✗[/red] {f.name}: {len(violations)} unexpected violation(s)")
                for v in violations:
                    console.print(f"      {v.rule_id} @ line {v.line_start}")
                passed = False
            else:
                console.print(f"  [green]✓[/green] {f.name}: clean (0 violations)")
    else:
        err_console.print(f"Clean dir not found: {clean_dir}")
        passed = False

    # Summary
    console.print()
    if passed:
        console.print("[bold green]✓ All test-pack checks passed[/bold green]")
    else:
        console.print("[bold red]✗ Some test-pack checks failed[/bold red]")
        raise typer.Exit(code=1)


# ═══════════════════════════════════════════════════════════════
# baseline — save current violations as accepted baseline
# ═══════════════════════════════════════════════════════════════

@app.command("baseline")
def create_baseline(
    target: str = typer.Argument(".", help="Directory or file to scan"),
    packs_dir: str = typer.Option("./anaya/packs", "--packs-dir", "-p", help="Rule packs directory"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to anaya.yml"),
    output: str = typer.Option(".anaya-baseline.json", "--output", "-o", help="Baseline output file"),
) -> None:
    """Create a baseline of current violations.

    Future scans with --baseline will only report NEW violations
    not present in this baseline. Use this when adopting AnaYa on
    an existing codebase to avoid alert fatigue.
    """
    start_ms = time.time()

    if config_file and Path(config_file).exists():
        import yaml
        raw = yaml.safe_load(Path(config_file).read_text(encoding="utf-8"))
        config = AnaYaConfig.model_validate(raw)
    else:
        config = AnaYaConfig.default()

    try:
        packs = load_pack_directory(packs_dir)
    except Exception as e:
        err_console.print(f"Failed to load packs: {e}")
        raise typer.Exit(code=2)

    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    elif target_path.is_dir():
        files = _collect_files(target_path, config)
    else:
        err_console.print(f"Target not found: {target}")
        raise typer.Exit(code=2)

    pattern_scanner = PatternScanner()
    ast_scanner: BaseScanner | None = None
    try:
        from anaya.engine.scanners.ast_scanner import ASTScanner
        ast_scanner = ASTScanner()
    except ImportError:
        pass

    all_violations: list[Violation] = []
    for pack in packs:
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            try:
                rel_path = str(file_path.relative_to(target_path)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
            if _is_ignored(rel_path, config):
                continue
            violations = pattern_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id)
            all_violations.extend(violations)
            if ast_scanner:
                all_violations.extend(ast_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id))

    # Build baseline fingerprints
    baseline_entries = []
    for v in all_violations:
        baseline_entries.append({
            "fingerprint": _violation_fingerprint(v),
            "rule_id": v.rule_id,
            "file": v.file_path.replace("\\", "/"),
            "line": v.line_start,
            "message": v.message[:200],
        })

    baseline_data = {
        "version": 1,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(baseline_entries),
        "violations": baseline_entries,
    }

    out_path = Path(output)
    out_path.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")

    duration = int((time.time() - start_ms) * 1000)
    console.print(
        f"[green]✓[/green] Baseline saved: {len(baseline_entries)} violations "
        f"in {output} ({duration}ms)"
    )
    console.print(
        f"[dim]Run scans with --baseline {output} to only see new violations[/dim]"
    )


# ═══════════════════════════════════════════════════════════════
# ci — CI/CD-optimized scan command
# ═══════════════════════════════════════════════════════════════

@app.command("ci")
def ci_scan(
    target: str = typer.Argument(".", help="Directory or file to scan"),
    packs_dir: str = typer.Option("./anaya/packs", "--packs-dir", "-p", help="Rule packs directory"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to anaya.yml"),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b", help="Baseline file to diff against"),
    fail_on: str = typer.Option("CRITICAL", "--fail-on", help="Minimum severity to fail (exit 1)"),
    sarif_output: Optional[str] = typer.Option(None, "--sarif", help="Write SARIF output to this file"),
) -> None:
    """CI/CD-optimized scan. Outputs compact results + SARIF file + exit code.

    Designed for GitHub Actions, GitLab CI, Jenkins, etc.

    Exit codes:
      0 = passed (no violations at or above fail_on severity)
      1 = failed (violations found at or above fail_on severity)
      2 = error (config/pack loading failure)

    Example GitHub Actions usage:

        - run: pip install anaya

        - run: anaya ci --sarif results.sarif --baseline .anaya-baseline.json

        - uses: github/codeql-action/upload-sarif@v3

          with:
            sarif_file: results.sarif
    """
    start_ms = time.time()

    # Load config
    if config_file and Path(config_file).exists():
        import yaml
        raw = yaml.safe_load(Path(config_file).read_text(encoding="utf-8"))
        config = AnaYaConfig.model_validate(raw)
    else:
        config = AnaYaConfig.default()

    try:
        fail_severity = Severity(fail_on.upper())
    except ValueError:
        err_console.print(f"Invalid severity: {fail_on}")
        raise typer.Exit(code=2)

    try:
        packs = load_pack_directory(packs_dir)
    except Exception as e:
        err_console.print(f"Failed to load packs: {e}")
        raise typer.Exit(code=2)

    if not packs:
        err_console.print(f"No rule packs found in {packs_dir}")
        raise typer.Exit(code=2)

    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    elif target_path.is_dir():
        files = _collect_files(target_path, config)
    else:
        err_console.print(f"Target not found: {target}")
        raise typer.Exit(code=2)

    pattern_scanner = PatternScanner()
    ast_scanner: BaseScanner | None = None
    try:
        from anaya.engine.scanners.ast_scanner import ASTScanner
        ast_scanner = ASTScanner()
    except ImportError:
        pass

    all_violations: list[Violation] = []
    packs_run: list[str] = []

    for pack in packs:
        packs_run.append(pack.manifest.id)
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            try:
                rel_path = str(file_path.relative_to(target_path)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
            if _is_ignored(rel_path, config):
                continue

            violations = pattern_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id)
            all_violations.extend(violations)
            if ast_scanner:
                all_violations.extend(ast_scanner.scan_file(rel_path, content, pack.rules, pack.manifest.id))

    # Baseline filtering
    if baseline and Path(baseline).exists():
        before = len(all_violations)
        all_violations = _filter_baseline(all_violations, baseline)
        console.print(f"[dim]Baseline: {before - len(all_violations)} suppressed, {len(all_violations)} new[/dim]")

    duration_ms = int((time.time() - start_ms) * 1000)
    summary = ScanResult.build_summary(
        violations=all_violations,
        packs_run=packs_run,
        files_scanned=len(files),
        fail_on=fail_severity,
        warn_on=fail_severity,
    )
    result = ScanResult(
        repo="local",
        pr_number=0,
        commit_sha="local",
        violations=all_violations,
        packs_run=packs_run,
        scan_duration_ms=duration_ms,
        summary=summary,
    )

    # Write SARIF if requested
    if sarif_output:
        from anaya.reporters.sarif_builder import build_sarif
        sarif = build_sarif(result)
        Path(sarif_output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        console.print(f"[dim]SARIF written to {sarif_output}[/dim]")

    # Compact CI output
    if all_violations:
        # Group by severity for compact display
        from collections import Counter
        by_sev = Counter(v.severity.value for v in all_violations)
        parts = [f"{cnt} {sev}" for sev, cnt in sorted(by_sev.items())]
        console.print(f"::warning::AnaYa found {len(all_violations)} violations ({', '.join(parts)}) in {len(files)} files ({duration_ms}ms)")

        # GitHub Actions annotations (::error and ::warning)
        for v in all_violations:
            fp = v.file_path.replace("\\", "/")
            level = "error" if v.severity >= fail_severity else "warning"
            msg = v.message.replace("\n", " ").replace("\r", "")[:200]
            typer.echo(f"::{level} file={fp},line={v.line_start}::[{v.rule_id}] {msg}")
    else:
        console.print(f"[green]✓[/green] AnaYa: no violations in {len(files)} files ({duration_ms}ms)")

    if summary.overall_status == "failed":
        raise typer.Exit(code=1)


# ═══════════════════════════════════════════════════════════════
# Baseline helpers
# ═══════════════════════════════════════════════════════════════

def _violation_fingerprint(v: Violation) -> str:
    """Create a stable fingerprint for a violation.

    Uses rule_id + file + snippet hash so the baseline survives
    minor line-number shifts from code edits.
    """
    import hashlib
    snippet_norm = (v.snippet or "").strip().lower()
    raw = f"{v.rule_id}|{v.file_path.replace(chr(92), '/')}|{snippet_norm}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _filter_baseline(violations: list[Violation], baseline_path: str) -> list[Violation]:
    """Remove violations that already exist in the baseline file."""
    try:
        data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_fps = {e["fingerprint"] for e in data.get("violations", [])}
    except Exception:
        return violations  # If baseline is corrupt, show everything

    return [v for v in violations if _violation_fingerprint(v) not in baseline_fps]


# ═══════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app()
