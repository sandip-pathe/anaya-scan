"""
Scan orchestrator — the main entry point for PR scans.

Ties together:
1. GitHub client → fetch PR files + file content
2. Rule loader → load packs
3. Scanners → pattern + AST
4. Reporters → check run + SARIF + PR comment
5. Database → record scan run
6. Compliance → DPDP analysis on the full codebase (optional)

This is called by the Celery worker task.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from anaya.config import settings
from anaya.engine.models import (
    AnaYaConfig,
    ScanResult,
    Severity,
    Violation,
)
from anaya.engine.rule_loader import load_pack_directory
from anaya.engine.scanners.base import BaseScanner
from anaya.engine.scanners.pattern import PatternScanner
from anaya.github.client import GitHubClient

logger = logging.getLogger(__name__)


async def run_pr_scan(
    installation_id: int,
    repo: str,
    pr_number: int,
    head_sha: str,
) -> ScanResult:
    """
    Execute a full compliance scan on a pull request.

    Flow:
    1. Create check run (in_progress)
    2. Fetch anaya.yml config from the repo's default branch
    3. Get list of changed files in the PR
    4. Load rule packs
    5. Fetch content of each changed file
    6. Run pattern + AST scanners
    7. Build scan result
    8. Complete check run with results
    9. Post PR comment (if violations found)
    10. Upload SARIF (if any violations)

    Args:
        installation_id: GitHub App installation ID.
        repo: Full repository name (owner/repo).
        pr_number: Pull request number.
        head_sha: Head commit SHA of the PR.

    Returns:
        ScanResult with all violations and summary.
    """
    start_ms = time.time()

    async with GitHubClient(installation_id) as client:
        # ── 1. Create check run ──────────────────────────────
        from anaya.github.check_runs import create_in_progress_check

        check_run_id = None
        try:
            check_run_id = await create_in_progress_check(
                client, repo, head_sha
            )
        except Exception:
            logger.warning(
                "Could not create check run (missing Checks permission?). "
                "Scan will continue but results won't appear as a Check Run.",
                exc_info=True,
            )

        try:
            result = await _execute_scan(
                client, repo, pr_number, head_sha, start_ms
            )

            # ── 8. Complete check run ────────────────────────
            if check_run_id:
                from anaya.github.check_runs import complete_check_run

                await complete_check_run(client, repo, check_run_id, result)

            # ── 9. Post PR comment if violations found ───────
            if result.violations:
                from anaya.reporters.comment import build_comment

                comment_body = build_comment(result)
                try:
                    await client.create_pr_comment(repo, pr_number, comment_body)
                    logger.info("Posted PR comment with %d violations", len(result.violations))
                except Exception:
                    logger.exception("Failed to post PR comment")

                # ── 9b. Post inline PR review (Semgrep-style) ────
                from anaya.reporters.pr_review import build_review_payload

                review_payload = build_review_payload(
                    result.violations, head_sha
                )
                if review_payload:
                    try:
                        await client.create_pr_review(
                            repo, pr_number, review_payload
                        )
                        logger.info(
                            "Posted inline PR review with %d comments",
                            len(review_payload.get("comments", [])),
                        )
                    except Exception:
                        logger.exception("Failed to post inline PR review")

            # ── 10. Upload SARIF ─────────────────────────────
            if result.violations:
                from anaya.github.sarif import upload_sarif_results

                try:
                    pr_info = await client.get_pr_info(repo, pr_number)
                    ref = f"refs/pull/{pr_number}/head"
                    await upload_sarif_results(client, repo, head_sha, ref, result)
                except Exception:
                    logger.exception("Failed to upload SARIF")

            # ── 11. DPDP Compliance analysis (if enabled) ────
            if settings.openai_api_key:
                try:
                    compliance_report = await _run_compliance_on_repo(
                        client, repo, head_sha
                    )
                    if compliance_report:
                        from anaya.reporters.compliance_comment import build_compliance_comment

                        compliance_body = build_compliance_comment(compliance_report)
                        try:
                            await client.create_pr_comment(
                                repo, pr_number, compliance_body
                            )
                            logger.info(
                                "Posted DPDP compliance comment: %s",
                                compliance_report.summary,
                            )
                        except Exception:
                            logger.exception("Failed to post compliance comment")
                except Exception:
                    logger.exception("DPDP compliance analysis failed")

            return result

        except Exception:
            # If scan fails, complete the check run as errored
            logger.exception("Scan failed for %s PR #%d", repo, pr_number)
            if check_run_id:
                try:
                    error_payload = {
                        "status": "completed",
                        "conclusion": "failure",
                        "output": {
                            "title": "AnaYa: Scan Failed",
                            "summary": "An internal error occurred during the compliance scan. Please check the logs.",
                        },
                    }
                    await client.update_check_run(repo, check_run_id, error_payload)
                except Exception:
                    logger.exception("Failed to update check run on error")
            raise


async def _execute_scan(
    client: GitHubClient,
    repo: str,
    pr_number: int,
    head_sha: str,
    start_ms: float,
) -> ScanResult:
    """
    Core scan logic — separated for clean error handling.

    Steps 2-7 from run_pr_scan.
    """
    # ── 2. Fetch anaya.yml config from default branch ────────
    config = await _fetch_repo_config(client, repo)

    # ── 3. Get changed files ─────────────────────────────────
    pr_files = await client.get_pr_files(repo, pr_number)

    # Filter to changed/added files (not deleted)
    scan_files = [
        f for f in pr_files
        if f.get("status") in ("added", "modified", "renamed", "changed")
    ]
    logger.info(
        "PR #%d: %d files changed, %d eligible for scanning",
        pr_number,
        len(pr_files),
        len(scan_files),
    )

    # ── 4. Load rule packs ───────────────────────────────────
    packs = load_pack_directory(settings.packs_dir)
    if not packs:
        logger.warning("No rule packs found in %s", settings.packs_dir)

    packs_run = [p.manifest.id for p in packs]

    # ── 5. Initialize scanners ───────────────────────────────
    pattern_scanner = PatternScanner()
    ast_scanner: BaseScanner | None = None
    try:
        from anaya.engine.scanners.ast_scanner import ASTScanner

        ast_scanner = ASTScanner()
    except ImportError:
        logger.warning("AST scanner not available (tree-sitter not installed)")

    llm_scanner: BaseScanner | None = None
    if config.enable_llm and settings.openai_api_key:
        try:
            from anaya.engine.scanners.llm_scanner import LLMScanner

            llm_scanner = LLMScanner()
            logger.info("LLM scanner enabled (model=%s)", settings.openai_model)
        except Exception:
            logger.warning("LLM scanner not available", exc_info=True)

    # ── 6. Scan each file ────────────────────────────────────
    all_violations: list[Violation] = []
    file_contents: dict[str, str] = {}  # keep for LLM enhancer
    files_scanned = 0

    for file_info in scan_files:
        filename = file_info["filename"]

        # Check ignore config
        if _should_ignore(filename, config):
            logger.debug("Skipping ignored file: %s", filename)
            continue

        # Check if file has a scannable extension
        language = BaseScanner.detect_language(filename)
        if language is None:
            continue

        # Fetch file content
        content = await client.get_file_content(repo, filename, head_sha)
        if content is None:
            logger.debug("Could not fetch content for %s", filename)
            continue

        files_scanned += 1
        file_contents[filename] = content

        # Run each pack's rules against the file
        for pack in packs:
            violations = pattern_scanner.scan_file(
                filename, content, pack.rules, pack.manifest.id
            )
            all_violations.extend(violations)

            if ast_scanner:
                ast_violations = ast_scanner.scan_file(
                    filename, content, pack.rules, pack.manifest.id
                )
                all_violations.extend(ast_violations)

            if llm_scanner:
                llm_violations = llm_scanner.scan_file(
                    filename, content, pack.rules, pack.manifest.id
                )
                all_violations.extend(llm_violations)

    # ── 6b. LLM violation enhancer (enrich pattern/AST findings) ─
    if config.enable_llm and settings.openai_api_key and all_violations:
        try:
            from anaya.engine.scanners.llm_enhancer import LLMViolationEnhancer

            enhancer = LLMViolationEnhancer()
            # Group violations by file for batch processing
            by_file: dict[str, list[Violation]] = {}
            for v in all_violations:
                by_file.setdefault(v.file, []).append(v)

            for fpath, file_violations in by_file.items():
                fcontent = file_contents.get(fpath, "")
                if fcontent:
                    enhancer.enhance_violations(fpath, fcontent, file_violations)

            logger.info("LLM enhancer processed %d files", len(by_file))
        except Exception:
            logger.warning("LLM violation enhancer failed", exc_info=True)

    # ── 7. Build result ──────────────────────────────────────
    duration_ms = int((time.time() - start_ms) * 1000)

    summary = ScanResult.build_summary(
        violations=all_violations,
        packs_run=packs_run,
        files_scanned=files_scanned,
        fail_on=config.thresholds.fail_on,
        warn_on=config.thresholds.warn_on,
    )

    return ScanResult(
        repo=repo,
        pr_number=pr_number,
        commit_sha=head_sha,
        violations=all_violations,
        packs_run=packs_run,
        scan_duration_ms=duration_ms,
        summary=summary,
    )


async def _fetch_repo_config(
    client: GitHubClient,
    repo: str,
) -> AnaYaConfig:
    """
    Fetch anaya.yml from the repo's default branch.

    Falls back to sensible defaults if the file doesn't exist.
    """
    try:
        default_branch = await client.get_default_branch(repo)
        content = await client.get_file_content(
            repo, "anaya.yml", default_branch
        )
        if content is None:
            # Also try .anaya.yml
            content = await client.get_file_content(
                repo, ".anaya.yml", default_branch
            )

        if content:
            import yaml

            raw = yaml.safe_load(content)
            if isinstance(raw, dict):
                config = AnaYaConfig.model_validate(raw)
                logger.info("Loaded anaya.yml from %s (%s branch)", repo, default_branch)
                return config
    except Exception:
        logger.warning("Failed to load anaya.yml from %s, using defaults", repo, exc_info=True)

    logger.info("No anaya.yml found in %s, using defaults", repo)
    return AnaYaConfig.default()


def _should_ignore(filename: str, config: AnaYaConfig) -> bool:
    """Check if a file should be ignored based on config."""
    import fnmatch

    for pattern in config.ignore.paths:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


async def _run_compliance_on_repo(
    client: GitHubClient,
    repo: str,
    head_sha: str,
) -> "ComplianceReport | None":
    """
    Clone the repo, run full DPDP compliance analysis, and return the report.

    This is a heavier operation than the security scan since it needs the
    full codebase (not just PR diffs). The repo is cloned to a temp directory
    and cleaned up afterwards.

    Returns None if compliance analysis is not available or fails.
    """
    from anaya.engine.compliance.analyzers.runner import ComplianceReport

    clone_dir = None
    try:
        # Get an installation token for git clone
        token = client._token
        if not token:
            logger.warning("No token available for compliance clone")
            return None

        # Clone to temp dir
        clone_dir = tempfile.mkdtemp(prefix="anaya-compliance-")
        clone_url = f"https://x-access-token:{token}@github.com/{repo}.git"

        logger.info("Cloning %s for compliance analysis…", repo)
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", clone_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )

        # Run compliance pipeline
        from anaya.engine.compliance.indexer import CodebaseIndexer
        from anaya.engine.compliance.pii_mapper import PersonalDataMapper
        from anaya.engine.compliance.analyzers.runner import DPDPComplianceRunner

        indexer = CodebaseIndexer(clone_dir)
        cmap = indexer.build()

        mapper = PersonalDataMapper()
        pii_map = mapper.map(cmap)

        runner = DPDPComplianceRunner()
        report = await runner.run(cmap, pii_map)

        # Override repo root for display
        report.repo_root = repo
        report.git_sha = head_sha

        logger.info(
            "Compliance analysis complete for %s: %s",
            repo,
            report.summary,
        )
        return report

    except FileNotFoundError:
        logger.warning("git not found — cannot run compliance analysis in PR mode")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Repo clone timed out for %s", repo)
        return None
    except Exception:
        logger.exception("Compliance analysis failed for %s", repo)
        return None
    finally:
        if clone_dir and os.path.exists(clone_dir):
            try:
                shutil.rmtree(clone_dir)
            except Exception:
                logger.warning("Failed to clean up clone dir: %s", clone_dir)
