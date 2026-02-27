"""
GitHub Check Runs integration.

High-level helpers that combine the client + reporters to:
1. Create a check run (in_progress)
2. Complete it with scan results (including annotation batching)
"""

from __future__ import annotations

import logging
from typing import Any

from anaya.engine.models import ScanResult
from anaya.github.client import GitHubClient
from anaya.reporters.check_run import (
    MAX_ANNOTATIONS_PER_UPDATE,
    build_annotation_batches,
    build_complete_payload,
    build_create_payload,
)

logger = logging.getLogger(__name__)


async def create_in_progress_check(
    client: GitHubClient,
    repo: str,
    head_sha: str,
    name: str = "AnaYa Compliance Scan",
) -> int:
    """
    Create a check run in 'in_progress' state.

    Returns the check_run_id for subsequent updates.
    """
    payload = build_create_payload(name=name, head_sha=head_sha)
    result = await client.create_check_run(repo, payload)
    check_run_id = result["id"]
    logger.info("Created check run %d for %s @ %s", check_run_id, repo, head_sha[:8])
    return check_run_id


async def complete_check_run(
    client: GitHubClient,
    repo: str,
    check_run_id: int,
    result: ScanResult,
) -> None:
    """
    Complete a check run with scan results.

    Handles annotation batching for >50 violations per GitHub API limits.
    The first PATCH includes the conclusion + first 50 annotations.
    Subsequent PATCHes add remaining annotations in batches of 50.
    """
    # First update: conclusion + summary + first batch of annotations
    payload = build_complete_payload(result)
    await client.update_check_run(repo, check_run_id, payload)
    logger.info(
        "Completed check run %d: %s (%d violations)",
        check_run_id,
        result.summary.overall_status,
        result.summary.total_violations,
    )

    # Additional annotation batches if >50 violations
    if len(result.violations) > MAX_ANNOTATIONS_PER_UPDATE:
        batches = build_annotation_batches(result.violations)
        # Skip the first batch (already sent with the completion payload)
        for i, batch in enumerate(batches[1:], start=2):
            update_payload: dict[str, Any] = {
                "output": {
                    "title": f"AnaYa: {result.summary.total_violations} violation(s) found",
                    "summary": f"Annotation batch {i}/{len(batches)}",
                    "annotations": batch,
                },
            }
            await client.update_check_run(repo, check_run_id, update_payload)
            logger.debug("Sent annotation batch %d/%d", i, len(batches))
