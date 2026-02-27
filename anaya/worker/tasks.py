"""
Celery tasks for asynchronous processing.

Each webhook event that requires heavy processing is dispatched
as a Celery task to keep the webhook handler fast.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from anaya.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    """
    Run an async coroutine from a sync Celery task.

    Creates a new event loop if none exists (Celery workers are sync).
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Should not happen in Celery, but handle gracefully
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


@celery_app.task(
    name="anaya.worker.tasks.scan_pr",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
)
def scan_pr(
    self,
    installation_id: int,
    repo: str,
    pr_number: int,
    head_sha: str,
) -> dict:
    """
    Execute a compliance scan on a pull request.

    This is the main Celery task that:
    1. Calls the orchestrator to run the scan
    2. Records the result in the database
    3. Returns a summary

    Args:
        installation_id: GitHub App installation ID.
        repo: Full repository name (owner/repo).
        pr_number: Pull request number.
        head_sha: Head commit SHA.

    Returns:
        Dict with scan summary.
    """
    scan_id = str(uuid.uuid4())

    logger.info(
        "Starting scan: id=%s repo=%s pr=#%d sha=%s",
        scan_id,
        repo,
        pr_number,
        head_sha[:8],
    )

    try:
        result = _run_async(
            _execute_and_record(
                scan_id, installation_id, repo, pr_number, head_sha
            )
        )
        return result

    except Exception as exc:
        logger.exception(
            "Scan failed: id=%s repo=%s pr=#%d",
            scan_id,
            repo,
            pr_number,
        )

        # Retry on transient errors
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.error(
                "Max retries exceeded for scan: id=%s repo=%s pr=#%d",
                scan_id,
                repo,
                pr_number,
            )
            return {
                "scan_id": scan_id,
                "status": "error",
                "error": str(exc),
            }


async def _execute_and_record(
    scan_id: str,
    installation_id: int,
    repo: str,
    pr_number: int,
    head_sha: str,
) -> dict:
    """
    Run the scan and record the result in the database.
    """
    from anaya.engine.orchestrator import run_pr_scan

    # Execute scan
    result = await run_pr_scan(
        installation_id=installation_id,
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
    )

    # Record in database
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

        from anaya.config import settings

        # Create a fresh engine bound to THIS event loop (Celery workers
        # use asyncio.run() which creates a new loop each time, so the
        # module-level engine from anaya.db won't work here).
        worker_engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_size=2,
            max_overflow=5,
        )
        WorkerSession = async_sessionmaker(
            worker_engine, class_=AsyncSession, expire_on_commit=False,
        )

        try:
            async with WorkerSession() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO scan_runs (
                            id, repo, pr_number, commit_sha,
                            status, summary_json, created_at
                        ) VALUES (
                            :id, :repo, :pr_number, :sha,
                            :status, CAST(:summary AS jsonb), NOW()
                        )
                        """
                    ),
                    {
                        "id": scan_id,
                        "repo": repo,
                        "pr_number": pr_number,
                        "sha": head_sha,
                        "status": result.summary.overall_status,
                        "summary": result.summary.model_dump_json(),
                    },
                )
                await session.commit()
                logger.info("Scan recorded: id=%s status=%s", scan_id, result.summary.overall_status)
        finally:
            await worker_engine.dispose()
    except Exception:
        logger.exception("Failed to record scan result in database")

    logger.info(
        "Scan complete: id=%s repo=%s pr=#%d violations=%d status=%s duration=%dms",
        scan_id,
        repo,
        pr_number,
        result.summary.total_violations,
        result.summary.overall_status,
        result.scan_duration_ms,
    )

    return {
        "scan_id": scan_id,
        "repo": repo,
        "pr_number": pr_number,
        "status": result.summary.overall_status,
        "total_violations": result.summary.total_violations,
        "files_scanned": result.summary.total_files_scanned,
        "duration_ms": result.scan_duration_ms,
    }
