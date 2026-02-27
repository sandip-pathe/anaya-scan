"""
SARIF upload to GitHub Code Scanning.

Handles gzip + base64 encoding of SARIF JSON before upload.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging

from anaya.engine.models import ScanResult
from anaya.github.client import GitHubClient
from anaya.reporters.sarif_builder import build_sarif

logger = logging.getLogger(__name__)


async def upload_sarif_results(
    client: GitHubClient,
    repo: str,
    commit_sha: str,
    ref: str,
    result: ScanResult,
) -> dict | None:
    """
    Build and upload SARIF results to GitHub Code Scanning.

    Steps:
    1. Build SARIF JSON from ScanResult
    2. Gzip compress the JSON
    3. Base64 encode the compressed data
    4. POST to /repos/{repo}/code-scanning/sarifs

    Returns the API response dict, or None if upload fails.
    """
    if not result.violations:
        logger.info("No violations to upload as SARIF for %s", repo)
        return None

    sarif = build_sarif(result)
    sarif_json = json.dumps(sarif).encode("utf-8")

    # Gzip compress
    compressed = gzip.compress(sarif_json)

    # Base64 encode
    encoded = base64.b64encode(compressed).decode("ascii")

    logger.info(
        "Uploading SARIF for %s @ %s (%d bytes compressed)",
        repo,
        commit_sha[:8],
        len(compressed),
    )

    try:
        response = await client.upload_sarif(repo, commit_sha, encoded, ref)
        logger.info("SARIF uploaded successfully for %s", repo)
        return response
    except Exception:
        logger.exception("Failed to upload SARIF for %s", repo)
        return None
