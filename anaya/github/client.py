"""
Authenticated GitHub API client.

Wraps httpx.AsyncClient with:
- Automatic installation token authentication
- Retry logic with exponential backoff for rate limits
- Standard GitHub API headers
- Methods for common operations (get file content, list PR files, etc.)
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

import httpx

from anaya.github.auth import get_installation_token

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds


class GitHubClient:
    """
    Authenticated async GitHub API client.

    Usage:
        async with GitHubClient(installation_id=12345) as gh:
            files = await gh.get_pr_files("owner/repo", 42)
    """

    def __init__(self, installation_id: int) -> None:
        self.installation_id = installation_id
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None

    async def __aenter__(self) -> GitHubClient:
        self._client = httpx.AsyncClient(
            base_url=GITHUB_API_BASE,
            timeout=30.0,
        )
        self._token = await get_installation_token(
            self.installation_id,
            http_client=self._client,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def _headers(self) -> dict[str, str]:
        """Standard headers for all GitHub API requests."""
        return {
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json: dict | list | None = None,
        params: dict | None = None,
    ) -> httpx.Response:
        """
        Make an authenticated GitHub API request with retry logic.

        Handles:
        - 403 rate limit: waits for x-ratelimit-reset
        - 502/503/504: exponential backoff retry
        """
        assert self._client is not None, "Client not initialized — use async with"

        for attempt in range(MAX_RETRIES):
            response = await self._client.request(
                method,
                url,
                headers=self._headers,
                json=json,
                params=params,
            )

            if response.status_code == 403:
                # Check if it's actually a rate limit (remaining=0) vs permissions error
                remaining = response.headers.get("x-ratelimit-remaining")
                reset_at = response.headers.get("x-ratelimit-reset")
                if remaining == "0" and reset_at:
                    import time

                    wait = max(int(reset_at) - int(time.time()), 1)
                    logger.warning("Rate limited. Waiting %ds...", wait)
                    await asyncio.sleep(min(wait, 60))
                    continue
                # Not rate-limited — this is a permissions/auth error, don't retry
                logger.error(
                    "GitHub 403 (not rate limit): %s %s — %s",
                    method, url, response.text[:200],
                )
                response.raise_for_status()

            if response.status_code in (502, 503, 504):
                wait = RETRY_BACKOFF_BASE ** attempt
                logger.warning(
                    "GitHub returned %d, retrying in %ds (attempt %d/%d)",
                    response.status_code,
                    wait,
                    attempt + 1,
                    MAX_RETRIES,
                )
                await asyncio.sleep(wait)
                continue

            response.raise_for_status()
            return response

        # Final attempt — let it raise
        response.raise_for_status()
        return response  # type: ignore[return-value]

    # ── Convenience methods ──────────────────────────────────

    async def get_pr_files(
        self, repo: str, pr_number: int
    ) -> list[dict[str, Any]]:
        """
        Get the list of files changed in a pull request.

        Returns list of dicts with keys: filename, status, additions,
        deletions, changes, patch, etc.
        """
        files: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._request(
                "GET",
                f"/repos/{repo}/pulls/{pr_number}/files",
                params={"per_page": 100, "page": page},
            )
            batch = resp.json()
            if not batch:
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1

        logger.info("PR #%d has %d changed files", pr_number, len(files))
        return files

    async def get_file_content(
        self, repo: str, path: str, ref: str
    ) -> str | None:
        """
        Get the decoded text content of a file at a specific ref.

        Returns None if the file doesn't exist (404).
        """
        try:
            resp = await self._request(
                "GET",
                f"/repos/{repo}/contents/{path}",
                params={"ref": ref},
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content", "")

    async def get_pr_info(
        self, repo: str, pr_number: int
    ) -> dict[str, Any]:
        """Get pull request metadata."""
        resp = await self._request("GET", f"/repos/{repo}/pulls/{pr_number}")
        return resp.json()

    async def get_default_branch(self, repo: str) -> str:
        """Get the repository's default branch name."""
        resp = await self._request("GET", f"/repos/{repo}")
        return resp.json().get("default_branch", "main")

    async def create_check_run(
        self, repo: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a GitHub Check Run."""
        resp = await self._request(
            "POST",
            f"/repos/{repo}/check-runs",
            json=payload,
        )
        return resp.json()

    async def update_check_run(
        self, repo: str, check_run_id: int, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an existing GitHub Check Run."""
        resp = await self._request(
            "PATCH",
            f"/repos/{repo}/check-runs/{check_run_id}",
            json=payload,
        )
        return resp.json()

    async def create_pr_comment(
        self, repo: str, pr_number: int, body: str
    ) -> dict[str, Any]:
        """Create a comment on a pull request."""
        resp = await self._request(
            "POST",
            f"/repos/{repo}/issues/{pr_number}/comments",
            json={"body": body},
        )
        return resp.json()

    async def create_pr_review(
        self, repo: str, pr_number: int, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a pull request review with inline comments.

        Payload should include: commit_id, event, body, comments[].
        Each comment: {path, line, body}.

        See: https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request
        """
        resp = await self._request(
            "POST",
            f"/repos/{repo}/pulls/{pr_number}/reviews",
            json=payload,
        )
        return resp.json()

    async def upload_sarif(
        self, repo: str, commit_sha: str, sarif_data: str, ref: str
    ) -> dict[str, Any]:
        """
        Upload SARIF data to GitHub Code Scanning.

        The sarif_data should be a gzipped, base64-encoded SARIF JSON string.
        """
        resp = await self._request(
            "POST",
            f"/repos/{repo}/code-scanning/sarifs",
            json={
                "commit_sha": commit_sha,
                "ref": ref,
                "sarif": sarif_data,
                "tool_name": "AnaYa",
            },
        )
        return resp.json()
