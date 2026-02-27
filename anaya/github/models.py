"""
Pydantic models for GitHub webhook payloads.

These models validate and type the incoming webhooks that trigger scans.
Only the fields Anaya uses are modeled; extra fields are ignored.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════
# Common nested models
# ═══════════════════════════════════════════════════════════════

class GitHubUser(BaseModel):
    """GitHub user/bot account (minimal fields)."""
    id: int
    login: str
    type: str = "User"  # "User", "Bot", "Organization"


class GitHubRepository(BaseModel):
    """GitHub repository (minimal fields)."""
    id: int
    full_name: str  # "owner/repo"
    name: str
    private: bool = False
    default_branch: str = "main"


class GitHubInstallation(BaseModel):
    """GitHub App installation reference in webhook payloads."""
    id: int
    account: GitHubUser | None = None


class GitHubPullRequestHead(BaseModel):
    """PR head ref info."""
    sha: str
    ref: str


class GitHubPullRequestBase(BaseModel):
    """PR base ref info."""
    sha: str
    ref: str


class GitHubPullRequest(BaseModel):
    """Pull request object from webhook payload."""
    number: int
    title: str = ""
    state: str = "open"  # "open", "closed"
    head: GitHubPullRequestHead
    base: GitHubPullRequestBase
    draft: bool = False
    user: GitHubUser | None = None


# ═══════════════════════════════════════════════════════════════
# Webhook event payloads
# ═══════════════════════════════════════════════════════════════

class PullRequestEvent(BaseModel):
    """
    GitHub pull_request webhook event payload.

    Triggers on: opened, synchronize, reopened.
    """
    action: str  # "opened", "synchronize", "reopened", "closed", etc.
    number: int
    pull_request: GitHubPullRequest
    repository: GitHubRepository
    installation: GitHubInstallation | None = None
    sender: GitHubUser | None = None

    @property
    def should_scan(self) -> bool:
        """Return True if this event should trigger a scan."""
        return (
            self.action in ("opened", "synchronize", "reopened")
            and self.pull_request.state == "open"
            and not self.pull_request.draft
        )

    @property
    def repo_full_name(self) -> str:
        return self.repository.full_name

    @property
    def head_sha(self) -> str:
        return self.pull_request.head.sha

    @property
    def pr_number(self) -> int:
        return self.pull_request.number

    @property
    def installation_id(self) -> int | None:
        return self.installation.id if self.installation else None


class InstallationEvent(BaseModel):
    """
    GitHub installation webhook event payload.

    Triggers on: created, deleted, suspend, unsuspend.
    """
    action: str  # "created", "deleted", "suspend", "unsuspend"
    installation: GitHubInstallation
    repositories: list[GitHubRepository] = Field(default_factory=list)
    sender: GitHubUser | None = None

    @property
    def installation_id(self) -> int:
        return self.installation.id

    @property
    def account_login(self) -> str | None:
        return self.installation.account.login if self.installation.account else None

    @property
    def account_type(self) -> str | None:
        return self.installation.account.type if self.installation.account else None


class PingEvent(BaseModel):
    """
    GitHub ping webhook event — sent when the webhook is first configured.
    """
    zen: str = ""
    hook_id: int = 0
    hook: dict = Field(default_factory=dict)
    repository: GitHubRepository | None = None
    sender: GitHubUser | None = None
    installation: GitHubInstallation | None = None
