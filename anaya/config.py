"""
Anaya application configuration.

Uses pydantic-settings to load from environment variables and .env files.
Singleton pattern: import `settings` from this module.
"""

from __future__ import annotations

import logging
from functools import cached_property
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── GitHub App ───────────────────────────────────────────
    github_app_id: str
    github_private_key_path: str = "./private-key.pem"
    github_private_key_content: str | None = None  # Direct PEM content (for Railway / cloud)
    github_webhook_secret: str

    # ── Database ─────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://anaya:anaya@localhost:5432/anaya"

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Application ──────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    app_port: int = 8000
    app_secret_key: str = "change-me-to-a-random-string"

    # ── Packs ────────────────────────────────────────────────
    packs_dir: str = "./anaya/packs"

    # ── LLM ──────────────────────────────────────────────────
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None  # For Azure OpenAI or custom endpoint
    llm_timeout: int = 30  # Seconds per LLM call
    llm_max_file_tokens: int = 4000  # Skip files larger than this (token count)

    @model_validator(mode="after")
    def _normalize_database_url(self) -> Settings:
        """Auto-rewrite postgresql:// → postgresql+asyncpg:// for Railway/cloud."""
        url = self.database_url
        if url.startswith("postgresql://") and "+asyncpg" not in url:
            self.database_url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return self

    @cached_property
    def github_private_key(self) -> str:
        """
        Get the PEM private key.

        Checks GITHUB_PRIVATE_KEY_CONTENT first (for cloud deployments where
        you can't mount files), then falls back to reading the file at
        GITHUB_PRIVATE_KEY_PATH.
        """
        if self.github_private_key_content:
            return self.github_private_key_content
        with open(self.github_private_key_path) as f:
            return f.read()


def _load_settings() -> Settings:
    """
    Load settings with graceful fallback for CLI / test usage.

    In CLI mode and tests, GitHub App env vars may not be set.
    We provide dummy defaults so the module can be imported without crashing.
    The actual values are only needed when the API / worker runs.
    """
    import os

    defaults: dict[str, str] = {}
    for key in ("GITHUB_APP_ID", "GITHUB_WEBHOOK_SECRET"):
        if key not in os.environ:
            defaults[key.lower()] = "__not_set__"

    if defaults:
        return Settings(**defaults)  # type: ignore[arg-type]
    return Settings()


settings = _load_settings()
