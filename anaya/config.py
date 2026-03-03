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
    # Optional — only required when running as a GitHub App (server mode).
    # CLI-only usage (anaya scan / anaya compliance) works without these.
    github_app_id: str | None = None
    github_private_key_path: str = "./private-key.pem"
    github_private_key_content: str | None = None  # Direct PEM content (for Railway / cloud)
    github_webhook_secret: str | None = None

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

    GitHub App env vars are optional — only required when running the server.
    """
    s = Settings()

    # ── Production safety checks ──────────────────────────────
    if s.app_env == "production" and s.app_secret_key == "change-me-to-a-random-string":
        logger.critical(
            "SECURITY: APP_SECRET_KEY is set to the default value in "
            "production. Generate a random secret: "
            "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
        raise SystemExit(
            "Refusing to start in production with the default APP_SECRET_KEY. "
            "Set a strong random value via the APP_SECRET_KEY environment variable."
        )

    return s


settings = _load_settings()
