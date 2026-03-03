"""
GitHub App authentication.

Handles:
- JWT generation from App ID + private key (RS256, 10-min expiry)
- Installation access token exchange via POST /app/installations/{id}/access_tokens
- Token caching in Redis with 55-minute TTL (falls back to in-memory)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import jwt

from anaya.config import settings

logger = logging.getLogger(__name__)

# JWT valid for 10 minutes (GitHub max), but refresh 60s early
_JWT_EXPIRY_SECONDS = 600
_TOKEN_REFRESH_BUFFER_SECONDS = 60

# Redis key prefix and TTL for installation tokens
_REDIS_TOKEN_PREFIX = "anaya:token:"
_REDIS_TOKEN_TTL_SECONDS = 55 * 60  # 55 minutes (GitHub tokens last 60 min)

# In-memory fallback cache: {installation_id: (token, expires_at)}
_token_cache: dict[int, tuple[str, datetime]] = {}


def generate_jwt(
    app_id: str | None = None,
    private_key: str | None = None,
) -> str:
    """
    Generate a JSON Web Token for GitHub App authentication.

    The JWT is signed with RS256 using the App's private key and has
    a 10-minute expiry (GitHub maximum).

    Args:
        app_id: GitHub App ID (defaults to settings).
        private_key: PEM private key string (defaults to settings).

    Returns:
        Encoded JWT string.
    """
    resolved_app_id = app_id or settings.github_app_id
    if not resolved_app_id or resolved_app_id == "__not_set__":
        raise ValueError(
            "GITHUB_APP_ID is not configured. "
            "Set the GITHUB_APP_ID environment variable."
        )

    resolved_key = private_key or settings.github_private_key
    if not resolved_key or resolved_key == "__not_set__":
        # Try loading from file path
        private_key_path = getattr(settings, "github_private_key_path", None)
        if private_key_path and private_key_path != "__not_set__":
            try:
                from pathlib import Path
                resolved_key = Path(private_key_path).read_text(encoding="utf-8")
            except FileNotFoundError:
                raise ValueError(
                    f"GitHub App private key file not found: {private_key_path}. "
                    "Check GITHUB_PRIVATE_KEY_PATH in your environment."
                ) from None
            except PermissionError:
                raise ValueError(
                    f"Cannot read GitHub App private key file: {private_key_path}. "
                    "Check file permissions."
                ) from None
        else:
            raise ValueError(
                "GITHUB_PRIVATE_KEY is not configured. "
                "Set GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH in your environment."
            )

    now = int(time.time())
    payload = {
        "iat": now - 60,  # 60 seconds in the past for clock drift
        "exp": now + _JWT_EXPIRY_SECONDS,
        "iss": resolved_app_id,
    }

    token: str = jwt.encode(payload, resolved_key, algorithm="RS256")
    logger.debug("Generated JWT for App ID %s", resolved_app_id)
    return token


async def get_installation_token(
    installation_id: int,
    *,
    http_client=None,
) -> str:
    """
    Get an installation access token, using cache when possible.

    If the cached token is still valid (with a 60s buffer), returns it.
    Otherwise, exchanges the JWT for a fresh token via the GitHub API.

    Args:
        installation_id: The GitHub App installation ID.
        http_client: Optional httpx.AsyncClient (creates one if not provided).

    Returns:
        Installation access token string.
    """
    # Check Redis cache first, then in-memory fallback
    cached = await _get_cached_token(installation_id)
    if cached is not None:
        return cached

    # Exchange JWT for installation token
    app_jwt = generate_jwt()

    import httpx

    close_client = False
    if http_client is None:
        http_client = httpx.AsyncClient()
        close_client = True

    try:
        response = await http_client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response.raise_for_status()
        data = response.json()
    finally:
        if close_client:
            await http_client.aclose()

    token = data["token"]
    expires_at_str = data["expires_at"]
    expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))

    # Cache in Redis (with 55-min TTL) and in-memory fallback
    await _cache_token(installation_id, token, expires_at)
    logger.info(
        "Obtained installation token for %d (expires %s)",
        installation_id,
        expires_at.isoformat(),
    )
    return token


async def _get_cached_token(installation_id: int) -> str | None:
    """Try Redis first, then in-memory fallback."""
    # Redis cache
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url)
        try:
            data = await r.get(f"{_REDIS_TOKEN_PREFIX}{installation_id}")
            if data:
                payload = json.loads(data)
                logger.debug("Using Redis-cached token for installation %d", installation_id)
                return payload["token"]
        finally:
            await r.aclose()
    except Exception:
        logger.debug("Redis unavailable for token cache, checking in-memory")

    # In-memory fallback
    if installation_id in _token_cache:
        token, expires_at = _token_cache[installation_id]
        now = datetime.now(timezone.utc)
        if now.timestamp() < (expires_at.timestamp() - _TOKEN_REFRESH_BUFFER_SECONDS):
            logger.debug("Using in-memory cached token for installation %d", installation_id)
            return token

    return None


async def _cache_token(installation_id: int, token: str, expires_at: datetime) -> None:
    """Cache token in Redis (55-min TTL) and in-memory."""
    # In-memory fallback always set
    _token_cache[installation_id] = (token, expires_at)

    # Redis cache
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url)
        try:
            payload = json.dumps({"token": token, "expires_at": expires_at.isoformat()})
            await r.setex(
                f"{_REDIS_TOKEN_PREFIX}{installation_id}",
                _REDIS_TOKEN_TTL_SECONDS,
                payload,
            )
            logger.debug("Cached token in Redis for installation %d (TTL=%ds)", installation_id, _REDIS_TOKEN_TTL_SECONDS)
        finally:
            await r.aclose()
    except Exception:
        logger.debug("Redis unavailable for token caching, using in-memory only")


def clear_token_cache() -> None:
    """Clear the in-memory installation token cache. Used in tests."""
    _token_cache.clear()
