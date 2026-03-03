"""
LLM guardrails — circuit breaker, rate limiter, and secret redaction.

Central module for all LLM call safety:
- **Circuit breaker**: If N consecutive LLM calls fail, stop calling for
  a cooldown period. Prevents burning retries when OpenAI is fully down.
- **Rate limiter**: Token-bucket limiter to prevent slamming the API within
  a single scan (especially with parallel batch calls).
- **Secret redaction**: Redact sensitive values in snippets before they reach
  PR comments, check run annotations, SARIF, or logs.

All three are thread-safe singletons — safe for ThreadPoolExecutor usage.
"""

from __future__ import annotations

import logging
import re
import threading
import time

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Circuit Breaker
# ─────────────────────────────────────────────────────────────────────────────


class LLMCircuitBreaker:
    """
    Simple circuit breaker for OpenAI calls.

    States:
        CLOSED  — normal operation, calls go through
        OPEN    — failures exceeded threshold, calls are blocked
        HALF    — cooldown expired, allow one probe call

    Thread-safe via a lock.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._consecutive_failures = 0
        self._state = self.CLOSED
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                if time.time() - self._opened_at >= self._cooldown:
                    self._state = self.HALF_OPEN
            return self._state

    def reset(self) -> None:
        """Reset to initial CLOSED state. Used by tests."""
        with self._lock:
            self._state = "CLOSED"
            self._consecutive_failures = 0
            self._opened_at = 0.0

    def allow_call(self) -> bool:
        """Return True if a call should be attempted."""
        current = self.state
        if current == self.CLOSED:
            return True
        if current == self.HALF_OPEN:
            return True  # allow one probe
        return False

    def record_success(self) -> None:
        """Call succeeded — reset to CLOSED."""
        with self._lock:
            self._consecutive_failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        """Call failed — increment counter, maybe trip to OPEN."""
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._state = self.OPEN
                self._opened_at = time.time()
                logger.warning(
                    "LLM circuit breaker OPEN after %d consecutive failures. "
                    "Blocking calls for %.0fs.",
                    self._consecutive_failures,
                    self._cooldown,
                )


# Global singleton
_circuit_breaker = LLMCircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)


def get_circuit_breaker() -> LLMCircuitBreaker:
    """Return the global circuit breaker instance."""
    return _circuit_breaker


# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter (token bucket)
# ─────────────────────────────────────────────────────────────────────────────


class LLMRateLimiter:
    """
    Token-bucket rate limiter for LLM calls.

    Prevents slamming the OpenAI API within a single scan.
    Default: 10 calls per 60 seconds (generous for GPT-4o-mini).
    """

    def __init__(
        self,
        max_calls: int = 10,
        period_seconds: float = 60.0,
    ) -> None:
        self._max_calls = max_calls
        self._period = period_seconds
        self._tokens = float(max_calls)
        self._last_refill = time.time()
        self._lock = threading.Lock()

    def reset(self) -> None:
        """Reset to full token bucket. Used by tests."""
        with self._lock:
            self._tokens = float(self._max_calls)
            self._last_refill = time.time()

    def acquire(self, timeout: float = 120.0) -> bool:
        """
        Block until a token is available, or return False on timeout.

        Returns True if a call is allowed, False if timed out.
        """
        deadline = time.time() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True

            # Wait and retry
            if time.time() >= deadline:
                logger.warning("LLM rate limiter timed out after %.0fs", timeout)
                return False

            time.sleep(0.5)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_refill
        refill = elapsed * (self._max_calls / self._period)
        self._tokens = min(self._max_calls, self._tokens + refill)
        self._last_refill = now


# Global singleton — 10 calls per 60s is generous for gpt-4o-mini
_rate_limiter = LLMRateLimiter(max_calls=10, period_seconds=60.0)


def get_rate_limiter() -> LLMRateLimiter:
    """Return the global rate limiter instance."""
    return _rate_limiter


# ─────────────────────────────────────────────────────────────────────────────
# Combined guard: use before every LLM call
# ─────────────────────────────────────────────────────────────────────────────


class LLMCallBlocked(Exception):
    """Raised when the circuit breaker is open or rate limiter times out."""


def guard_llm_call() -> None:
    """
    Check circuit breaker + rate limiter before making an LLM call.

    Raises LLMCallBlocked if the call should not proceed.
    Call record_llm_success() or record_llm_failure() after the call.
    """
    cb = get_circuit_breaker()
    if not cb.allow_call():
        raise LLMCallBlocked(
            "LLM circuit breaker is OPEN — too many consecutive failures. "
            f"Will retry after {cb._cooldown:.0f}s cooldown."
        )

    rl = get_rate_limiter()
    if not rl.acquire(timeout=120.0):
        raise LLMCallBlocked("LLM rate limiter timeout — too many calls in flight.")


def record_llm_success() -> None:
    """Record a successful LLM call."""
    get_circuit_breaker().record_success()


def record_llm_failure() -> None:
    """Record a failed LLM call."""
    get_circuit_breaker().record_failure()


# ─────────────────────────────────────────────────────────────────────────────
# Secret Redaction
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that look like secrets / credentials in source code
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    # API keys, tokens (long hex/base64 strings assigned to variables)
    re.compile(
        r"""(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token"""
        r"""|private[_-]?key|password|passwd|credential|bearer)"""
        r"""\s*[:=]\s*['"][^'"]{8,}['"]""",
    ),
    # Generic long string assignments that look like secrets
    re.compile(
        r"""(?i)(?:key|token|secret|password)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{20,}['"]""",
    ),
    # AWS keys
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # GitHub tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    # JWT tokens
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    # PEM private keys
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    """
    Redact potential secrets from a text snippet.

    Used to sanitize LLM scanner output before it reaches
    PR comments, check runs, SARIF, or logs.
    """
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def is_secret_rule(rule_id: str, tags: list[str] | None = None) -> bool:
    """Check if a rule ID or tags indicate a secrets-detection rule."""
    _SECRET_KEYWORDS = ("secret", "password", "key", "token", "credential", "pem", "jwt")
    if tags and "secrets" in tags:
        return True
    return any(kw in rule_id.lower() for kw in _SECRET_KEYWORDS)
