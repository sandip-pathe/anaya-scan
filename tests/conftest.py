"""
Shared pytest fixtures for the Anaya test suite.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Ensure tests can import anaya without a full .env
os.environ.setdefault("GITHUB_APP_ID", "__test__")
os.environ.setdefault("GITHUB_PRIVATE_KEY_PATH", "__test__")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "__test__")
os.environ.setdefault("APP_SECRET_KEY", "__test__")

from anaya.engine.llm_guard import get_circuit_breaker, get_rate_limiter

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PACKS_FIXTURE_DIR = FIXTURES_DIR / "packs"
PYTHON_DIRTY_DIR = FIXTURES_DIR / "python" / "dirty"
PYTHON_CLEAN_DIR = FIXTURES_DIR / "python" / "clean"
JS_DIRTY_DIR = FIXTURES_DIR / "javascript" / "dirty"
JS_CLEAN_DIR = FIXTURES_DIR / "javascript" / "clean"


@pytest.fixture(autouse=True)
def _reset_llm_guard() -> None:
    """Reset circuit breaker + rate limiter before every test."""
    get_circuit_breaker().reset()
    get_rate_limiter().reset()


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def packs_fixture_dir() -> Path:
    return PACKS_FIXTURE_DIR


@pytest.fixture
def python_dirty_dir() -> Path:
    return PYTHON_DIRTY_DIR


@pytest.fixture
def python_clean_dir() -> Path:
    return PYTHON_CLEAN_DIR


@pytest.fixture
def js_dirty_dir() -> Path:
    return JS_DIRTY_DIR


@pytest.fixture
def js_clean_dir() -> Path:
    return JS_CLEAN_DIR
