"""
Minimal async SQLAlchemy setup for Anaya V1.

Tables:
  - installations: tracks GitHub App installations
  - scan_runs: records each PR scan with results

Provides async engine, session factory, FastAPI dependency, and init_db().
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from anaya.config import settings


# ── Engine & Session ─────────────────────────────────────────

async_engine = create_async_engine(
    settings.database_url,
    echo=(settings.app_env == "development"),
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Base ─────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Tables ───────────────────────────────────────────────────

class Installation(Base):
    __tablename__ = "installations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    installation_id = Column(BigInteger, unique=True, nullable=False, index=True)
    account_login = Column(Text, nullable=True)
    account_type = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    repo = Column(Text, nullable=True)
    pr_number = Column(Integer, nullable=True)
    commit_sha = Column(String(40), nullable=True)
    status = Column(Text, nullable=True)  # queued, in_progress, completed, failed
    summary_json = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)


# ── FastAPI dependency ───────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session; rolls back on exception, always closes."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Init ─────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables. Called on application startup."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
