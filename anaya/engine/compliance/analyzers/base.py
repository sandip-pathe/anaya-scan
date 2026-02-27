"""
Base types for DPDP section analyzers.
"""

from __future__ import annotations

import abc
from typing import Literal

from pydantic import BaseModel, Field

from anaya.engine.compliance.models import CodebaseMap
from anaya.engine.compliance.pii_mapper import PersonalDataMap


class SectionResult(BaseModel):
    """Result of analyzing one DPDP section against a codebase."""

    section: str                   # e.g. "§8(4)"
    title: str                     # e.g. "Encryption of Personal Data"
    status: Literal[
        "COMPLIANT", "PARTIAL", "NON_COMPLIANT", "UNKNOWN"
    ] = "UNKNOWN"
    evidence: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    llm_calls_made: int = 0


class BaseAnalyzer(abc.ABC):
    """Interface every section analyzer must implement."""

    @abc.abstractmethod
    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        """Evaluate one DPDP section. Return a SectionResult."""
        ...
