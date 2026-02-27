"""
Anaya engine data models.

This is the single most critical file — every module imports from here.
All models use Pydantic v2 syntax.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# 1. Severity
# ═══════════════════════════════════════════════════════════════

class Severity(str, Enum):
    """Rule severity levels, ordered from most to least severe."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def rank(cls, severity: Severity) -> int:
        """Return numeric rank (0 = most severe) for comparison."""
        return list(cls).index(severity)

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity.rank(self) <= Severity.rank(other)

    def __gt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity.rank(self) < Severity.rank(other)

    def __le__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity.rank(self) >= Severity.rank(other)

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity.rank(self) > Severity.rank(other)


# ═══════════════════════════════════════════════════════════════
# 2. BaseRule
# ═══════════════════════════════════════════════════════════════

class BaseRule(BaseModel):
    """Fields shared by every rule type."""
    id: str  # slug, unique within pack e.g. "no-hardcoded-api-key"
    name: str
    severity: Severity
    enabled: bool = True  # False = rule loads but never fires
    message: str  # supports {line}, {file}, {match} placeholders
    fix_hint: str | None = None
    references: list[str] = []
    tags: list[str] = []
    mode: Literal["search", "taint"] = "search"  # reserved for Phase 2 taint engine


# ═══════════════════════════════════════════════════════════════
# 3. PatternRule
# ═══════════════════════════════════════════════════════════════

class PatternRule(BaseRule):
    """Regex-based pattern matching rule."""
    type: Literal["pattern"] = "pattern"
    languages: list[str]  # ["python", "javascript", "*" for all]
    patterns: list[str]  # regex strings, any single match = violation
    exclude_patterns: list[str] = []
    # If any exclude_pattern matches the SAME line as a violation, suppress it.
    # Used to eliminate false positives on compliant patterns.
    # Example: ["os\\.getenv", "process\\.env", "environ\\["] suppresses
    # violations on lines that read from env vars, not hardcode secrets.


# ═══════════════════════════════════════════════════════════════
# 4. ASTRule
# ═══════════════════════════════════════════════════════════════

class ASTRule(BaseRule):
    """Tree-sitter S-expression query rule."""
    type: Literal["ast"] = "ast"
    languages: list[str]
    query: str  # tree-sitter S-expression. Primary capture = violation location.
    name_regex: str | None = None  # If set, @fn_name capture must match this regex
    must_not_contain: str | None = None  # If set, @fn_body text must NOT match (absence = violation)


# ═══════════════════════════════════════════════════════════════
# 5-6. DependencyCheck + DependencyRule
# ═══════════════════════════════════════════════════════════════

class DependencyCheck(BaseModel):
    """Single dependency version check."""
    package: str
    language: str
    max_version: str | None = None
    reason: str


class DependencyRule(BaseRule):
    """Dependency version constraint rule."""
    type: Literal["dependency"] = "dependency"
    checks: list[DependencyCheck]


# ═══════════════════════════════════════════════════════════════
# 6. LLMRule
# ═══════════════════════════════════════════════════════════════

class LLMRule(BaseRule):
    """
    LLM-powered contextual analysis rule.

    Unlike pattern/AST rules, these send file content to an LLM
    with a structured prompt to detect intent-level violations
    (missing logic, absent safeguards, business-logic flaws).
    """
    type: Literal["llm"] = "llm"
    languages: list[str]  # ["python", "javascript", "*"]
    prompt: str
    # Description of what to look for — sent to the LLM as part of the
    # system prompt. Should describe the violation in plain English.
    # Example: "Check if this function handles personal data but does not
    #           obtain user consent before processing."
    examples: list[str] = []
    # Optional few-shot examples of code that violates this rule.
    # Improves LLM accuracy by showing what a violation looks like.


# ═══════════════════════════════════════════════════════════════
# 7. Rule (discriminated union)
# ═══════════════════════════════════════════════════════════════

Rule = Annotated[
    Union[PatternRule, ASTRule, DependencyRule, LLMRule],
    Field(discriminator="type"),
]


# ═══════════════════════════════════════════════════════════════
# 8-9. PackChangelog + PackManifest
# ═══════════════════════════════════════════════════════════════

class PackChangelog(BaseModel):
    """Single changelog entry for a rule pack."""
    version: str
    date: str
    notes: str


class PackManifest(BaseModel):
    """Metadata header for a rule pack."""
    id: str  # "{vendor}/{pack-slug}" e.g. "generic/secrets-detection"
    version: str  # strict semver
    name: str
    description: str
    last_updated: str
    sources: list[str] = []
    changelog: list[PackChangelog] = []


# ═══════════════════════════════════════════════════════════════
# 10. RulePack
# ═══════════════════════════════════════════════════════════════

class RulePack(BaseModel):
    """A complete rule pack: manifest + rules."""
    manifest: PackManifest
    rules: list[Rule]


# ═══════════════════════════════════════════════════════════════
# 11. RulePackSource (abstract + concrete implementations)
# ═══════════════════════════════════════════════════════════════

class RulePackSource(ABC):
    """Abstract base for loading rule packs from various sources."""

    @abstractmethod
    async def load(self) -> list[RulePack]:
        ...


class LocalPackSource(RulePackSource):
    """Load rule packs from a local directory."""

    def __init__(self, path: str) -> None:
        self.path = path

    async def load(self) -> list[RulePack]:
        # Import here to avoid circular dependency — rule_loader imports models
        from anaya.engine.rule_loader import load_pack_directory
        return load_pack_directory(self.path)


class RemotePackSource(RulePackSource):
    """Load rule packs from a remote registry (Phase 2)."""

    def __init__(self, pack_id: str, registry_url: str, token: str) -> None:
        self.pack_id = pack_id
        self.registry_url = registry_url
        self.token = token

    async def load(self) -> list[RulePack]:
        raise NotImplementedError("Remote pack registry not implemented in V1")


# ═══════════════════════════════════════════════════════════════
# 12. Violation
# ═══════════════════════════════════════════════════════════════

class Violation(BaseModel):
    """A single detected policy violation."""
    rule_id: str  # FULLY QUALIFIED: "generic/secrets-detection/no-hardcoded-api-key"
    rule_name: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    col_start: int | None = None
    col_end: int | None = None
    message: str
    snippet: str | None = None
    # The offending source line. Truncate to 200 chars.
    # REDACT the matched portion for secrets rules:
    #   e.g. 'api_key = "[REDACTED]"' — never store actual secret values.
    fix_hint: str | None = None
    references: list[str] = []
    confidence: float = 1.0
    # Always 1.0 for pattern/AST/dep rules. 0.0-1.0 for LLM (Phase 2).
    # Field exists now to avoid breaking model change later.


# ═══════════════════════════════════════════════════════════════
# 13. ScanSummary
# ═══════════════════════════════════════════════════════════════

class ScanSummary(BaseModel):
    """Aggregate statistics for a completed scan."""
    total_files_scanned: int
    total_violations: int
    by_severity: dict[str, int]  # {"CRITICAL": 0, "HIGH": 2, ...}
    by_pack: dict[str, int]  # {"generic/secrets-detection": 3, ...}
    overall_status: Literal["passed", "warned", "failed"]
    # "failed" = any violation >= fail_on threshold
    # "warned" = any violation >= warn_on but none >= fail_on
    # "passed" = nothing at or above warn_on


# ═══════════════════════════════════════════════════════════════
# 14. ScanResult
# ═══════════════════════════════════════════════════════════════

class ScanResult(BaseModel):
    """Complete result of scanning a PR or directory."""
    repo: str
    pr_number: int
    commit_sha: str
    violations: list[Violation]
    packs_run: list[str]
    scan_duration_ms: int
    summary: ScanSummary

    @classmethod
    def build_summary(
        cls,
        violations: list[Violation],
        packs_run: list[str],
        files_scanned: int,
        fail_on: Severity,
        warn_on: Severity,
    ) -> ScanSummary:
        """Build a ScanSummary from violation data and threshold config."""
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_pack: dict[str, int] = {}

        for v in violations:
            by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
            # Extract pack_id: "generic/secrets-detection/rule-slug" → "generic/secrets-detection"
            parts = v.rule_id.rsplit("/", 1)
            pack_id = parts[0] if len(parts) > 1 else v.rule_id
            by_pack[pack_id] = by_pack.get(pack_id, 0) + 1

        # Determine overall status
        has_fail = any(
            v.severity >= fail_on for v in violations
        )
        has_warn = any(
            v.severity >= warn_on for v in violations
        )

        if has_fail:
            overall_status: Literal["passed", "warned", "failed"] = "failed"
        elif has_warn:
            overall_status = "warned"
        else:
            overall_status = "passed"

        return ScanSummary(
            total_files_scanned=files_scanned,
            total_violations=len(violations),
            by_severity=by_severity,
            by_pack=by_pack,
            overall_status=overall_status,
        )


# ═══════════════════════════════════════════════════════════════
# 15-18. Config sub-models
# ═══════════════════════════════════════════════════════════════

class PackRef(BaseModel):
    """Reference to a rule pack in anaya.yml."""
    id: str
    version: str = "latest"


class ScanConfig(BaseModel):
    """Scan configuration section of anaya.yml."""
    mode: Literal["diff", "full"] = "diff"
    languages: list[str] | None = None  # None = scan all supported languages


class ThresholdConfig(BaseModel):
    """Threshold configuration for pass/warn/fail decisions."""
    fail_on: Severity = Severity.CRITICAL
    warn_on: Severity = Severity.HIGH


class IgnoreConfig(BaseModel):
    """Global suppression rules."""
    paths: list[str] = []  # glob patterns
    rules: list[str] = []  # fully qualified rule IDs


# ═══════════════════════════════════════════════════════════════
# 19. AnaYaConfig
# ═══════════════════════════════════════════════════════════════

class AnaYaConfig(BaseModel):
    """
    Root configuration model for anaya.yml.

    Pydantic-validated. Fetched from the repo's default branch only.
    Falls back to sensible defaults if the file doesn't exist.
    """
    version: str = "1"
    packs: list[PackRef] = [
        PackRef(id="generic/secrets-detection"),
        PackRef(id="generic/owasp-top10"),
    ]
    scan: ScanConfig = ScanConfig()
    thresholds: ThresholdConfig = ThresholdConfig()
    ignore: IgnoreConfig = IgnoreConfig()
    enable_llm: bool = False  # explicit opt-in only

    @classmethod
    def default(cls) -> AnaYaConfig:
        """Return a config with all defaults applied."""
        return cls()


# ═══════════════════════════════════════════════════════════════
# Export helper
# ═══════════════════════════════════════════════════════════════

def export_rule_json_schema() -> dict:
    """Export JSON schema for rule YAML authoring (used by validate-pack CLI command)."""
    # Use a wrapper model to get the discriminated union schema
    class _RuleWrapper(BaseModel):
        rule: Rule

    schema = _RuleWrapper.model_json_schema()
    return schema
