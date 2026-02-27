"""
Rule pack loader.

Parses YAML rule pack files into typed Pydantic models.
Provides human-readable error messages (not raw Pydantic tracebacks).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from anaya.engine.models import (
    ASTRule,
    DependencyRule,
    LLMRule,
    PackManifest,
    PatternRule,
    Rule,
    RulePack,
)

logger = logging.getLogger(__name__)

# Map of type string → rule model class
_RULE_TYPE_MAP: dict[str, type] = {
    "pattern": PatternRule,
    "ast": ASTRule,
    "dependency": DependencyRule,
    "llm": LLMRule,
}


class RuleLoadError(Exception):
    """Human-readable rule loading error."""

    pass


def _parse_rule(raw: dict[str, Any], pack_id: str) -> Rule:
    """
    Parse a single raw dict into a typed Rule.

    Produces human-readable errors, not raw Pydantic tracebacks.
    """
    rule_id = raw.get("id", "<unknown>")
    rule_type = raw.get("type")

    if rule_type is None:
        raise RuleLoadError(
            f"Rule '{rule_id}' in pack '{pack_id}' is missing required field: type"
        )

    if rule_type not in _RULE_TYPE_MAP:
        raise RuleLoadError(
            f"Rule '{rule_id}' in pack '{pack_id}' has unknown type: '{rule_type}'. "
            f"Valid types: {', '.join(sorted(_RULE_TYPE_MAP.keys()))}"
        )

    # Validate rule ID format
    if rule_id != "<unknown>":
        if " " in rule_id:
            logger.warning(
                "Rule '%s' in pack '%s' has spaces in its ID — use hyphens instead",
                rule_id,
                pack_id,
            )
        if rule_id != rule_id.lower():
            logger.warning(
                "Rule '%s' in pack '%s' has uppercase characters — use lowercase slugs",
                rule_id,
                pack_id,
            )

    model_cls = _RULE_TYPE_MAP[rule_type]
    try:
        return model_cls.model_validate(raw)
    except ValidationError as e:
        # Convert Pydantic errors to human-readable messages
        errors = e.errors()
        messages: list[str] = []
        for err in errors:
            field = " → ".join(str(loc) for loc in err["loc"])
            msg = err["msg"]
            err_type = err["type"]
            if err_type == "missing":
                messages.append(f"missing required field: {field}")
            elif err_type == "string_type":
                messages.append(f"field '{field}' must be a string")
            elif err_type == "list_type":
                messages.append(f"field '{field}' must be a list")
            else:
                messages.append(f"field '{field}': {msg}")

        error_text = "; ".join(messages)
        raise RuleLoadError(
            f"Rule '{rule_id}' in pack '{pack_id}' is invalid: {error_text}"
        ) from None


def load_pack(path: str) -> RulePack:
    """
    Load a single YAML rule pack file.

    The file must contain:
    - A 'manifest' section with pack metadata
    - A 'rules' list with one or more rules

    Returns a validated RulePack.
    Raises RuleLoadError with human-readable messages on failure.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise RuleLoadError(f"Pack file not found: {path}")

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuleLoadError(f"Invalid YAML in {path}: {e}") from None

    if not isinstance(raw, dict):
        raise RuleLoadError(f"Pack file {path} must contain a YAML mapping, got {type(raw).__name__}")

    # ── Parse manifest ───────────────────────────────────────
    raw_manifest = raw.get("manifest")
    if raw_manifest is None:
        raise RuleLoadError(f"Pack file {path} is missing required section: manifest")

    try:
        manifest = PackManifest.model_validate(raw_manifest)
    except ValidationError as e:
        errors = e.errors()
        fields = ", ".join(str(err["loc"][0]) for err in errors if err["type"] == "missing")
        if fields:
            raise RuleLoadError(
                f"Pack manifest in {path} is missing required field(s): {fields}"
            ) from None
        raise RuleLoadError(f"Pack manifest in {path} is invalid: {e}") from None

    # ── Parse rules ──────────────────────────────────────────
    raw_rules = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        raise RuleLoadError(f"Pack '{manifest.id}': 'rules' must be a list")

    rules: list[Rule] = []
    for i, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise RuleLoadError(
                f"Pack '{manifest.id}': rule at index {i} must be a mapping, got {type(raw_rule).__name__}"
            )
        rule = _parse_rule(raw_rule, manifest.id)
        rules.append(rule)

    return RulePack(manifest=manifest, rules=rules)


def load_pack_directory(path: str) -> list[RulePack]:
    """
    Load all rule packs from a directory structure.

    Expected layout:
        path/
        ├── vendor1/
        │   ├── _pack.yml       (pack-level manifest, ignored by this loader)
        │   ├── rules-a.yml     (rule pack file)
        │   └── rules-b.yml
        └── vendor2/
            └── ...

    Files named _pack.yml are skipped (they're vendor-level metadata).
    Each .yml file in subdirectories is loaded as a separate RulePack.

    Returns list of validated RulePack objects.
    """
    base = Path(path)
    if not base.exists():
        logger.warning("Packs directory does not exist: %s", path)
        return []

    packs: list[RulePack] = []
    yml_files = sorted(base.rglob("*.yml"))

    for yml_file in yml_files:
        # Skip _pack.yml files (vendor-level metadata, not rule packs)
        if yml_file.name == "_pack.yml":
            continue

        try:
            pack = load_pack(str(yml_file))
            packs.append(pack)
            logger.info(
                "Loaded pack '%s' v%s with %d rules from %s",
                pack.manifest.id,
                pack.manifest.version,
                len(pack.rules),
                yml_file,
            )
        except RuleLoadError as e:
            logger.error("Failed to load pack from %s: %s", yml_file, e)
            raise

    return packs
