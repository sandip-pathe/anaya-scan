"""
SARIF 2.1.0 builder — converts ScanResult into Static Analysis Results
Interchange Format for GitHub Code Scanning.

See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub: https://docs.github.com/en/code-security/code-scanning/sarif-support
"""

from __future__ import annotations

from typing import Any

from anaya.engine.models import ScanResult, Violation


_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# Map severity → SARIF level
_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _build_rule_descriptor(rule_id: str, violation: Violation) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a violation."""
    descriptor: dict[str, Any] = {
        "id": rule_id,
        "name": violation.rule_name,
        "shortDescription": {"text": violation.rule_name},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(violation.severity.value, "warning"),
        },
        "properties": {
            "tags": [],
            "severity": violation.severity.value,
        },
    }
    if violation.fix_hint:
        descriptor["help"] = {"text": violation.fix_hint}
    if violation.references:
        descriptor["helpUri"] = violation.references[0]
    return descriptor


def _build_result(violation: Violation, rule_index: int) -> dict[str, Any]:
    """Build a SARIF result from a violation."""
    result: dict[str, Any] = {
        "ruleId": violation.rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(violation.severity.value, "warning"),
        "message": {"text": violation.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": violation.file_path.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": violation.line_start,
                        "endLine": violation.line_end,
                    },
                }
            }
        ],
    }

    if violation.col_start is not None:
        region = result["locations"][0]["physicalLocation"]["region"]
        region["startColumn"] = violation.col_start
    if violation.col_end is not None:
        region = result["locations"][0]["physicalLocation"]["region"]
        region["endColumn"] = violation.col_end

    if violation.snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": violation.snippet,
        }

    if violation.fix_hint:
        result["fixes"] = [
            {
                "description": {"text": violation.fix_hint},
            }
        ]

    return result


def build_sarif(result: ScanResult) -> dict[str, Any]:
    """
    Build a complete SARIF 2.1.0 document from a ScanResult.

    Args:
        result: The completed scan result.

    Returns:
        A dict representing the SARIF JSON structure.
    """
    # Deduplicate rules by rule_id
    seen_rules: dict[str, int] = {}
    rule_descriptors: list[dict[str, Any]] = []

    for v in result.violations:
        if v.rule_id not in seen_rules:
            seen_rules[v.rule_id] = len(rule_descriptors)
            rule_descriptors.append(_build_rule_descriptor(v.rule_id, v))

    # Build results
    results = []
    for v in result.violations:
        rule_index = seen_rules[v.rule_id]
        results.append(_build_result(v, rule_index))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "AnaYa",
                "version": "1.0.0",
                "informationUri": "https://github.com/anaya-compliance/anaya",
                "rules": rule_descriptors,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [],
            }
        ],
    }

    # Add runAutomationDetails.id using the commit SHA for deduplication
    if result.commit_sha:
        run["automationDetails"] = {
            "id": f"anaya/{result.commit_sha}",
        }

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }

    return sarif
