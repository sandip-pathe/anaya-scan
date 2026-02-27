"""
§8(5) — Data Retention & Storage Limitation.

DPDP Act §8(5) requires that personal data shall not be retained beyond the
period necessary to fulfil the purpose for which it was collected. Once the
purpose is served or consent is withdrawn, the data must be erased.

This analyzer checks:
1. Whether retention-related fields exist (expires_at, retention_period, etc.)
2. Whether scheduled deletion / cleanup tasks exist (Celery beat, cron, management commands).
3. Whether a retention policy is documented or enforced in code.

Zero LLM calls — purely structural / grep evidence.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.models import CodebaseMap
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)

_RETENTION_FIELD_NAMES = {
    "expires_at", "expiry_date", "expiry", "retention_period",
    "retention_days", "ttl", "valid_until", "valid_till",
    "purge_after", "auto_delete_at", "delete_after",
    "data_retention", "retention_end",
}

_RETENTION_PATTERNS = [
    re.compile(r"retention.?policy|data.?retention", re.IGNORECASE),
    re.compile(r"auto.?purge|auto.?delete|auto.?cleanup", re.IGNORECASE),
    re.compile(r"scheduled.?deletion|periodic.?deletion", re.IGNORECASE),
    re.compile(r"cleanup.?task|purge.?task|delete.?old|remove.?expired", re.IGNORECASE),
    re.compile(r"RETENTION_DAYS|RETENTION_PERIOD|DATA_TTL", re.IGNORECASE),
]

_CELERY_BEAT_PATTERNS = [
    re.compile(r"celery.?beat|periodic.?task|crontab|beat_schedule", re.IGNORECASE),
    re.compile(r"@periodic_task|@app\.task.*schedule", re.IGNORECASE),
]

_MANAGEMENT_CMD_PATTERNS = [
    re.compile(r"class Command\(BaseCommand\)", re.IGNORECASE),
    re.compile(r"management/commands/", re.IGNORECASE),
]


class DataRetentionAnalyzer(BaseAnalyzer):
    """Evaluate §8(5) — data retention and storage limitation."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§8(5)",
            title="Data Retention & Storage Limitation",
            llm_calls_made=0,
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — retention obligation does not apply."
            )
            return result

        repo_root = Path(cmap.root)
        pii_model_set = set(pii_map.pii_models)

        # ── 1. Check for retention-related fields on PII models ──────────
        retention_fields: list[str] = []
        for model in cmap.models:
            if model.name not in pii_model_set:
                continue
            for field in model.fields:
                if field.name.lower() in _RETENTION_FIELD_NAMES:
                    retention_fields.append(f"{model.name}.{field.name}")

        # Also check all models for generic retention
        all_retention_fields: list[str] = []
        for model in cmap.models:
            for field in model.fields:
                if field.name.lower() in _RETENTION_FIELD_NAMES:
                    all_retention_fields.append(f"{model.name}.{field.name}")

        # ── 2. Grep for retention policies / scheduled tasks ─────────────
        retention_refs: list[str] = []
        celery_beat_refs: list[str] = []
        mgmt_cmd_refs: list[str] = []

        py_files = list(repo_root.rglob("*.py"))
        for pyf in py_files:
            if "__pycache__" in str(pyf) or ".venv" in str(pyf):
                continue
            try:
                content = pyf.read_text(errors="replace")
            except OSError:
                continue
            rel = str(pyf.relative_to(repo_root)).replace("\\", "/")

            for pat in _RETENTION_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    retention_refs.append(
                        f"{rel}:{line_no} — {m.group().strip()}"
                    )
                    break

            for pat in _CELERY_BEAT_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    celery_beat_refs.append(
                        f"{rel}:{line_no} — {m.group().strip()}"
                    )
                    break

            # Check management commands
            if "management/commands/" in rel.replace("\\", "/"):
                for pat in _MANAGEMENT_CMD_PATTERNS:
                    if pat.search(content):
                        mgmt_cmd_refs.append(rel)
                        break

        # ── 3. Check soft-delete patterns on PII models ──────────────────
        soft_delete_pii: list[str] = []
        for model in cmap.models:
            if model.name in pii_model_set and model.has_soft_delete:
                soft_delete_pii.append(model.name)

        # ── Build evidence ───────────────────────────────────────────────
        has_retention_fields = bool(retention_fields)
        has_retention_policy = bool(retention_refs)
        has_scheduled_cleanup = bool(celery_beat_refs)
        has_mgmt_commands = bool(mgmt_cmd_refs)

        if retention_fields:
            result.evidence.append(
                f"Retention-related fields on PII models: "
                f"{', '.join(retention_fields)}"
            )
        else:
            result.evidence.append(
                "No retention-related fields (expires_at, ttl, etc.) found "
                "on any PII model."
            )

        if all_retention_fields and not retention_fields:
            result.evidence.append(
                f"Retention fields exist on non-PII models: "
                f"{', '.join(all_retention_fields[:5])}"
            )

        if retention_refs:
            result.evidence.append(
                f"Retention policy references: "
                f"{'; '.join(retention_refs[:5])}"
            )
        else:
            result.evidence.append(
                "No data retention policy or configuration found."
            )

        if celery_beat_refs:
            result.evidence.append(
                f"Scheduled task infrastructure (Celery beat): "
                f"{'; '.join(celery_beat_refs[:5])}"
            )

        if mgmt_cmd_refs:
            result.evidence.append(
                f"Management commands found: {', '.join(mgmt_cmd_refs[:5])}"
            )

        if soft_delete_pii:
            result.evidence.append(
                f"Soft-delete on PII models: {', '.join(soft_delete_pii)}. "
                f"Soft-deleted data still occupies storage and may violate "
                f"retention limits if not periodically purged."
            )

        if cmap.framework.has_celery:
            result.evidence.append("Celery is installed (task queue available).")

        # ── Determine status ─────────────────────────────────────────────
        if has_retention_fields and (has_scheduled_cleanup or has_retention_policy):
            result.status = "PARTIAL"
            result.evidence.append(
                "Retention infrastructure exists but manual verification "
                "is needed to confirm all PII is covered."
            )
        elif has_retention_policy or has_retention_fields:
            result.status = "PARTIAL"
        else:
            result.status = "NON_COMPLIANT"

        # ── Blockers ─────────────────────────────────────────────────────
        if not has_retention_fields:
            pii_list = ", ".join(sorted(pii_model_set)[:5])
            result.blockers.append(
                f"PII models ({pii_list}) have no retention/expiry fields — "
                f"impossible to enforce automated retention limits."
            )
        if not has_scheduled_cleanup and not has_retention_policy:
            result.blockers.append(
                "No automated cleanup mechanism — personal data will be "
                "retained indefinitely, violating §8(5)."
            )

        # ── Remediation ──────────────────────────────────────────────────
        framework = cmap.framework.primary.value

        if not has_retention_fields:
            result.remediation.append(
                "Add retention fields (e.g., data_retention_until, "
                "consent_expiry_date) to PII models to track when data "
                "should be purged."
            )
        if not has_scheduled_cleanup:
            if framework == "django" and cmap.framework.has_celery:
                result.remediation.append(
                    "Create a Celery periodic task that queries PII models "
                    "for expired retention dates and hard-deletes or "
                    "anonymizes records."
                )
            elif framework == "django":
                result.remediation.append(
                    "Create a Django management command (e.g., "
                    "purge_expired_data) and schedule it via cron or "
                    "Celery beat to enforce retention limits."
                )
            else:
                result.remediation.append(
                    "Implement a scheduled job that queries PII records "
                    "past their retention date and permanently deletes "
                    "or anonymizes them."
                )
        result.remediation.append(
            "Define and document a data retention policy specifying "
            "retention periods for each category of personal data "
            "(DPDP §8(5))."
        )

        return result
