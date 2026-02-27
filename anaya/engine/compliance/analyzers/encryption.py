"""
§8(4) — Encryption of Personal Data.

DPDP Act §8(4) requires "reasonable security safeguards" to protect personal
data from breaches, which is universally interpreted as encryption at rest
for PII/sensitive PII fields.

This analyzer uses ZERO LLM calls. All evidence comes from the CodebaseMap
and PersonalDataMap:
  - If any PII/SENSITIVE_PII field lacks encryption → NON_COMPLIANT
  - If all PII fields are encrypted → COMPLIANT
  - If some but not all → PARTIAL
"""

from __future__ import annotations

import logging

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.models import CodebaseMap
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)


class EncryptionAnalyzer(BaseAnalyzer):
    """Evaluate §8(4) — encryption of personal data at rest."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§8(4)",
            title="Encryption of Personal Data",
            llm_calls_made=0,
        )

        # ── Gather all PII / SENSITIVE_PII fields ────────────────────────
        unencrypted_pii: list[str] = []
        encrypted_pii: list[str] = []
        sensitive_unencrypted: list[str] = []

        # Build a fast lookup: model_name → {field_name → ModelField}
        model_fields_lookup: dict[str, dict[str, object]] = {}
        for model in cmap.models:
            model_fields_lookup[model.name] = {
                f.name: f for f in model.fields
            }

        for mc in pii_map.model_classifications:
            for fc in mc.fields:
                if fc.classification not in ("PII", "SENSITIVE_PII"):
                    continue

                qualified = f"{mc.model_name}.{fc.field_name}"
                model_field = model_fields_lookup.get(
                    mc.model_name, {}
                ).get(fc.field_name)

                is_encrypted = (
                    model_field.is_encrypted if model_field else False  # type: ignore[union-attr]
                )

                if is_encrypted:
                    encrypted_pii.append(qualified)
                else:
                    unencrypted_pii.append(qualified)
                    if fc.classification == "SENSITIVE_PII":
                        sensitive_unencrypted.append(qualified)

        total_pii = len(unencrypted_pii) + len(encrypted_pii)

        # ── No PII at all → COMPLIANT (nothing to protect) ──────────────
        if total_pii == 0:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII or Sensitive PII fields detected in any model."
            )
            return result

        # ── Determine status ─────────────────────────────────────────────
        if not unencrypted_pii:
            result.status = "COMPLIANT"
            result.evidence.append(
                f"All {total_pii} PII fields use encrypted field types."
            )
        elif not encrypted_pii:
            result.status = "NON_COMPLIANT"
            result.evidence.append(
                f"{len(unencrypted_pii)} PII fields stored as plaintext — "
                f"zero encrypted fields found anywhere in the codebase."
            )
        else:
            result.status = "PARTIAL"
            result.evidence.append(
                f"{len(encrypted_pii)}/{total_pii} PII fields encrypted, "
                f"{len(unencrypted_pii)} remain plaintext."
            )

        # ── Evidence: list unencrypted PII fields ────────────────────────
        if unencrypted_pii:
            result.evidence.append(
                f"Unencrypted PII fields: {', '.join(unencrypted_pii)}"
            )

        # ── Highlight sensitive fields specifically ──────────────────────
        if sensitive_unencrypted:
            result.evidence.append(
                f"Sensitive PII (health/financial/biometric) stored plaintext: "
                f"{', '.join(sensitive_unencrypted)}"
            )

        # ── Special callouts: Aadhaar, health, financial ─────────────────
        if pii_map.aadhaar_fields:
            aadhaar_unenc = [
                f for f in pii_map.aadhaar_fields if f in unencrypted_pii
            ]
            if aadhaar_unenc:
                result.evidence.append(
                    f"Aadhaar/national ID fields stored plaintext: "
                    f"{', '.join(aadhaar_unenc)}"
                )

        if pii_map.health_fields:
            health_unenc = [
                f for f in pii_map.health_fields if f in unencrypted_pii
            ]
            if health_unenc:
                result.evidence.append(
                    f"Health data fields stored plaintext: "
                    f"{', '.join(health_unenc)}"
                )

        # ── Blockers ─────────────────────────────────────────────────────
        for field_ref in unencrypted_pii:
            model_name, field_name = field_ref.split(".", 1)
            mf = model_fields_lookup.get(model_name, {}).get(field_name)
            ftype = mf.field_type if mf else "unknown"  # type: ignore[union-attr]
            result.blockers.append(
                f"{field_ref} ({ftype}) — stored as plaintext"
            )

        # ── Remediation (framework-aware) ────────────────────────────────
        framework = cmap.framework.primary.value

        if framework == "django":
            result.remediation.append(
                "Install django-encrypted-model-fields: "
                "pip install django-encrypted-model-fields"
            )
            # Group by field type for specific advice
            char_fields = [
                f for f in unencrypted_pii
                if model_fields_lookup.get(f.split(".")[0], {})
                .get(f.split(".")[1])
                and getattr(
                    model_fields_lookup[f.split(".")[0]][f.split(".")[1]],
                    "field_type", ""
                ) in ("CharField", "TextField")
            ]
            if char_fields:
                result.remediation.append(
                    f"Replace CharField/TextField with EncryptedCharField "
                    f"for: {', '.join(char_fields)}"
                )

            date_fields = [
                f for f in unencrypted_pii
                if model_fields_lookup.get(f.split(".")[0], {})
                .get(f.split(".")[1])
                and getattr(
                    model_fields_lookup[f.split(".")[0]][f.split(".")[1]],
                    "field_type", ""
                ) in ("DateField", "DateTimeField")
            ]
            if date_fields:
                result.remediation.append(
                    f"Replace DateField/DateTimeField with EncryptedDateField "
                    f"for: {', '.join(date_fields)}"
                )

        elif framework == "fastapi":
            result.remediation.append(
                "Add application-level encryption using the cryptography "
                "library (Fernet or AES-GCM) for PII columns before "
                "writing to the database."
            )
            result.remediation.append(
                "Consider SQLAlchemy-Utils EncryptedType for transparent "
                "column-level encryption."
            )

        else:
            result.remediation.append(
                "Implement field-level encryption for all PII fields using "
                "your framework's recommended encryption library."
            )

        result.remediation.append(
            "Ensure encryption keys are stored in a secrets manager "
            "(AWS KMS, Azure Key Vault, HashiCorp Vault), not in code or env vars."
        )

        return result
