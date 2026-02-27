"""
§5 — Data Minimisation (Purpose Limitation).

DPDP Act §5 states that personal data collected must be limited to what is
necessary for the stated purpose. Data fiduciaries must not collect more
personal data than is required.

This analyzer requires 1 LLM call to make a judgment about whether the
collected PII fields are proportionate to the application's stated purpose.

Checks:
1. How many PII / SENSITIVE_PII fields exist relative to the application domain.
2. Whether any model collects PII that seems disproportionate to its purpose.
3. Whether sensitive categories (Aadhaar, financial, health) are justified.
"""

from __future__ import annotations

import json
import logging

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.models import CodebaseMap
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)


class DataMinimisationAnalyzer(BaseAnalyzer):
    """Evaluate §5 — data minimisation and purpose limitation."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§5",
            title="Data Minimisation",
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — minimisation obligation "
                "does not apply."
            )
            result.llm_calls_made = 0
            return result

        # ── Gather facts for LLM judgment ────────────────────────────────
        pii_summary: list[dict[str, object]] = []
        for mc in pii_map.model_classifications:
            pii_fields = [
                {"field": f.field_name, "type": f.field_type, "classification": f.classification}
                for f in mc.fields
                if f.classification in ("PII", "SENSITIVE_PII")
            ]
            if pii_fields:
                pii_summary.append({
                    "model": mc.model_name,
                    "file": mc.file,
                    "pii_field_count": len(pii_fields),
                    "total_fields": len(mc.fields),
                    "pii_fields": pii_fields,
                })

        facts = {
            "framework": cmap.framework.primary.value,
            "total_models": len(cmap.models),
            "pii_models_count": len(pii_map.pii_models),
            "pii_models": pii_summary,
            "sensitive_categories": {
                "aadhaar_fields": pii_map.aadhaar_fields,
                "financial_fields": pii_map.financial_fields,
                "health_fields": pii_map.health_fields,
            },
            "total_pii_fields": pii_map.stats.get("pii_fields", 0),
            "total_sensitive_fields": pii_map.stats.get("sensitive_pii_fields", 0),
        }

        # ── Build structural evidence ────────────────────────────────────
        result.evidence.append(
            f"{len(pii_map.pii_models)} model(s) collect PII out of "
            f"{len(cmap.models)} total models."
        )
        result.evidence.append(
            f"Total PII fields: {pii_map.stats.get('pii_fields', 0)}, "
            f"Sensitive PII: {pii_map.stats.get('sensitive_pii_fields', 0)}"
        )

        if pii_map.aadhaar_fields:
            result.evidence.append(
                f"Aadhaar/national ID collected: {', '.join(pii_map.aadhaar_fields)}"
            )
        if pii_map.financial_fields:
            result.evidence.append(
                f"Financial data collected: {', '.join(pii_map.financial_fields[:5])}"
                + (f" (+{len(pii_map.financial_fields)-5} more)"
                   if len(pii_map.financial_fields) > 5 else "")
            )
        if pii_map.health_fields:
            result.evidence.append(
                f"Health data collected: {', '.join(pii_map.health_fields)}"
            )

        # ── LLM judgment ─────────────────────────────────────────────────
        judgment = await self._llm_judge(facts)
        result.llm_calls_made = 1

        llm_status = judgment.get("status", "UNKNOWN").upper()
        if llm_status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT"):
            result.status = llm_status  # type: ignore[assignment]
        else:
            result.status = "UNKNOWN"

        if judgment.get("reasoning"):
            result.evidence.append(f"LLM assessment: {judgment['reasoning']}")

        for field_concern in judgment.get("excessive_fields", []):
            result.blockers.append(field_concern)

        for fix in judgment.get("remediation", []):
            result.remediation.append(fix)

        # ── Fallback remediation ─────────────────────────────────────────
        if not result.remediation:
            result.remediation.append(
                "Review each PII field and document the business purpose "
                "for its collection. Remove any fields not essential to "
                "the stated purpose."
            )
            if pii_map.aadhaar_fields:
                result.remediation.append(
                    "Aadhaar collection requires specific legal basis — "
                    "verify collection is mandated and store only the "
                    "masked/last-4-digits where full Aadhaar is not required."
                )

        return result

    async def _llm_judge(self, facts: dict) -> dict:
        """Use LLM to assess whether data collection is proportionate."""
        import httpx
        from openai import OpenAI
        from anaya.config import settings

        if not settings.openai_api_key:
            logger.warning("No OpenAI API key — skipping LLM judgment for §5")
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM judgment skipped — no API key configured.",
                "excessive_fields": [],
                "remediation": [],
            }

        system = (
            "You are a DPDP (Digital Personal Data Protection Act, India 2023) "
            "compliance auditor. You are evaluating §5 — purpose limitation "
            "and data minimisation.\n\n"
            "You will receive a summary of all PII fields collected by models "
            "in a codebase.\n\n"
            "DPDP §5 requires:\n"
            "1. Personal data collection must be limited to what is NECESSARY "
            "for the STATED purpose.\n"
            "2. The purpose must be DOCUMENTED (privacy policy, consent notice, "
            "or in-code purpose declaration).\n"
            "3. Sensitive PII (health, financial, biometric, Aadhaar) requires "
            "EXPLICIT justification — not just implicit domain fit.\n\n"
            "DO NOT infer or assume the application's purpose. If there is no "
            "documented purpose statement in the codebase, that itself is a "
            "finding — you cannot determine if fields are minimised without "
            "a declared purpose.\n\n"
            "Flag:\n"
            "- Any sensitive PII (Aadhaar, health, financial) that lacks "
            "explicit documented justification for collection.\n"
            "- Any model collecting a disproportionately large number of PII "
            "fields (e.g., 10+ PII fields on one model).\n"
            "- Absence of a privacy policy or data purpose declaration.\n\n"
            "Respond in JSON:\n"
            '{\n'
            '  "status": "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT",\n'
            '  "reasoning": "one paragraph explaining your verdict",\n'
            '  "excessive_fields": ["Model.field — why it is flagged"],\n'
            '  "remediation": ["specific fix 1", "specific fix 2"]\n'
            '}'
        )

        user = (
            "Here are the PII fields collected by this codebase:\n\n"
            f"{json.dumps(facts, indent=2)}"
        )

        kwargs: dict = {
            "api_key": settings.openai_api_key,
            "timeout": httpx.Timeout(120.0, connect=10.0),
            "max_retries": 3,
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url

        client = OpenAI(**kwargs)

        logger.info("Calling LLM (%s) for §5 minimisation judgment…", settings.openai_model)

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content or "{}"
        logger.debug("§5 LLM response: %s", raw)

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.error("§5 LLM returned invalid JSON: %s", raw[:200])
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM returned unparseable response.",
                "excessive_fields": [],
                "remediation": [],
            }
