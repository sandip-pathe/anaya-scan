"""
§7(3) — Right to Erasure.

DPDP Act §7(3) gives data principals the right to have their personal data
erased. The data fiduciary must be able to erase all personal data upon a
verified request, unless retention is required by law.

This analyzer checks:
1. Whether DELETE endpoints exist for PII-holding models.
2. Whether PROTECT foreign keys block deletion of PII models.
3. Whether soft-delete patterns exist (may or may not satisfy erasure).
4. Sends a concise fact summary to LLM for final judgment.
"""

from __future__ import annotations

import json
import logging

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.models import (
    CascadeAction,
    CodebaseMap,
    HttpMethod,
)
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)


class ErasureAnalyzer(BaseAnalyzer):
    """Evaluate §7(3) — right to erasure of personal data."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§7(3)",
            title="Right to Erasure",
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — erasure obligation does not apply."
            )
            result.llm_calls_made = 0
            return result

        pii_model_set = set(pii_map.pii_models)

        # ── 1. Check DELETE endpoints for PII models ─────────────────────
        delete_endpoints_for_pii: list[dict[str, str]] = []
        pii_models_with_delete: set[str] = set()

        for ep in cmap.endpoints:
            if HttpMethod.DELETE not in ep.http_methods:
                continue
            # Check if endpoint deletes or is associated with a PII model
            related_models = set(ep.models_deleted + ep.models_written + ep.models_read)
            matched = related_models & pii_model_set
            if matched:
                delete_endpoints_for_pii.append({
                    "path": ep.path,
                    "handler": ep.handler,
                    "models": sorted(matched),
                    "requires_auth": ep.requires_auth,
                })
                pii_models_with_delete.update(matched)

            # Also match by viewset class name containing PII model name
            if ep.viewset_class:
                for pm in pii_model_set:
                    if pm.lower() in ep.viewset_class.lower():
                        delete_endpoints_for_pii.append({
                            "path": ep.path,
                            "handler": ep.handler,
                            "models": [pm],
                            "requires_auth": ep.requires_auth,
                        })
                        pii_models_with_delete.add(pm)

        pii_models_without_delete = pii_model_set - pii_models_with_delete

        # ── 2. Check PROTECT blockers on PII models ──────────────────────
        protect_blockers: list[dict[str, str]] = []
        for dp in cmap.delete_paths:
            if not dp.is_blocker:
                continue
            # A blocker is relevant if it blocks deletion of a PII model
            if dp.target_model in pii_model_set:
                protect_blockers.append({
                    "source_model": dp.source_model,
                    "field": dp.field_name,
                    "target_model": dp.target_model,
                    "file": dp.file,
                })

        # ── 3. Check soft-delete patterns ────────────────────────────────
        soft_delete_models: list[str] = []
        hard_delete_models: list[str] = []
        for model in cmap.models:
            if model.name not in pii_model_set:
                continue
            if model.has_soft_delete:
                soft_delete_models.append(model.name)
            if model.has_delete_method:
                hard_delete_models.append(model.name)

        # ── 4. Check CASCADE coverage from PII models ────────────────────
        cascade_from_pii: list[dict[str, str]] = []
        for dp in cmap.delete_paths:
            if dp.target_model in pii_model_set and dp.on_delete == CascadeAction.CASCADE:
                cascade_from_pii.append({
                    "source": dp.source_model,
                    "field": dp.field_name,
                    "target": dp.target_model,
                })

        # ── Build evidence from structural analysis ──────────────────────
        if delete_endpoints_for_pii:
            result.evidence.append(
                f"{len(delete_endpoints_for_pii)} DELETE endpoint(s) "
                f"exist for PII models."
            )
        else:
            result.evidence.append(
                "No DELETE endpoints found for any PII model."
            )

        if pii_models_without_delete:
            result.evidence.append(
                f"PII models with no DELETE endpoint: "
                f"{', '.join(sorted(pii_models_without_delete))}"
            )

        if cascade_from_pii:
            result.evidence.append(
                f"{len(cascade_from_pii)} CASCADE FK path(s) ensure "
                f"related data is deleted when PII models are removed."
            )

        if soft_delete_models:
            result.evidence.append(
                f"Soft-delete pattern detected in: "
                f"{', '.join(soft_delete_models)}. "
                f"Soft-delete alone may not satisfy DPDP erasure requirements — "
                f"data must be permanently removed, not just flagged."
            )

        # ── Blockers ─────────────────────────────────────────────────────
        if protect_blockers:
            for pb in protect_blockers:
                result.blockers.append(
                    f"{pb['source_model']}.{pb['field']} → {pb['target_model']} "
                    f"(on_delete=PROTECT) — deletion will be blocked by ORM "
                    f"if related records exist"
                )

        # ── 5. LLM judgment call ─────────────────────────────────────────
        facts = {
            "pii_models": sorted(pii_model_set),
            "delete_endpoints": len(delete_endpoints_for_pii),
            "pii_models_with_delete_endpoint": sorted(pii_models_with_delete),
            "pii_models_without_delete_endpoint": sorted(pii_models_without_delete),
            "protect_blockers": protect_blockers,
            "cascade_paths_from_pii": len(cascade_from_pii),
            "soft_delete_models": soft_delete_models,
            "has_custom_delete_method": hard_delete_models,
            "global_auth_required": cmap.framework.global_auth_required,
            "framework": cmap.framework.primary.value,
        }

        judgment = await self._llm_judge(facts)
        result.llm_calls_made = 1

        # ── Apply LLM judgment ───────────────────────────────────────────
        llm_status = judgment.get("status", "UNKNOWN").upper()
        if llm_status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT"):
            result.status = llm_status  # type: ignore[assignment]
        else:
            result.status = "UNKNOWN"

        if judgment.get("reasoning"):
            result.evidence.append(f"LLM assessment: {judgment['reasoning']}")

        for fix in judgment.get("remediation", []):
            result.remediation.append(fix)

        # ── If LLM didn't provide remediation, add structural ones ───────
        if not result.remediation:
            if pii_models_without_delete:
                result.remediation.append(
                    f"Add DELETE endpoints for: "
                    f"{', '.join(sorted(pii_models_without_delete))}"
                )
            if protect_blockers:
                result.remediation.append(
                    "Implement a purge function that manually deletes "
                    "or anonymizes PROTECT-linked records before deleting "
                    "the parent PII model."
                )
            if soft_delete_models:
                result.remediation.append(
                    "Ensure soft-deleted PII is permanently purged within "
                    "a defined retention period, or switch to hard deletion "
                    "for DPDP compliance."
                )

        return result

    async def _llm_judge(self, facts: dict) -> dict:
        """Send structured facts to LLM for erasure compliance judgment."""
        import httpx
        from openai import OpenAI
        from anaya.config import settings
        from anaya.engine.llm_guard import (
            LLMCallBlocked,
            guard_llm_call,
            record_llm_failure,
            record_llm_success,
        )

        if not settings.openai_api_key:
            logger.warning("No OpenAI API key — skipping LLM judgment for §7(3)")
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM judgment skipped — no API key configured.",
                "remediation": [],
            }

        try:
            guard_llm_call()
        except LLMCallBlocked as exc:
            logger.warning("LLM blocked for §7(3) erasure judgment: %s", exc)
            return {
                "status": "UNKNOWN",
                "reasoning": f"LLM call blocked: {exc}",
                "remediation": [],
            }

        system = (
            "You are a DPDP (Digital Personal Data Protection Act, India 2023) "
            "compliance auditor. You are evaluating §7(3) — the right to erasure.\n\n"
            "You will receive structured facts about a codebase's deletion "
            "capabilities for models that hold personal data (PII).\n\n"
            "Evaluate whether the codebase can fulfil a data principal's "
            "erasure request. Consider:\n"
            "- Can all PII be deleted via API endpoints?\n"
            "- Do PROTECT foreign keys block deletion?\n"
            "- Is soft-delete sufficient for DPDP, or must data be hard-deleted?\n"
            "- Are there cascading deletes that properly clean up related data?\n\n"
            "Respond in JSON:\n"
            '{\n'
            '  "status": "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT",\n'
            '  "reasoning": "one paragraph explaining your verdict",\n'
            '  "remediation": ["specific fix 1", "specific fix 2"]\n'
            '}'
        )

        user = (
            "Here are the erasure-related facts for this codebase:\n\n"
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

        logger.info("Calling LLM (%s) for §7(3) erasure judgment…", settings.openai_model)

        try:
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
            record_llm_success()
        except LLMCallBlocked:
            raise
        except Exception:
            record_llm_failure()
            raise

        raw = response.choices[0].message.content or "{}"
        logger.debug("§7(3) LLM response: %s", raw)

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.error("§7(3) LLM returned invalid JSON: %s", raw[:200])
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM returned unparseable response.",
                "remediation": [],
            }
