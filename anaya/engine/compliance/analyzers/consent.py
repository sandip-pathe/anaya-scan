"""
§4 — Consent Before Collection of Personal Data.

DPDP Act §4 requires that personal data may only be processed with the
consent of the data principal, obtained before or at the time of collection.
Consent must be free, specific, informed, unconditional, and unambiguous.

This analyzer checks:
1. Whether a Consent/DataConsent model exists (vs clinical/procedure consent).
2. Whether PII-creating endpoints have consent verification in their handler.
3. Uses grep-based evidence + 1 LLM call to distinguish clinical consent
   from DPDP data-processing consent.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from anaya.engine.compliance.analyzers.base import BaseAnalyzer, SectionResult
from anaya.engine.compliance.models import CodebaseMap, HttpMethod
from anaya.engine.compliance.pii_mapper import PersonalDataMap

logger = logging.getLogger(__name__)

# Patterns that indicate a consent mechanism
_CONSENT_PATTERNS = [
    re.compile(r"consent", re.IGNORECASE),
    re.compile(r"data_processing_consent", re.IGNORECASE),
    re.compile(r"consent_given", re.IGNORECASE),
    re.compile(r"has_consented", re.IGNORECASE),
    re.compile(r"consent_required", re.IGNORECASE),
    re.compile(r"ConsentMiddleware", re.IGNORECASE),
    re.compile(r"require_consent", re.IGNORECASE),
]

# Patterns for clinical/medical consent (distinct from data-processing consent)
_CLINICAL_CONSENT_PATTERNS = [
    re.compile(r"informed_consent|procedure_consent|surgical_consent", re.IGNORECASE),
    re.compile(r"consent.*treatment|treatment.*consent", re.IGNORECASE),
    re.compile(r"class Consent\b", re.IGNORECASE),  # Generic "Consent" model
]


class ConsentAnalyzer(BaseAnalyzer):
    """Evaluate §4 — consent before collection of personal data."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§4",
            title="Consent Before Collection",
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — consent obligation does not apply."
            )
            result.llm_calls_made = 0
            return result

        pii_model_set = set(pii_map.pii_models)
        repo_root = Path(cmap.root)

        # ── 1. Find Consent-Like Models ──────────────────────────────────
        consent_models: list[dict[str, str]] = []
        for model in cmap.models:
            name_lower = model.name.lower()
            if "consent" in name_lower:
                field_names = [f.name for f in model.fields]
                consent_models.append({
                    "name": model.name,
                    "file": model.file,
                    "fields": ", ".join(field_names[:15]),
                    "base_classes": ", ".join(model.base_classes),
                })

        # ── 2. Find PII-Creating Endpoints ───────────────────────────────
        pii_create_endpoints: list[dict[str, str]] = []
        for ep in cmap.endpoints:
            # POST endpoints that write to PII models
            if HttpMethod.POST not in ep.http_methods and HttpMethod.ANY not in ep.http_methods:
                continue
            related = set(ep.models_written + ep.models_read)
            matched = related & pii_model_set
            if not matched:
                # Also check viewset class name
                if ep.viewset_class:
                    for pm in pii_model_set:
                        if pm.lower() in ep.viewset_class.lower():
                            matched.add(pm)
                if not matched:
                    continue

            pii_create_endpoints.append({
                "path": ep.path,
                "handler": ep.handler,
                "viewset": ep.viewset_class or "",
                "file": ep.file,
                "models": ", ".join(sorted(matched)),
                "requires_auth": str(ep.requires_auth),
            })

        # ── 3. Grep for consent checks in endpoint handler files ─────────
        endpoint_files = {ep["file"] for ep in pii_create_endpoints}
        consent_references_in_views: list[dict[str, str]] = []
        consent_middleware_found = False

        for rel_path in endpoint_files:
            full_path = repo_root / rel_path
            if not full_path.is_file():
                continue
            try:
                content = full_path.read_text(errors="replace")
            except OSError:
                continue

            for pattern in _CONSENT_PATTERNS:
                for match in pattern.finditer(content):
                    # Get line number
                    line_no = content[:match.start()].count("\n") + 1
                    line_text = content.split("\n")[line_no - 1].strip()
                    consent_references_in_views.append({
                        "file": rel_path,
                        "line": str(line_no),
                        "match": line_text[:120],
                    })
                    if "middleware" in match.group().lower():
                        consent_middleware_found = True

        # ── 4. Check middleware/settings for consent enforcement ──────────
        for sf in cmap.framework.settings_files:
            full_path = repo_root / sf
            if not full_path.is_file():
                continue
            try:
                content = full_path.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"ConsentMiddleware|consent_required", content, re.IGNORECASE):
                consent_middleware_found = True
                consent_references_in_views.append({
                    "file": sf,
                    "line": "settings",
                    "match": "ConsentMiddleware in MIDDLEWARE or consent_required decorator found",
                })

        # ── 5. Grab Consent model source + first PII endpoint source ─────
        consent_model_source = ""
        if consent_models:
            first_consent = consent_models[0]
            full_path = repo_root / first_consent["file"]
            if full_path.is_file():
                try:
                    lines = full_path.read_text(errors="replace").split("\n")
                    # Find the class definition and grab ~40 lines
                    for i, line in enumerate(lines):
                        if f"class {first_consent['name']}" in line:
                            consent_model_source = "\n".join(
                                lines[max(0, i):i + 40]
                            )
                            break
                except OSError:
                    pass

        pii_create_handler_source = ""
        if pii_create_endpoints:
            first_ep = pii_create_endpoints[0]
            full_path = repo_root / first_ep["file"]
            if full_path.is_file():
                try:
                    content = full_path.read_text(errors="replace")
                    # Find the handler / viewset class
                    search_term = first_ep["viewset"] or first_ep["handler"]
                    if search_term:
                        idx = content.find(f"class {search_term}")
                        if idx == -1:
                            idx = content.find(f"def {search_term}")
                        if idx >= 0:
                            pre_lines = content[:idx].count("\n")
                            all_lines = content.split("\n")
                            pii_create_handler_source = "\n".join(
                                all_lines[max(0, pre_lines):pre_lines + 60]
                            )
                except OSError:
                    pass

        # ── 6. Build structural evidence ─────────────────────────────────
        if consent_models:
            result.evidence.append(
                f"Consent-related model(s) found: "
                f"{', '.join(cm['name'] for cm in consent_models)}"
            )
        else:
            result.evidence.append("No Consent model found in the codebase.")

        if pii_create_endpoints:
            result.evidence.append(
                f"{len(pii_create_endpoints)} endpoint(s) create PII data "
                f"(POST to {', '.join(sorted({ep['models'] for ep in pii_create_endpoints}))})"
            )
        else:
            result.evidence.append("No POST endpoints found for PII models.")

        if consent_references_in_views:
            result.evidence.append(
                f"{len(consent_references_in_views)} consent-related reference(s) "
                f"found in view/handler files."
            )
        else:
            result.evidence.append(
                "No consent checks found in any PII-creating endpoint handler."
            )

        if consent_middleware_found:
            result.evidence.append("Consent middleware/decorator detected in settings.")

        # ── 7. LLM judgment ──────────────────────────────────────────────
        facts = {
            "pii_models": sorted(pii_model_set),
            "consent_models": consent_models,
            "pii_create_endpoints_count": len(pii_create_endpoints),
            "pii_create_endpoints": pii_create_endpoints[:5],  # limit for token budget
            "consent_references_in_views": consent_references_in_views[:10],
            "consent_middleware_found": consent_middleware_found,
            "framework": cmap.framework.primary.value,
        }

        # Include source code snippets if available
        source_context = {}
        if consent_model_source:
            source_context["consent_model_source"] = consent_model_source[:2000]
        if pii_create_handler_source:
            source_context["pii_create_handler_source"] = pii_create_handler_source[:3000]

        judgment = await self._llm_judge(facts, source_context)
        result.llm_calls_made = 1

        # ── Apply LLM judgment ───────────────────────────────────────────
        llm_status = judgment.get("status", "UNKNOWN").upper()
        if llm_status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT"):
            result.status = llm_status  # type: ignore[assignment]
        else:
            result.status = "UNKNOWN"

        if judgment.get("reasoning"):
            result.evidence.append(f"LLM assessment: {judgment['reasoning']}")

        if judgment.get("consent_type"):
            result.evidence.append(
                f"Consent type detected: {judgment['consent_type']}"
            )

        for fix in judgment.get("remediation", []):
            result.remediation.append(fix)

        # ── Fallback remediation ─────────────────────────────────────────
        if not result.remediation:
            if not consent_models:
                result.remediation.append(
                    "Create a DataProcessingConsent model to record when and "
                    "how consent was obtained from each data principal."
                )
            if not consent_middleware_found:
                result.remediation.append(
                    "Add a consent gate (middleware or decorator) on all "
                    "endpoints that create or update personal data."
                )
            result.remediation.append(
                "Ensure consent is: free, specific, informed, unconditional, "
                "and unambiguous, with a clear withdrawal mechanism (DPDP §4)."
            )

        return result

    async def _llm_judge(
        self,
        facts: dict,
        source_context: dict[str, str],
    ) -> dict:
        """Send structured facts + code snippets to LLM for consent judgment."""
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
            logger.warning("No OpenAI API key — skipping LLM judgment for §4")
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM judgment skipped — no API key configured.",
                "consent_type": None,
                "remediation": [],
            }

        try:
            guard_llm_call()
        except LLMCallBlocked as exc:
            logger.warning("LLM blocked for §4 consent judgment: %s", exc)
            return {
                "status": "UNKNOWN",
                "reasoning": f"LLM call blocked: {exc}",
                "consent_type": None,
                "remediation": [],
            }

        system = (
            "You are a DPDP (Digital Personal Data Protection Act, India 2023) "
            "compliance auditor. You are evaluating §4 — consent before "
            "collection of personal data.\n\n"
            "You will receive structured facts about a codebase's consent "
            "mechanisms plus source code snippets.\n\n"
            "CRITICAL DISTINCTION:\n"
            "- **Data-processing consent (DPDP §4)**: Consent to collect, "
            "store, and process a person's personal data. Must be obtained "
            "BEFORE personal data is stored. Think 'privacy policy acceptance', "
            "'I agree to data collection', consent checkbox on registration.\n"
            "- **Clinical/procedure consent**: Consent for a medical procedure "
            "or treatment. This is NOT the same as DPDP consent.\n\n"
            "Evaluate whether the codebase obtains DPDP data-processing consent "
            "before storing personal data. A clinical Consent model alone does "
            "NOT satisfy §4.\n\n"
            "Respond in JSON:\n"
            '{\n'
            '  "status": "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT",\n'
            '  "reasoning": "one paragraph explaining your verdict",\n'
            '  "consent_type": "data_processing" | "clinical" | "both" | "none",\n'
            '  "remediation": ["specific fix 1", "specific fix 2"]\n'
            '}'
        )

        user_parts = [
            "Here are the consent-related facts for this codebase:\n",
            json.dumps(facts, indent=2),
        ]
        if source_context:
            user_parts.append("\n\nSource code snippets:\n")
            for label, code in source_context.items():
                user_parts.append(f"\n### {label}\n```python\n{code}\n```")

        user = "\n".join(user_parts)

        kwargs: dict = {
            "api_key": settings.openai_api_key,
            "timeout": httpx.Timeout(120.0, connect=10.0),
            "max_retries": 3,
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url

        client = OpenAI(**kwargs)

        logger.info("Calling LLM (%s) for §4 consent judgment…", settings.openai_model)

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
        logger.debug("§4 LLM response: %s", raw)

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.error("§4 LLM returned invalid JSON: %s", raw[:200])
            return {
                "status": "UNKNOWN",
                "reasoning": "LLM returned unparseable response.",
                "consent_type": None,
                "remediation": [],
            }
