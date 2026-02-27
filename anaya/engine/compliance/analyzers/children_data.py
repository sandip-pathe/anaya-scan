"""
§9 — Children's Data.

DPDP Act §9 prohibits processing personal data of children (under 18) that
is likely to cause any detrimental effect on their well-being. It also
requires verifiable consent from a parent/guardian before processing a
child's data. Tracking, behavioral monitoring, and targeted advertising
directed at children are explicitly prohibited.

This analyzer checks:
1. Whether any model stores age/DOB fields (from PII map).
2. Whether age-gating logic exists (min_age checks, age verification).
3. Whether child-specific models exist.
4. Whether parental consent mechanisms are present.

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

_AGE_FIELD_NAMES = {
    "date_of_birth", "dob", "birth_date", "birthdate",
    "age", "year_of_birth", "birth_year",
}

_CHILD_PATTERNS = [
    re.compile(r"child|minor|juvenile|under.?age|underage", re.IGNORECASE),
    re.compile(r"parental.?consent|guardian.?consent", re.IGNORECASE),
    re.compile(r"age.?gate|age.?check|age.?verif|verify.?age|min.?age", re.IGNORECASE),
    re.compile(r"is.?child|is.?minor", re.IGNORECASE),
]

_AGE_GATE_PATTERNS = [
    re.compile(r"age\s*[<>=!]+\s*1[0-8]", re.IGNORECASE),
    re.compile(r"years?\s*[<>=!]+\s*1[0-8]", re.IGNORECASE),
    re.compile(r"MIN_AGE|MINIMUM_AGE|CHILD_AGE", re.IGNORECASE),
    re.compile(r"if.*age.*(?:18|fourteen|sixteen|thirteen)", re.IGNORECASE),
    re.compile(r"timedelta.*days.*(?:6570|6574)", re.IGNORECASE),  # ~18 years in days
]


class ChildrenDataAnalyzer(BaseAnalyzer):
    """Evaluate §9 — processing of children's personal data."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§9",
            title="Children's Data",
            llm_calls_made=0,
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — children's data obligation "
                "does not apply."
            )
            return result

        repo_root = Path(cmap.root)
        pii_model_set = set(pii_map.pii_models)

        # ── 1. Find age/DOB fields in PII models ────────────────────────
        age_fields_in_pii: list[str] = []
        for model in cmap.models:
            if model.name not in pii_model_set:
                continue
            for field in model.fields:
                if field.name.lower() in _AGE_FIELD_NAMES:
                    age_fields_in_pii.append(f"{model.name}.{field.name}")

        # Also check the PII map's children_data_risk flag
        children_risk_flag = pii_map.children_data_risk

        # ── 2. Find child-related models ─────────────────────────────────
        child_models: list[str] = []
        for model in cmap.models:
            name_lower = model.name.lower()
            if any(kw in name_lower for kw in ("child", "minor", "juvenile", "kid", "infant", "pediatric", "paediatric")):
                child_models.append(model.name)

        # ── 3. Grep for age-gating logic ─────────────────────────────────
        age_gate_refs: list[str] = []
        child_refs: list[str] = []
        parental_consent_refs: list[str] = []

        py_files = list(repo_root.rglob("*.py"))
        for pyf in py_files:
            if "__pycache__" in str(pyf) or ".venv" in str(pyf):
                continue
            try:
                content = pyf.read_text(errors="replace")
            except OSError:
                continue
            rel = str(pyf.relative_to(repo_root)).replace("\\", "/")

            # Age gate patterns
            for pat in _AGE_GATE_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    age_gate_refs.append(f"{rel}:{line_no} — {m.group().strip()}")
                    break

            # Child-related references
            for pat in _CHILD_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    matched_text = m.group().strip()
                    if "parental" in matched_text.lower() or "guardian" in matched_text.lower():
                        parental_consent_refs.append(f"{rel}:{line_no}")
                    else:
                        child_refs.append(f"{rel}:{line_no} — {matched_text}")
                    break

        # ── Build evidence ───────────────────────────────────────────────
        has_age_fields = bool(age_fields_in_pii)
        has_age_gate = bool(age_gate_refs)
        has_parental_consent = bool(parental_consent_refs)
        collects_children = has_age_fields or bool(child_models) or children_risk_flag

        if age_fields_in_pii:
            result.evidence.append(
                f"Age/DOB fields found in PII models: "
                f"{', '.join(age_fields_in_pii)}"
            )
        else:
            result.evidence.append(
                "No age/DOB fields detected in PII models."
            )

        if child_models:
            result.evidence.append(
                f"Child-related model(s): {', '.join(child_models)}"
            )

        if age_gate_refs:
            result.evidence.append(
                f"Age-gating logic found: {'; '.join(age_gate_refs[:5])}"
            )
        else:
            result.evidence.append("No age-gating logic found in codebase.")

        if parental_consent_refs:
            result.evidence.append(
                f"Parental consent reference(s): "
                f"{'; '.join(parental_consent_refs[:5])}"
            )
        else:
            result.evidence.append(
                "No parental consent mechanism found."
            )

        if child_refs:
            result.evidence.append(
                f"Child-related code references: "
                f"{'; '.join(child_refs[:5])}"
            )

        if children_risk_flag:
            result.evidence.append(
                "LLM PII mapper flagged children_data_risk = True."
            )

        # ── Determine status ─────────────────────────────────────────────
        if not collects_children:
            # No evidence the system handles children's data
            result.status = "COMPLIANT"
            result.evidence.append(
                "No evidence the system collects or processes children's "
                "personal data specifically."
            )
        elif has_age_gate and has_parental_consent:
            result.status = "PARTIAL"
            result.evidence.append(
                "Age-gating and parental consent mechanisms exist — "
                "manual verification needed for full §9 compliance."
            )
        elif has_age_fields and not has_age_gate:
            result.status = "NON_COMPLIANT"
        else:
            result.status = "PARTIAL"

        # ── Blockers ─────────────────────────────────────────────────────
        if has_age_fields and not has_age_gate:
            result.blockers.append(
                f"DOB/age fields ({', '.join(age_fields_in_pii)}) exist but "
                f"no age-gating logic — children's data may be processed "
                f"without appropriate safeguards."
            )
        if collects_children and not has_parental_consent:
            result.blockers.append(
                "No parental/guardian consent mechanism — §9 requires "
                "verifiable parental consent before processing a child's data."
            )

        # ── Remediation ──────────────────────────────────────────────────
        if has_age_fields and not has_age_gate:
            result.remediation.append(
                "Add age verification at registration: if date_of_birth "
                "indicates age < 18, require verifiable parental consent "
                "before storing any personal data."
            )
        if collects_children and not has_parental_consent:
            result.remediation.append(
                "Implement a ParentalConsent model and workflow: "
                "parent/guardian must verify identity and explicitly consent "
                "before the child's data is processed."
            )
        if collects_children:
            result.remediation.append(
                "Ensure no tracking, behavioral monitoring, or targeted "
                "advertising is directed at users identified as children (§9(3))."
            )

        return result
