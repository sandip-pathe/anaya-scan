"""
PersonalDataMapper — single LLM call to classify PII across the codebase.

Takes a CodebaseMap (from CodebaseIndexer) and produces a PersonalDataMap:
which models/fields contain personal data under DPDP, classified by sensitivity.

The result is cached by repo+git_sha so repeated scans on the same commit
cost zero tokens.

Usage:
    from anaya.engine.compliance.pii_mapper import PersonalDataMapper
    from anaya.engine.compliance.indexer import CodebaseIndexer

    cmap = CodebaseIndexer("/path/to/repo").build()
    mapper = PersonalDataMapper()
    pii_map = mapper.map(cmap)
    print(pii_map.model_dump_json(indent=2))
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from anaya.engine.compliance.models import CodebaseMap

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Output models
# ─────────────────────────────────────────────────────────────────────────────


class FieldClassification(BaseModel):
    """Classification of a single model field."""
    field_name: str
    field_type: str
    classification: str   # PII | SENSITIVE_PII | INDIRECT | NOT_PII
    reason: str = ""      # brief justification from LLM


class ModelClassification(BaseModel):
    """Classification of all fields in a single model."""
    model_name: str
    file: str
    fields: list[FieldClassification] = Field(default_factory=list)
    has_pii: bool = False
    has_sensitive_pii: bool = False


class PersonalDataMap(BaseModel):
    """
    The complete PII classification of a codebase.
    Produced by one LLM call, cached per repo+sha.
    """

    # Models that contain any PII
    pii_models: list[str] = Field(default_factory=list)

    # Models with SENSITIVE_PII (health, financial, children, biometric)
    sensitive_models: list[str] = Field(default_factory=list)

    # Full per-model, per-field breakdown
    model_classifications: list[ModelClassification] = Field(default_factory=list)

    # Flat dict for quick lookup: {model_name: {field_name: classification}}
    field_classifications: dict[str, dict[str, str]] = Field(default_factory=dict)

    # Specific risk flags
    children_data_risk: bool = False    # model has DOB/age + no age gate detected
    aadhaar_fields: list[str] = Field(default_factory=list)    # "Model.field" format
    financial_fields: list[str] = Field(default_factory=list)  # payment/transaction fields
    health_fields: list[str] = Field(default_factory=list)     # diagnosis, conditions, etc.

    # Metadata
    git_sha: str | None = None
    llm_model: str | None = None
    cached: bool = False

    # Stats
    stats: dict[str, int] = Field(default_factory=dict)

    def compute_stats(self) -> None:
        total_fields = sum(len(mc.fields) for mc in self.model_classifications)
        pii_count = sum(
            1 for mc in self.model_classifications
            for f in mc.fields if f.classification == "PII"
        )
        sensitive_count = sum(
            1 for mc in self.model_classifications
            for f in mc.fields if f.classification == "SENSITIVE_PII"
        )
        indirect_count = sum(
            1 for mc in self.model_classifications
            for f in mc.fields if f.classification == "INDIRECT"
        )
        self.stats = {
            "total_models_analyzed": len(self.model_classifications),
            "pii_models": len(self.pii_models),
            "sensitive_models": len(self.sensitive_models),
            "total_fields": total_fields,
            "pii_fields": pii_count,
            "sensitive_pii_fields": sensitive_count,
            "indirect_fields": indirect_count,
            "not_pii_fields": total_fields - pii_count - sensitive_count - indirect_count,
            "aadhaar_fields": len(self.aadhaar_fields),
            "financial_fields": len(self.financial_fields),
            "health_fields": len(self.health_fields),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Cache
# ─────────────────────────────────────────────────────────────────────────────

_CACHE_DIR = Path.home() / ".anaya" / "pii_cache"


def _cache_key(root: str, sha: str | None) -> str:
    """Generate a deterministic cache key."""
    raw = f"{root}:{sha or 'unknown'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load_cache(root: str, sha: str | None) -> PersonalDataMap | None:
    """Load cached PersonalDataMap if it exists for this repo+sha."""
    if not sha:
        return None
    key = _cache_key(root, sha)
    cache_file = _CACHE_DIR / f"{key}.json"
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            pmap = PersonalDataMap(**data)
            pmap.cached = True
            logger.info("Loaded cached PII map for sha=%s", sha)
            return pmap
        except Exception as exc:
            logger.debug("Cache read failed: %s", exc)
    return None


def _save_cache(root: str, sha: str | None, pmap: PersonalDataMap) -> None:
    """Persist PersonalDataMap to local cache."""
    if not sha:
        return
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        key = _cache_key(root, sha)
        cache_file = _CACHE_DIR / f"{key}.json"
        cache_file.write_text(
            pmap.model_dump_json(indent=2), encoding="utf-8"
        )
        logger.info("Cached PII map at %s", cache_file)
    except Exception as exc:
        logger.warning("Failed to write PII cache: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Prompt construction
# ─────────────────────────────────────────────────────────────────────────────


_SYSTEM_PROMPT = """\
You are a data privacy expert analysing a codebase for compliance with \
India's Digital Personal Data Protection Act (DPDP Act, 2023).

You will receive a list of database models with their field names and types \
from a {framework} application.

For EACH field in EACH model, classify it as one of:

- **PII**: Directly identifies a natural person. Examples: name, phone number, \
email, address, date of birth, national ID (Aadhaar), passport number, photo.
- **SENSITIVE_PII**: Special category personal data under DPDP §9. Examples: \
health/medical data (diagnosis, conditions, medication, blood group, vital signs), \
financial data (bank account, payment info, invoice amounts), children's data, \
biometric data, caste, religion, sexual orientation, genetic data.
- **INDIRECT**: Does not identify alone but could when combined with other data. \
Examples: IP address, device ID, geo-coordinates, organisation membership, \
usage timestamps tied to a user.
- **NOT_PII**: Non-personal metadata. Examples: status enums, configuration flags, \
auto-generated IDs (UUIDs, PKs), system timestamps not tied to a person, \
boolean flags, structural FKs to non-personal entities.

IMPORTANT CONTEXT:
- A model named `PatientIdentifier` with a field `value` (CharField) stores \
national identifiers including Aadhaar numbers. The `PatientIdentifierConfig` \
model defines what type of identifier it is. Classify `PatientIdentifier.value` \
as PII (national ID / Aadhaar).
- ForeignKey fields to personal models (e.g. FK to Patient) should be classified \
as INDIRECT — they reference a person but don't contain PII themselves.
- Fields like `external_id`, `id`, `created_date`, `modified_date` are NOT_PII \
unless they are explicitly personal.

Respond ONLY with valid JSON matching this exact schema (no markdown, no explanation):

{{
  "models": [
    {{
      "model_name": "ModelName",
      "fields": [
        {{
          "field_name": "field_name",
          "classification": "PII|SENSITIVE_PII|INDIRECT|NOT_PII",
          "reason": "brief reason"
        }}
      ]
    }}
  ],
  "aadhaar_fields": ["Model.field"],
  "financial_fields": ["Model.field"],
  "health_fields": ["Model.field"],
  "children_data_risk": true/false
}}
"""


def _build_user_prompt_for_models(cmap: CodebaseMap, models: list) -> str:
    """Build the user prompt for a subset of models from the CodebaseMap."""
    lines: list[str] = []
    lines.append(f"Framework: {cmap.framework.primary.value}")
    lines.append(f"ORM: {cmap.framework.orm or 'unknown'}")
    lines.append(f"Models in this batch: {len(models)}")
    lines.append("")
    lines.append("=" * 60)
    lines.append("MODELS AND FIELDS")
    lines.append("=" * 60)

    for model in models:
        if not model.fields:
            continue
        lines.append(f"\n## {model.name}  ({model.file})")
        if model.base_classes:
            lines.append(f"   Bases: {', '.join(model.base_classes)}")
        for field in model.fields:
            fk_info = ""
            if field.related_model:
                fk_info = f" -> {field.related_model}"
                if field.on_delete:
                    fk_info += f" (on_delete={field.on_delete.value})"
            encrypted = " [ENCRYPTED]" if field.is_encrypted else ""
            nullable = " nullable" if field.is_nullable else ""
            maxlen = f" max_length={field.max_length}" if field.max_length else ""
            lines.append(
                f"   - {field.name}: {field.field_type}"
                f"{maxlen}{nullable}{fk_info}{encrypted}"
            )

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# LLM call
# ─────────────────────────────────────────────────────────────────────────────


def _call_llm(system_prompt: str, user_prompt: str) -> dict[str, Any]:
    """Make a single OpenAI chat completion call and parse JSON response."""
    import httpx
    from openai import OpenAI
    from anaya.config import settings

    if not settings.openai_api_key:
        raise ValueError(
            "OPENAI_API_KEY is required for PersonalDataMapper. "
            "Set it in your .env file or environment."
        )

    kwargs: dict[str, Any] = {
        "api_key": settings.openai_api_key,
        "timeout": httpx.Timeout(180.0, connect=10.0),
        "max_retries": 3,
    }
    if settings.openai_base_url:
        kwargs["base_url"] = settings.openai_base_url

    client = OpenAI(**kwargs)
    model = settings.openai_model

    logger.info("Calling LLM (%s) for PII classification…", model)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.0,
        max_tokens=16384,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content or "{}"
    logger.debug("LLM raw response length: %d chars", len(raw))

    return json.loads(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Main mapper
# ─────────────────────────────────────────────────────────────────────────────


class PersonalDataMapper:
    """
    Classify all model fields as PII / SENSITIVE_PII / INDIRECT / NOT_PII.

    Single LLM call. Result cached per repo + git SHA.
    """

    # Maximum models per LLM batch — keeps output JSON within token limits.
    BATCH_SIZE = 25

    def map(self, cmap: CodebaseMap, *, force: bool = False) -> PersonalDataMap:
        """
        Produce a PersonalDataMap from a CodebaseMap.

        Args:
            cmap: The structural map from CodebaseIndexer.
            force: If True, skip cache and always call the LLM.

        Returns:
            PersonalDataMap with per-field classifications.
        """
        # ── Check cache ───────────────────────────────────────────────────
        if not force:
            cached = _load_cache(cmap.root, cmap.git_sha)
            if cached is not None:
                return cached

        # ── Filter models that actually have fields ───────────────────────
        models_with_fields = [m for m in cmap.models if m.fields]

        logger.info(
            "PII mapping: %d models, ~%d fields",
            len(models_with_fields),
            sum(len(m.fields) for m in models_with_fields),
        )

        # ── Build system prompt (shared across batches) ───────────────────
        system = _SYSTEM_PROMPT.format(
            framework=cmap.framework.primary.value
        )

        # ── Chunk models into batches and call LLM for each ──────────────
        batches = [
            models_with_fields[i : i + self.BATCH_SIZE]
            for i in range(0, len(models_with_fields), self.BATCH_SIZE)
        ]

        merged_result: dict[str, Any] = {
            "models": [],
            "children_data_risk": False,
            "aadhaar_fields": [],
            "financial_fields": [],
            "health_fields": [],
        }

        for batch_idx, batch in enumerate(batches, 1):
            user_prompt = _build_user_prompt_for_models(cmap, batch)
            logger.info(
                "Batch %d/%d: %d models, prompt ~%d chars",
                batch_idx, len(batches), len(batch), len(user_prompt),
            )
            result = _call_llm(system, user_prompt)

            # Merge batch result into the combined result
            merged_result["models"].extend(result.get("models", []))
            if result.get("children_data_risk"):
                merged_result["children_data_risk"] = True
            merged_result["aadhaar_fields"].extend(
                result.get("aadhaar_fields", [])
            )
            merged_result["financial_fields"].extend(
                result.get("financial_fields", [])
            )
            merged_result["health_fields"].extend(
                result.get("health_fields", [])
            )

        # ── Parse merged response ─────────────────────────────────────────
        pmap = self._parse_response(merged_result, cmap)
        pmap.git_sha = cmap.git_sha
        from anaya.config import settings
        pmap.llm_model = settings.openai_model
        pmap.compute_stats()

        # ── Cache result ──────────────────────────────────────────────────
        _save_cache(cmap.root, cmap.git_sha, pmap)

        return pmap

    def _parse_response(
        self, raw: dict[str, Any], cmap: CodebaseMap
    ) -> PersonalDataMap:
        """Parse the LLM JSON response into a PersonalDataMap."""
        # Build a file lookup from cmap
        model_files = {m.name: m.file for m in cmap.models}
        model_field_types = {
            m.name: {f.name: f.field_type for f in m.fields}
            for m in cmap.models
        }

        model_classifications: list[ModelClassification] = []
        field_classifications: dict[str, dict[str, str]] = {}
        pii_models: list[str] = []
        sensitive_models: list[str] = []

        for model_data in raw.get("models", []):
            model_name = model_data.get("model_name", "")
            if not model_name:
                continue

            fields: list[FieldClassification] = []
            model_field_map: dict[str, str] = {}
            has_pii = False
            has_sensitive = False

            for field_data in model_data.get("fields", []):
                fname = field_data.get("field_name", "")
                classification = field_data.get("classification", "NOT_PII")
                reason = field_data.get("reason", "")

                # Normalise classification
                classification = classification.upper().replace(" ", "_")
                if classification not in ("PII", "SENSITIVE_PII", "INDIRECT", "NOT_PII"):
                    classification = "NOT_PII"

                ftype = model_field_types.get(model_name, {}).get(fname, "")

                fields.append(FieldClassification(
                    field_name=fname,
                    field_type=ftype,
                    classification=classification,
                    reason=reason,
                ))
                model_field_map[fname] = classification

                if classification == "PII":
                    has_pii = True
                elif classification == "SENSITIVE_PII":
                    has_sensitive = True
                    has_pii = True  # sensitive is a superset

            model_classifications.append(ModelClassification(
                model_name=model_name,
                file=model_files.get(model_name, ""),
                fields=fields,
                has_pii=has_pii,
                has_sensitive_pii=has_sensitive,
            ))
            field_classifications[model_name] = model_field_map

            if has_pii:
                pii_models.append(model_name)
            if has_sensitive:
                sensitive_models.append(model_name)

        return PersonalDataMap(
            pii_models=pii_models,
            sensitive_models=sensitive_models,
            model_classifications=model_classifications,
            field_classifications=field_classifications,
            children_data_risk=raw.get("children_data_risk", False),
            aadhaar_fields=raw.get("aadhaar_fields", []),
            financial_fields=raw.get("financial_fields", []),
            health_fields=raw.get("health_fields", []),
        )
