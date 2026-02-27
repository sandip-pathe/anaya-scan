"""
LLM Violation Enhancer — enriches pattern/AST findings with AI context.

After pattern and AST scanners find violations, this module sends them
to GPT-4o-mini to add:
- Why this matters (business/compliance context)
- How to fix it (specific remediation steps)
- Regulatory reference (which section of which regulation)
- False positive assessment (LLM's opinion on whether it's real)

Runs as a batch — all violations from a file in one API call.
Cost: ~$0.001 per file (GPT-4o-mini pricing).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from anaya.config import settings
from anaya.engine.models import Violation

logger = logging.getLogger(__name__)

ENHANCER_SYSTEM = """You are a senior security and compliance auditor reviewing
code violations found by a static analysis tool. For each violation, provide
additional context to help the developer understand and fix it.

You will receive the source file content and a list of violations found in it.
For each violation, respond with a JSON object containing:

- "is_likely_fp": boolean — true if this is likely a false positive
- "fp_reason": string — if is_likely_fp, explain why (empty string otherwise)
- "business_impact": string — 1-2 sentences on why this matters for the business  
- "remediation": string — specific, actionable fix steps (not generic advice)
- "regulatory_ref": string — specific regulation section if applicable

Respond ONLY with a JSON array of objects, one per violation, in the same order.
No markdown, no explanation outside the JSON."""

ENHANCER_USER = """## Source File: {file_path}

```
{content}
```

## Violations Found:

{violations_json}

Analyze each violation in context and respond with a JSON array."""


class LLMViolationEnhancer:
    """Enriches pattern/AST violations with LLM-generated context."""

    def __init__(self) -> None:
        from openai import OpenAI

        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY required for LLM enhancer")

        kwargs: dict[str, Any] = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url

        self._client = OpenAI(**kwargs)
        self._model = settings.openai_model
        self._timeout = settings.llm_timeout

    def enhance_violations(
        self,
        file_path: str,
        content: str,
        violations: list[Violation],
    ) -> list[Violation]:
        """
        Enhance violations with LLM-generated context.

        Args:
            file_path: Path to the source file.
            content: Full file content.
            violations: Violations found by pattern/AST scanners.

        Returns:
            Updated violations with enhanced messages and adjusted confidence.
        """
        if not violations:
            return violations

        # Truncate content if too large (keep first 8000 chars)
        truncated = content[:8000] if len(content) > 8000 else content

        # Build violations JSON for the prompt
        v_data = [
            {
                "index": i,
                "rule_id": v.rule_id,
                "rule_name": v.rule_name,
                "severity": v.severity.value,
                "line": v.line_start,
                "snippet": v.snippet or "",
                "message": v.message,
            }
            for i, v in enumerate(violations)
        ]

        user_prompt = ENHANCER_USER.format(
            file_path=file_path,
            content=truncated,
            violations_json=json.dumps(v_data, indent=2),
        )

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": ENHANCER_SYSTEM},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=2000,
                timeout=self._timeout,
            )

            raw = response.choices[0].message.content or "[]"
            # Strip markdown code fences if present
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            enhancements = json.loads(raw)

            if not isinstance(enhancements, list):
                logger.warning("LLM enhancer returned non-list: %s", type(enhancements))
                return violations

            # Apply enhancements
            for i, enhancement in enumerate(enhancements):
                if i >= len(violations):
                    break

                v = violations[i]

                # If LLM thinks it's a false positive, lower confidence
                if enhancement.get("is_likely_fp", False):
                    v.confidence = max(0.1, v.confidence - 0.5)
                    fp_reason = enhancement.get("fp_reason", "")
                    if fp_reason:
                        v.message = f"{v.message} [LLM note: likely FP — {fp_reason}]"

                # Enhance fix_hint with specific remediation
                remediation = enhancement.get("remediation", "")
                if remediation and remediation != v.fix_hint:
                    v.fix_hint = remediation

                # Add business impact to message
                impact = enhancement.get("business_impact", "")
                if impact:
                    v.message = f"{v.message}\n\n**Impact:** {impact}"

                # Add regulatory reference
                reg_ref = enhancement.get("regulatory_ref", "")
                if reg_ref and reg_ref not in v.references:
                    v.references.append(reg_ref)

            logger.info(
                "Enhanced %d violations for %s", len(violations), file_path
            )

        except json.JSONDecodeError:
            logger.warning("LLM enhancer returned invalid JSON for %s", file_path)
        except Exception:
            logger.warning("LLM enhancer failed for %s", file_path, exc_info=True)

        return violations
