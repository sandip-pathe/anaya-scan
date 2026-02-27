"""
§8(6) — Breach Notification.

DPDP Act §8(6) requires the data fiduciary to inform the Board and each
affected data principal in the event of a personal data breach, "in such
form and manner as may be prescribed."

This analyzer checks:
1. Whether incident-response / alerting infrastructure exists
   (Sentry, PagerDuty, Opsgenie, custom alert handlers, email alerting).
2. Whether logging covers PII-access events.
3. Whether any breach-notification workflow or model exists.

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

# Libraries / services that indicate breach-notification infrastructure
_ALERTING_IMPORTS = {
    "sentry_sdk": "Sentry (error tracking / alerting)",
    "sentry": "Sentry",
    "raven": "Raven/Sentry legacy",
    "pagerduty": "PagerDuty",
    "opsgenie": "Opsgenie",
    "datadog": "Datadog",
    "newrelic": "New Relic",
    "rollbar": "Rollbar",
    "bugsnag": "Bugsnag",
    "airbrake": "Airbrake",
}

_BREACH_PATTERNS = [
    re.compile(r"breach", re.IGNORECASE),
    re.compile(r"incident.?response", re.IGNORECASE),
    re.compile(r"data.?breach.?notif", re.IGNORECASE),
    re.compile(r"notify.?board|notify.?dpa|notify.?authority", re.IGNORECASE),
    re.compile(r"BreachNotification|DataBreach", re.IGNORECASE),
]

_AUDIT_LOG_PATTERNS = [
    re.compile(r"AuditLog|audit_log", re.IGNORECASE),
    re.compile(r"AccessLog|access_log", re.IGNORECASE),
    re.compile(r"DataAccessLog", re.IGNORECASE),
    re.compile(r"security_event|SecurityEvent", re.IGNORECASE),
]


class BreachNotificationAnalyzer(BaseAnalyzer):
    """Evaluate §8(6) — breach notification readiness."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§8(6)",
            title="Breach Notification",
            llm_calls_made=0,
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — breach notification obligation "
                "does not apply."
            )
            return result

        repo_root = Path(cmap.root)

        # ── 1. Check for alerting/monitoring imports ─────────────────────
        alerting_found: list[str] = []
        for lib in cmap.library_usages:
            module_base = lib.module.split(".")[0].lower()
            if module_base in _ALERTING_IMPORTS:
                desc = _ALERTING_IMPORTS[module_base]
                alerting_found.append(f"{desc} ({lib.module} in {lib.file})")

        # Also grep settings files for DSN / integration config
        for sf in cmap.framework.settings_files:
            full = repo_root / sf
            if not full.is_file():
                continue
            try:
                content = full.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"SENTRY_DSN|sentry_sdk\.init|sentry_dsn", content, re.IGNORECASE):
                alerting_found.append(f"Sentry DSN configured in {sf}")
            if re.search(r"PAGERDUTY|OPSGENIE|DATADOG", content, re.IGNORECASE):
                alerting_found.append(f"Alerting service configured in {sf}")

        # ── 2. Grep for breach-notification code ─────────────────────────
        breach_references: list[str] = []
        py_files = list(repo_root.rglob("*.py"))
        for pyf in py_files:
            if "__pycache__" in str(pyf) or ".venv" in str(pyf):
                continue
            try:
                content = pyf.read_text(errors="replace")
            except OSError:
                continue
            rel = str(pyf.relative_to(repo_root)).replace("\\", "/")
            for pat in _BREACH_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    breach_references.append(f"{rel}:{line_no} — {m.group()}")
                    break  # one match per file is enough

        # ── 3. Check for audit logging models/infrastructure ─────────────
        audit_models: list[str] = []
        for model in cmap.models:
            for pat in _AUDIT_LOG_PATTERNS:
                if pat.search(model.name):
                    audit_models.append(model.name)
                    break

        # Also check for logging imports
        logging_libs = [
            lib for lib in cmap.library_usages
            if lib.category == "logging"
        ]

        # ── 4. Check for email/notification utilities ────────────────────
        email_notification = False
        for pyf in py_files:
            if "__pycache__" in str(pyf) or ".venv" in str(pyf):
                continue
            try:
                content = pyf.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"send_mail|EmailMessage|notify_admins", content):
                email_notification = True
                break

        # ── Build evidence ───────────────────────────────────────────────
        has_alerting = bool(alerting_found)
        has_breach_code = bool(breach_references)
        has_audit = bool(audit_models)

        if alerting_found:
            result.evidence.append(
                f"Alerting/monitoring infrastructure detected: "
                f"{'; '.join(alerting_found[:5])}"
            )
        else:
            result.evidence.append(
                "No alerting/monitoring service detected (no Sentry, "
                "PagerDuty, Datadog, etc.)."
            )

        if breach_references:
            result.evidence.append(
                f"Breach-related code references found: "
                f"{'; '.join(breach_references[:5])}"
            )
        else:
            result.evidence.append(
                "No breach notification workflow or model found in codebase."
            )

        if audit_models:
            result.evidence.append(
                f"Audit logging model(s): {', '.join(audit_models)}"
            )

        if logging_libs:
            result.evidence.append(
                f"{len(logging_libs)} logging-related import(s) found."
            )

        if email_notification:
            result.evidence.append(
                "Email notification capability detected (send_mail/EmailMessage)."
            )

        # ── Determine status ─────────────────────────────────────────────
        if has_breach_code and has_alerting:
            result.status = "PARTIAL"
            result.evidence.append(
                "Alerting infrastructure exists and breach-related code "
                "is present, but a formal DPDP-compliant breach notification "
                "workflow (notify Board + affected data principals) should "
                "be verified manually."
            )
        elif has_alerting or has_audit:
            result.status = "PARTIAL"
            result.evidence.append(
                "Monitoring/audit infrastructure exists but no explicit "
                "breach notification workflow found."
            )
        else:
            result.status = "NON_COMPLIANT"

        # ── Blockers ─────────────────────────────────────────────────────
        if not has_breach_code:
            result.blockers.append(
                "No breach notification model or handler — §8(6) requires "
                "notifying the Board and affected data principals."
            )
        if not has_alerting:
            result.blockers.append(
                "No alerting service integration — breaches may go undetected."
            )

        # ── Remediation ──────────────────────────────────────────────────
        if not has_alerting:
            result.remediation.append(
                "Integrate an alerting service (Sentry, PagerDuty, or "
                "custom webhook) to detect anomalous data access."
            )
        if not has_breach_code:
            result.remediation.append(
                "Implement a BreachNotification model and workflow: "
                "detect breach → log details → notify Board within 72 hours "
                "→ notify affected data principals."
            )
        if not has_audit:
            result.remediation.append(
                "Add audit logging for all PII access events to enable "
                "breach forensics and affected-user identification."
            )

        return result
