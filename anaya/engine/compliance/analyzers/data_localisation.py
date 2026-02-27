"""
§11 — Data Localisation (Cross-Border Transfer).

DPDP Act §11 allows the Central Government to restrict transfer of personal
data to certain countries/territories. Until specific restrictions are
notified, data may flow freely — but the data fiduciary should know WHERE
data is stored and be prepared to comply with future restrictions.

This analyzer checks:
1. Cloud provider region configuration (AWS, GCP, Azure).
2. Database connection strings for hosted regions.
3. Third-party data transfer (S3, external APIs, CDN).
4. Whether any data-localisation configuration exists.

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

# Indian cloud regions
_INDIAN_REGIONS = {
    # AWS
    "ap-south-1", "ap-south-2",
    # GCP
    "asia-south1", "asia-south2",
    # Azure
    "centralindia", "southindia", "westindia", "jioindiawest", "jioindiacentral",
}

_REGION_PATTERNS = [
    re.compile(r"AWS_REGION|AWS_DEFAULT_REGION|REGION_NAME", re.IGNORECASE),
    re.compile(r"ap-south-[12]"),  # AWS India
    re.compile(r"asia-south[12]"),  # GCP India
    re.compile(r"centralindia|southindia|westindia|jioindia", re.IGNORECASE),  # Azure India
    re.compile(r"GOOGLE_CLOUD_REGION|GCP_REGION|AZURE_REGION", re.IGNORECASE),
]

_CLOUD_STORAGE_PATTERNS = [
    re.compile(r"S3Boto3Storage|AWS_S3|boto3|s3_bucket", re.IGNORECASE),
    re.compile(r"google.cloud.storage|GCS_BUCKET", re.IGNORECASE),
    re.compile(r"azure.storage.blob|AZURE_CONTAINER", re.IGNORECASE),
    re.compile(r"DEFAULT_FILE_STORAGE|STATICFILES_STORAGE", re.IGNORECASE),
]

_DB_HOST_PATTERNS = [
    re.compile(r"DATABASE_URL|DB_HOST|DATABASES", re.IGNORECASE),
    re.compile(r"\.rds\.amazonaws\.com"),
    re.compile(r"\.sql\.gcp\."),
    re.compile(r"\.database\.azure\.com"),
    re.compile(r"\.mongodb\.net"),
]

_EXTERNAL_API_PATTERNS = [
    re.compile(r"https?://[a-zA-Z0-9.-]+\.(?:com|io|net|org)/api", re.IGNORECASE),
    re.compile(r"EXTERNAL_API|THIRD_PARTY_URL|WEBHOOK_URL", re.IGNORECASE),
]


class DataLocalisationAnalyzer(BaseAnalyzer):
    """Evaluate §11 — data localisation and cross-border transfer."""

    async def analyze(
        self,
        cmap: CodebaseMap,
        pii_map: PersonalDataMap,
    ) -> SectionResult:
        result = SectionResult(
            section="§11",
            title="Data Localisation",
            llm_calls_made=0,
        )

        if not pii_map.pii_models:
            result.status = "COMPLIANT"
            result.evidence.append(
                "No PII models detected — localisation obligation "
                "does not apply."
            )
            return result

        repo_root = Path(cmap.root)

        # Collect all relevant files
        region_refs: list[str] = []
        cloud_storage_refs: list[str] = []
        db_host_refs: list[str] = []
        external_api_refs: list[str] = []
        indian_region_found = False
        non_indian_region_found = False
        region_values: list[str] = []

        # Scan settings files first (highest signal)
        scan_files: list[Path] = []
        for sf in cmap.framework.settings_files:
            p = repo_root / sf
            if p.is_file():
                scan_files.append(p)

        # Also scan .env files and config files
        for pattern in ["*.env", ".env*", "*.yml", "*.yaml", "*.toml", "*.cfg", "*.ini"]:
            for f in repo_root.glob(pattern):
                if f.is_file() and f not in scan_files:
                    scan_files.append(f)

        # Add Dockerfiles and compose files
        for name in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
            p = repo_root / name
            if p.is_file() and p not in scan_files:
                scan_files.append(p)

        # Also scan py files for region config
        py_files = list(repo_root.rglob("*.py"))
        for pyf in py_files:
            if "__pycache__" in str(pyf) or ".venv" in str(pyf):
                continue
            if pyf not in scan_files:
                scan_files.append(pyf)

        for fpath in scan_files:
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue
            rel = str(fpath.relative_to(repo_root)).replace("\\", "/")

            # Region patterns
            for pat in _REGION_PATTERNS:
                for m in pat.finditer(content):
                    line_no = content[:m.start()].count("\n") + 1
                    matched = m.group().strip()
                    region_refs.append(f"{rel}:{line_no} — {matched}")

                    # Check if the value is an Indian region
                    # Look for the value after = or : on same line
                    line = content.split("\n")[line_no - 1]
                    for region in _INDIAN_REGIONS:
                        if region in line.lower():
                            indian_region_found = True
                            region_values.append(f"{region} (in {rel})")
                    # Check for non-Indian AWS regions
                    non_india_match = re.search(
                        r"(us-east|us-west|eu-west|eu-central|ap-northeast|"
                        r"ap-southeast|sa-east|ca-central|me-south|af-south|"
                        r"us-gov|europe-west|europe-north|northeurope|"
                        r"westeurope|eastus|westus|northcentralus|southcentralus)",
                        line, re.IGNORECASE,
                    )
                    if non_india_match:
                        non_indian_region_found = True
                        region_values.append(
                            f"{non_india_match.group()} (in {rel})"
                        )

            # Cloud storage
            for pat in _CLOUD_STORAGE_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    cloud_storage_refs.append(f"{rel}:{line_no} — {m.group()}")

            # DB host
            for pat in _DB_HOST_PATTERNS:
                m = pat.search(content)
                if m:
                    line_no = content[:m.start()].count("\n") + 1
                    db_host_refs.append(f"{rel}:{line_no} — {m.group()}")

            # External APIs (only in py files)
            if str(fpath).endswith(".py"):
                for pat in _EXTERNAL_API_PATTERNS:
                    m = pat.search(content)
                    if m:
                        line_no = content[:m.start()].count("\n") + 1
                        external_api_refs.append(
                            f"{rel}:{line_no} — {m.group()[:80]}"
                        )

        # ── Build evidence ───────────────────────────────────────────────
        has_region_config = bool(region_refs)
        has_cloud_storage = bool(cloud_storage_refs)
        has_db_config = bool(db_host_refs)

        if region_refs:
            result.evidence.append(
                f"Cloud region configuration found: "
                f"{'; '.join(region_refs[:5])}"
            )
        else:
            result.evidence.append(
                "No explicit cloud region configuration detected."
            )

        if indian_region_found:
            india_regions = [r for r in region_values if any(
                ir in r.lower() for ir in (
                    "ap-south", "asia-south", "centralindia",
                    "southindia", "westindia", "jioindia",
                )
            )]
            result.evidence.append(
                f"Indian cloud region detected: {', '.join(india_regions[:3])}"
            )

        if non_indian_region_found:
            non_india = [r for r in region_values if not any(
                ir in r.lower() for ir in (
                    "ap-south", "asia-south", "centralindia",
                    "southindia", "westindia", "jioindia",
                )
            )]
            result.evidence.append(
                f"Non-Indian cloud region detected: {', '.join(non_india[:3])}. "
                f"Personal data may be stored outside India."
            )

        if cloud_storage_refs:
            result.evidence.append(
                f"Cloud storage service(s) used: "
                f"{'; '.join(cloud_storage_refs[:3])}"
            )

        if db_host_refs:
            result.evidence.append(
                f"Database host configuration: "
                f"{'; '.join(db_host_refs[:3])}"
            )

        if external_api_refs:
            result.evidence.append(
                f"External API integrations detected: "
                f"{'; '.join(external_api_refs[:3])}"
            )

        # ── Determine status ─────────────────────────────────────────────
        # §11 is currently permissive — no countries are restricted yet.
        # We check preparedness: does the codebase know where data lives?

        if not has_region_config and not has_cloud_storage and not has_db_config:
            result.status = "UNKNOWN"
            result.evidence.append(
                "Cannot determine data storage location — no region "
                "configuration, cloud storage, or database host detected. "
                "Deployment infrastructure may be configured externally."
            )
        elif indian_region_found and not non_indian_region_found:
            result.status = "COMPLIANT"
            result.evidence.append(
                "Data appears to be stored in Indian cloud region(s). "
                "No evidence of cross-border transfer."
            )
        elif non_indian_region_found and not indian_region_found:
            result.status = "PARTIAL"
            result.evidence.append(
                "Data appears to be stored outside India. As of now §11 "
                "does not restrict most transfers, but the Central "
                "Government may issue restrictions in the future."
            )
        elif indian_region_found and non_indian_region_found:
            result.status = "PARTIAL"
            result.evidence.append(
                "Multiple regions detected — data may be replicated across "
                "Indian and non-Indian regions."
            )
        else:
            result.status = "PARTIAL"

        # ── Blockers ─────────────────────────────────────────────────────
        if non_indian_region_found:
            result.blockers.append(
                "Non-Indian cloud region in use — if the Central Government "
                "restricts transfers to that region, migration will be needed."
            )
        if not has_region_config:
            result.blockers.append(
                "No explicit region configuration — cannot verify data "
                "residency without inspecting deployment infrastructure."
            )

        # ── Remediation ──────────────────────────────────────────────────
        if not has_region_config:
            result.remediation.append(
                "Explicitly configure cloud region in settings/env vars "
                "(e.g., AWS_REGION=ap-south-1) for auditability."
            )
        if non_indian_region_found:
            result.remediation.append(
                "Consider migrating PII storage to an Indian cloud region "
                "(AWS ap-south-1/ap-south-2, GCP asia-south1/asia-south2, "
                "Azure centralindia) to future-proof against §11 restrictions."
            )
        if has_cloud_storage and not indian_region_found:
            result.remediation.append(
                "Verify cloud storage buckets are in Indian regions, or "
                "configure region-specific buckets for PII data."
            )
        result.remediation.append(
            "Document data flow: where PII is stored, processed, and "
            "transferred — this inventory is required for §11 compliance."
        )

        return result
