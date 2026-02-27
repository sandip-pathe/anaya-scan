"""
DPDP Section Analyzers.

Each analyzer evaluates one section of the Digital Personal Data Protection Act
against a CodebaseMap + PersonalDataMap, producing a SectionResult.
"""

from anaya.engine.compliance.analyzers.base import SectionResult, BaseAnalyzer
from anaya.engine.compliance.analyzers.breach_notification import BreachNotificationAnalyzer
from anaya.engine.compliance.analyzers.children_data import ChildrenDataAnalyzer
from anaya.engine.compliance.analyzers.consent import ConsentAnalyzer
from anaya.engine.compliance.analyzers.data_localisation import DataLocalisationAnalyzer
from anaya.engine.compliance.analyzers.data_minimisation import DataMinimisationAnalyzer
from anaya.engine.compliance.analyzers.data_retention import DataRetentionAnalyzer
from anaya.engine.compliance.analyzers.encryption import EncryptionAnalyzer
from anaya.engine.compliance.analyzers.erasure import ErasureAnalyzer
from anaya.engine.compliance.analyzers.runner import DPDPComplianceRunner

__all__ = [
    "SectionResult",
    "BaseAnalyzer",
    "BreachNotificationAnalyzer",
    "ChildrenDataAnalyzer",
    "ConsentAnalyzer",
    "DataLocalisationAnalyzer",
    "DataMinimisationAnalyzer",
    "DataRetentionAnalyzer",
    "EncryptionAnalyzer",
    "ErasureAnalyzer",
    "DPDPComplianceRunner",
]
