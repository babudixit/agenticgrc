"""Unified Pydantic schemas — the internal contract every ingester emits and
every downstream module consumes. Vendor-specific field names must never leak
past the normalizer boundary.
"""

from grc_agent.schemas.asset import UnifiedAsset
from grc_agent.schemas.attack_control_mapping import AttackControlMapping
from grc_agent.schemas.attack_technique import UnifiedAttackTechnique
from grc_agent.schemas.control import UnifiedControl
from grc_agent.schemas.enums import (
    AssetCriticality,
    AssetType,
    CloudProvider,
    Framework,
    Severity,
    SourceClass,
)
from grc_agent.schemas.finding import UnifiedFinding
from grc_agent.schemas.ingestion_result import IngestionResult
from grc_agent.schemas.source_system import SourceSystem
from grc_agent.schemas.vulnerability import UnifiedVulnerability
from grc_agent.schemas.weakness import UnifiedWeakness

__all__ = [
    "AssetCriticality",
    "AssetType",
    "AttackControlMapping",
    "CloudProvider",
    "Framework",
    "IngestionResult",
    "Severity",
    "SourceClass",
    "SourceSystem",
    "UnifiedAsset",
    "UnifiedAttackTechnique",
    "UnifiedControl",
    "UnifiedFinding",
    "UnifiedVulnerability",
    "UnifiedWeakness",
]
