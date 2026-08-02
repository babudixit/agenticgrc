"""UnifiedFinding — the contract every vendor normalizer emits (FR-204/FR-205).

Field set and shape are taken directly from FR-205 and the worked example in
spec §9 (Step 2), including preserving the vendor's own severity rating
alongside the normalized one (FR-208) and the source class the finding came
from (FR-201/202/203) so downstream cross-source deduplication (FR-207) and
reasoning can distinguish a scanner finding from a SIEM alert.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.enums import Severity, SourceClass
from grc_agent.schemas.validators import (
    normalize_attack_technique_id,
    normalize_cpe,
    normalize_cve_id,
    normalize_cwe_id,
    validate_id_list,
)


class UnifiedFinding(UnifiedRecordBase):
    """A single normalized finding from a scanner, CSPM tool, or SIEM."""

    finding_id: str = Field(
        description="Globally unique finding ID, conventionally "
        "'<source>:<source_finding_id>:<asset>', e.g. 'tenable:144982:prod-web-01'."
    )
    source_system: str = Field(description="Reporting system name, e.g. 'Tenable.io'.")
    source_class: SourceClass
    source_finding_id: str = Field(description="The vendor's own identifier for this finding.")
    timestamp: datetime = Field(description="When the source system detected/reported this.")
    severity: Severity = Field(description="Normalized Critical/High/Medium/Low/Informational.")
    vendor_severity: str = Field(
        description="The vendor's own severity rating, preserved verbatim (FR-208)."
    )
    title: str
    description: str
    affected_assets: list[str] = Field(
        default_factory=list, description="Asset identifiers (hostname, IP, ARN, ...)."
    )
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs, when the source provides them directly (FR-305). "
        "Scanner findings typically don't; those get technique inference during mapping.",
    )
    recommended_remediation: str | None = None

    @field_validator("cves")
    @classmethod
    def _validate_cves(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_cve_id)

    @field_validator("cwes")
    @classmethod
    def _validate_cwes(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_cwe_id)

    @field_validator("cpes")
    @classmethod
    def _validate_cpes(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_cpe)

    @field_validator("mitre_techniques")
    @classmethod
    def _validate_mitre_techniques(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_attack_technique_id)
