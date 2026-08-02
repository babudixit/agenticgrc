"""UnifiedAttackTechnique — a single MITRE ATT&CK (sub-)technique.

Modeled after the ATT&CK STIX 2.1 Enterprise bundle's `attack-pattern`
objects. Added alongside `UnifiedWeakness` as part of the Deliverable 5
reference-data expansion to complete the CVE->CWE->ATT&CK->Controls graph
traversal chain — not part of the original §4.2/§7.2 schema list.

Only techniques, sub-techniques, and their parent tactics are in scope for
Phase 1 (per user decision); mitigations, groups, software, and campaigns
are deliberately out of scope.
"""

from __future__ import annotations

from pydantic import Field, field_validator

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.validators import normalize_attack_technique_id, validate_id_list


class UnifiedAttackTechnique(UnifiedRecordBase):
    """A single MITRE ATT&CK technique or sub-technique."""

    technique_id: str = Field(description="ATT&CK technique ID, e.g. 'T1059' or 'T1059.001'.")
    name: str
    description: str
    tactics: list[str] = Field(
        default_factory=list,
        description="Tactic short names (kill-chain phases) this technique belongs to, "
        "e.g. 'credential-access'.",
    )
    is_subtechnique: bool = Field(
        default=False, description="True if this ID has a '.NNN' suffix, e.g. 'T1059.001'."
    )
    parent_technique_id: str | None = Field(
        default=None, description="Base technique ID if this is a sub-technique, e.g. 'T1059'."
    )
    platforms: list[str] = Field(
        default_factory=list, description="Platforms this technique applies to, e.g. 'Windows'."
    )

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, v: str) -> str:
        return normalize_attack_technique_id(v)

    @field_validator("tactics")
    @classmethod
    def _validate_tactics(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, lambda s: s.strip().lower())

    @field_validator("parent_technique_id")
    @classmethod
    def _validate_parent_technique_id(cls, v: str | None) -> str | None:
        return normalize_attack_technique_id(v) if v is not None else None
