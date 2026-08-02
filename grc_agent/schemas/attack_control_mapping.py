"""AttackControlMapping — a single ATT&CK-technique-to-control edge record.

Sourced from the Center for Threat-Informed Defense (CTID) "Mappings
Explorer" dataset, which links ATT&CK techniques to the NIST SP 800-53 Rev 5
controls that mitigate them. Unlike the `Unified*` node schemas, this models
an *edge* between two already-ingested entities (an `UnifiedAttackTechnique`
and a `UnifiedControl`) contributed by a third, independent data source —
so it isn't a field on either entity, but its own small record type, loaded
as a `MAPS_TO` relationship (FR-404) by the graph loader.

This is what closes the CVE->CWE->ATT&CK->Controls traversal chain: without
it, technique nodes would have no edge back into the control graph at all
(per user decision, the CWE->ATT&CK hop itself is intentionally left to the
mapping agent's ChromaDB semantic-search fallback rather than CAPEC).
"""

from __future__ import annotations

from pydantic import Field, field_validator

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.enums import Framework
from grc_agent.schemas.validators import normalize_attack_technique_id


class AttackControlMapping(UnifiedRecordBase):
    """A single 'this ATT&CK technique is mitigated by this control' edge."""

    technique_id: str = Field(description="ATT&CK technique ID, e.g. 'T1059.001'.")
    control_id: str = Field(description="Framework-native control identifier, e.g. 'AC-2'.")
    control_framework: Framework
    mapping_type: str = Field(
        description="Relationship the source dataset assigns, e.g. 'mitigates'."
    )
    comments: str | None = Field(
        default=None, description="Source dataset's justification/rationale for the mapping."
    )

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, v: str) -> str:
        return normalize_attack_technique_id(v)
