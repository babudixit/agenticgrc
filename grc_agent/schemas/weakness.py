"""UnifiedWeakness — a single CWE weakness-type record.

Modeled after the MITRE CWE XML catalog (spec's CVE->CWE->ATT&CK->Controls
traversal chain needs a `(:Weakness)` node type that wasn't enumerated in the
original §4.2/§7.2 schema list, since Deliverable 2 only covered the
Tenable-finding path). Added as part of the Deliverable 5 reference-data
expansion: a `UnifiedVulnerability.cwes` entry needs a graph node to resolve
against via a `MAPS_TO` edge.

`related_weakness_ids` intentionally only carries View-1000 (research view)
ChildOf/ParentOf/PeerOf/CanPrecede targets — CWE's own primary hierarchy —
not every relationship in every view, keeping the field small and traversable.
"""

from __future__ import annotations

from pydantic import Field, field_validator

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.validators import normalize_cwe_id, validate_id_list


class UnifiedWeakness(UnifiedRecordBase):
    """A single CWE weakness-type record from the MITRE CWE catalog."""

    weakness_id: str = Field(description="CWE identifier, e.g. 'CWE-79'.")
    name: str
    description: str
    extended_description: str | None = Field(
        default=None, description="Longer-form explanation beyond the one-line description."
    )
    abstraction: str | None = Field(
        default=None, description="CWE abstraction level, e.g. 'Base', 'Class', 'Variant'."
    )
    status: str | None = Field(
        default=None, description="CWE lifecycle status, e.g. 'Stable', 'Draft', 'Incomplete'."
    )
    related_weakness_ids: list[str] = Field(
        default_factory=list,
        description="CWE IDs this weakness is ChildOf/ParentOf/PeerOf/CanPrecede in View-1000.",
    )

    @field_validator("weakness_id")
    @classmethod
    def _validate_weakness_id(cls, v: str) -> str:
        return normalize_cwe_id(v)

    @field_validator("related_weakness_ids")
    @classmethod
    def _validate_related_weakness_ids(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_cwe_id)
