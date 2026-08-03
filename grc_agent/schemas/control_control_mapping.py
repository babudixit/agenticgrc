"""ControlControlMapping — a single cross-framework control-to-control edge record.

Generalizes `AttackControlMapping`'s pattern (an edge contributed by a
third, independent data source, between two already-ingested `UnifiedControl`
nodes) to *framework-to-framework* crosswalks: NIST CSF 2.0's Informative
References to SP 800-53, SP 800-171 Rev 3's Appendix D source-control
mapping to SP 800-53, and (once available) the CIS Controls v8 mapping.

This is what "connects" a non-800-53 framework's controls into the same
graph neighborhood as the CVE->CWE->ATT&CK->Controls traversal chain: without
it, a `(:Control {framework: NIST_CSF_2.0})` node would be an island with no
path back to anything a finding could ever map to. Modeled as its own record
type (loaded as a `MAPS_TO` edge, same relationship type FR-404 already uses
for ATT&CK->Control) rather than a field on `UnifiedControl`, because it's
authored by a separate source dataset, not the framework catalog itself.
"""

from __future__ import annotations

from pydantic import Field

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.enums import Framework


class ControlControlMapping(UnifiedRecordBase):
    """A single 'this control in framework A is satisfied/covered by this
    control in framework B' edge, as asserted by some crosswalk dataset.
    """

    source_control_id: str = Field(description="Framework-native control ID, e.g. 'GV.OC-01'.")
    source_framework: Framework
    target_control_id: str = Field(description="Framework-native control ID, e.g. 'AC-2'.")
    target_framework: Framework
    mapping_type: str = Field(
        default="related",
        description="Relationship the source dataset assigns, e.g. 'related', 'satisfies'.",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Source dataset's confidence score for this mapping, if it provides one "
        "(NIST informative-reference crosswalks generally don't; third-party datasets like "
        "the CIS/CCI mapping do).",
    )
    comments: str | None = Field(
        default=None, description="Source dataset's justification/rationale for the mapping."
    )
