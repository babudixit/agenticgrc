"""UnifiedControl — a single control/safeguard from any framework catalog.

Modeled after the OSCAL catalog structure (NIST SP 800-53 Rev 5, NIST CSF
2.0) and CIS Controls v8, per spec §6.1 and the `(:Control {framework: ...})`
node shape from §9. Cross-framework relationships (e.g. a CIS safeguard
mapping to an 800-53 control) are represented as `MAPS_TO` graph edges
(FR-404), not duplicated here — `related_controls` is only for same-framework
relationships (OSCAL's own "related controls").

Field notes:
- `parameters` and `baselines` are intentionally light-weight (label lists,
  not fully resolved objects) because Deliverable 3 ingests the OSCAL
  *catalog* only, not a resolved baseline *profile* — baseline membership
  isn't derivable from the catalog alone and may be refined once a profile
  resource is cross-referenced.
"""

from __future__ import annotations

from pydantic import Field

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.enums import Framework


class UnifiedControl(UnifiedRecordBase):
    """A single control or safeguard from a compliance framework catalog."""

    control_id: str = Field(description="Framework-native control identifier, e.g. 'SI-2'.")
    framework: Framework
    version: str = Field(description="Framework revision, e.g. '5' for SP 800-53 Rev 5.")
    title: str
    statement: str = Field(description="The control's descriptive/normative text.")
    control_family: str | None = Field(
        default=None, description="Control family/class code, e.g. 'SI' (System Integrity)."
    )
    parent_control_id: str | None = Field(
        default=None,
        description="Base control ID if this record is an enhancement, e.g. 'AC-2' for 'AC-2(1)'.",
    )
    related_controls: list[str] = Field(
        default_factory=list,
        description="Other control IDs within the SAME framework this control relates to.",
    )
    parameters: list[str] = Field(
        default_factory=list,
        description="Parameter labels/IDs referenced by the control statement (OSCAL params).",
    )
    baselines: list[str] = Field(
        default_factory=list,
        description="Baseline impact levels this control belongs to (low/moderate/high), "
        "if known.",
    )
