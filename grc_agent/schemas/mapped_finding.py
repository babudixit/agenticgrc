"""MappedFinding — the mapping agent's (Deliverable 5) output.

Unlike every other schema in this package, `MappedFinding` isn't a
normalized *ingested* record (it has no `raw_source` to preserve verbatim —
it's synthesized by an LLM reasoning over already-ingested data), so it
doesn't inherit `UnifiedRecordBase`. It's still `extra="forbid"`, for the
same "no field leakage" discipline as everything else.

`MappedTechnique`/`MappedControl` carry a `match_method` and per-match
`confidence` (spec's worked example, §9 Step 4/5) rather than a single
finding-level confidence, because a single finding can legitimately produce
both high-confidence direct graph matches and lower-confidence semantic
fallback matches in the same run — collapsing that into one number would
hide exactly the distinction an auditor most needs to see.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from grc_agent.schemas.base import utc_now
from grc_agent.schemas.enums import Framework, MatchMethod


class MappedTechnique(BaseModel):
    """A single ATT&CK technique matched to the finding, with its provenance."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    name: str | None = None
    match_method: MatchMethod
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str | None = Field(
        default=None, description="Short justification, e.g. why a semantic match was chosen."
    )


class MappedControl(BaseModel):
    """A single control matched to the finding, with the technique(s) that led to it."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    framework: Framework
    title: str | None = None
    via_technique_ids: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique ID(s) whose MAPS_TO edge produced this control match.",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class MappedFinding(BaseModel):
    """The mapping agent's output for a single UnifiedFinding: candidate CVEs, CWEs,
    ATT&CK techniques, and controls, plus the LLM's overall reasoning and confidence.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(description="The UnifiedFinding.finding_id this maps.")
    agent_run_id: str = Field(description="Provenance: which agent run produced this mapping.")
    mapped_at: datetime = Field(default_factory=utc_now)
    model_used: str = Field(description="The Claude model that produced this mapping.")

    matched_cves: list[str] = Field(
        default_factory=list, description="CVE IDs carried by the finding and/or found in Neo4j."
    )
    matched_weaknesses: list[str] = Field(
        default_factory=list, description="CWE IDs reached via the finding's CVEs/CWEs."
    )
    matched_techniques: list[MappedTechnique] = Field(default_factory=list)
    matched_controls: list[MappedControl] = Field(default_factory=list)

    reasoning: str = Field(description="The LLM's narrative justification for this mapping.")
    overall_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="The LLM's holistic confidence in this mapping, distinct from the "
        "per-technique/per-control confidences above.",
    )
