"""SourceSystem — metadata about a customer's scanner/CSPM/SIEM instance.

Backs the `(:SourceSystem)` graph node type (FR-402) and the "REPORTED_BY"
edge from findings to the system that reported them (FR-403). Also carries
the incremental-ingestion bookkeeping required by FR-209 (tracking the
timestamp of the last successful pull per source).

Unlike the Unified* record schemas, `SourceSystem` doesn't wrap a normalized
third-party payload — it's first-party configuration/state describing a
source, so it doesn't inherit `UnifiedRecordBase`.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from grc_agent.schemas.enums import SourceClass


class SourceSystem(BaseModel):
    """A configured scanner, CSPM tool, or SIEM instance findings are pulled from."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str = Field(description="Canonical system name, e.g. 'Tenable.io'.")
    source_class: SourceClass
    vendor: str = Field(description="The product vendor, e.g. 'Tenable'.")
    description: str | None = None
    api_base_url: str | None = None
    is_active: bool = True
    last_successful_pull_at: datetime | None = Field(
        default=None, description="Timestamp of the last successful pull (FR-209)."
    )
    last_successful_run_id: str | None = Field(
        default=None, description="IngestionResult.run_id of the last successful pull."
    )
