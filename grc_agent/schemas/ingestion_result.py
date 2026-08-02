"""IngestionResult — the run summary every ingester/normalizer produces.

`run_id` is the provenance token threaded through `UnifiedRecordBase.ingester_run_id`
(FR-408) so any node or edge in the graph can be traced back to the exact
ingestion run that created it, months later (NFR-01 auditability), even after
the underlying reference data has since been refreshed.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field

from grc_agent.schemas.base import utc_now


class IngestionResult(BaseModel):
    """Summary of a single ingester/normalizer/loader run."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    source_name: str = Field(description="Name of the ingester/normalizer, e.g. 'nist_sp800_53'.")
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    records_processed: int = Field(default=0, ge=0)
    records_written: int = Field(default=0, ge=0)
    records_failed: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)
    output_path: str | None = Field(
        default=None, description="Path to the JSON-Lines file this run wrote, if any."
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success(self) -> bool:
        """A run is successful once it has finished with zero failed records."""
        return self.completed_at is not None and self.records_failed == 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    def record_success(self, count: int = 1) -> None:
        """Increment both processed and written counters for `count` clean records."""
        self.records_processed += count
        self.records_written += count

    def record_error(self, message: str) -> None:
        """Record a failed record and its error message."""
        self.records_processed += 1
        self.records_failed += 1
        self.errors.append(message)

    def finish(self) -> None:
        """Mark the run complete. Idempotent-ish: safe to call once at the end of a run."""
        self.completed_at = utc_now()
