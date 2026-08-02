"""Shared base model for every Unified* record.

Encodes two non-negotiable architectural rules from the spec directly into
the type system:

- FR-113: every normalized record preserves its raw source payload for audit
  traceability (`raw_source`).
- FR-408: every record carries the ingester run ID that produced it, for
  provenance tracking once loaded into the graph.

`extra="forbid"` enforces the "no vendor-specific field leakage" rule
(§7.2): a normalizer that accidentally passes through an un-mapped
vendor field fails validation immediately, at the normalizer boundary,
instead of silently leaking into the graph.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class UnifiedRecordBase(BaseModel):
    """Common fields for every schema that wraps a normalized third-party record."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    raw_source: dict[str, Any] = Field(
        description="The original, unmodified source payload — preserved verbatim for audit "
        "traceability (FR-113). Never parsed or relied upon downstream of the normalizer."
    )
    ingested_at: datetime = Field(
        default_factory=utc_now,
        description="When this record was normalized into the Unified* schema.",
    )
    ingester_run_id: str | None = Field(
        default=None,
        description="The IngestionResult.run_id of the ingester/normalizer run that produced "
        "this record (FR-408 provenance).",
    )
