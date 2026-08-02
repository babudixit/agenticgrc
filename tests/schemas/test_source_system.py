from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import SourceClass, SourceSystem


def test_valid_source_system_constructs(source_system_data: dict[str, Any]) -> None:
    system = SourceSystem(**source_system_data)

    assert system.name == "Tenable.io"
    assert system.source_class is SourceClass.VULNERABILITY_SCANNER
    assert system.is_active is True
    assert system.last_successful_pull_at is None


def test_extra_field_forbidden(source_system_data: dict[str, Any]) -> None:
    source_system_data["region"] = "us-east-1"
    with pytest.raises(ValidationError, match="region"):
        SourceSystem(**source_system_data)


def test_last_successful_pull_tracking(source_system_data: dict[str, Any]) -> None:
    system = SourceSystem(**source_system_data)
    system.last_successful_pull_at = "2024-05-18T02:11:00Z"  # type: ignore[assignment]
    system.last_successful_run_id = "abc-123"

    assert system.last_successful_pull_at is not None
    assert system.last_successful_run_id == "abc-123"


def test_json_roundtrip(source_system_data: dict[str, Any]) -> None:
    original = SourceSystem(**source_system_data)

    restored = SourceSystem.model_validate_json(original.model_dump_json())

    assert restored == original
