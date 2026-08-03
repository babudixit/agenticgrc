from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import ControlControlMapping, Framework


def test_valid_mapping_constructs(control_control_mapping_data: dict[str, Any]) -> None:
    mapping = ControlControlMapping(**control_control_mapping_data)

    assert mapping.source_control_id == "GV.OC-01"
    assert mapping.source_framework is Framework.NIST_CSF_2_0
    assert mapping.target_control_id == "PM-11"
    assert mapping.target_framework is Framework.NIST_SP_800_53_R5
    assert mapping.mapping_type == "related"
    assert mapping.confidence is None


def test_mapping_type_defaults_to_related(control_control_mapping_data: dict[str, Any]) -> None:
    del control_control_mapping_data["mapping_type"]
    mapping = ControlControlMapping(**control_control_mapping_data)
    assert mapping.mapping_type == "related"


def test_confidence_out_of_range_raises(control_control_mapping_data: dict[str, Any]) -> None:
    control_control_mapping_data["confidence"] = 1.5
    with pytest.raises(ValidationError):
        ControlControlMapping(**control_control_mapping_data)


def test_confidence_accepts_valid_score(control_control_mapping_data: dict[str, Any]) -> None:
    control_control_mapping_data["confidence"] = 0.92
    mapping = ControlControlMapping(**control_control_mapping_data)
    assert mapping.confidence == 0.92


def test_comments_default_to_none(control_control_mapping_data: dict[str, Any]) -> None:
    del control_control_mapping_data["comments"]
    mapping = ControlControlMapping(**control_control_mapping_data)
    assert mapping.comments is None


def test_extra_field_forbidden(control_control_mapping_data: dict[str, Any]) -> None:
    control_control_mapping_data["tenant_id"] = "acme-corp"
    with pytest.raises(ValidationError, match="tenant_id"):
        ControlControlMapping(**control_control_mapping_data)


def test_json_roundtrip(control_control_mapping_data: dict[str, Any]) -> None:
    original = ControlControlMapping(**control_control_mapping_data)
    restored = ControlControlMapping.model_validate_json(original.model_dump_json())
    assert restored == original
