from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import Framework, UnifiedControl


def test_valid_control_constructs(control_data: dict[str, Any]) -> None:
    control = UnifiedControl(**control_data)

    assert control.control_id == "SI-2"
    assert control.framework is Framework.NIST_SP_800_53_R5
    assert control.related_controls == ["SI-3", "RA-5"]
    assert control.ingester_run_id is None


def test_missing_required_field_raises(control_data: dict[str, Any]) -> None:
    del control_data["statement"]
    with pytest.raises(ValidationError, match="statement"):
        UnifiedControl(**control_data)


def test_invalid_framework_raises(control_data: dict[str, Any]) -> None:
    control_data["framework"] = "NIST_SP_800-53_r4"  # not a supported Phase 1 framework
    with pytest.raises(ValidationError):
        UnifiedControl(**control_data)


def test_extra_field_forbidden(control_data: dict[str, Any]) -> None:
    control_data["tenant_id"] = "acme-corp"  # a made-up, un-mapped field
    with pytest.raises(ValidationError, match="tenant_id"):
        UnifiedControl(**control_data)


def test_defaults_for_optional_fields(control_data: dict[str, Any]) -> None:
    del control_data["related_controls"], control_data["parameters"], control_data["baselines"]
    control = UnifiedControl(**control_data)

    assert control.related_controls == []
    assert control.parameters == []
    assert control.baselines == []
    assert control.parent_control_id is None


def test_json_roundtrip(control_data: dict[str, Any]) -> None:
    original = UnifiedControl(**control_data)

    restored = UnifiedControl.model_validate_json(original.model_dump_json())

    assert restored == original


def test_dict_roundtrip(control_data: dict[str, Any]) -> None:
    original = UnifiedControl(**control_data)

    restored = UnifiedControl.model_validate(original.model_dump(mode="json"))

    assert restored == original
