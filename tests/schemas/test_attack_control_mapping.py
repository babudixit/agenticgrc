from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import AttackControlMapping, Framework


def test_valid_mapping_constructs(attack_control_mapping_data: dict[str, Any]) -> None:
    mapping = AttackControlMapping(**attack_control_mapping_data)

    assert mapping.technique_id == "T1556.009"
    assert mapping.control_id == "AC-2"
    assert mapping.control_framework is Framework.NIST_SP_800_53_R5
    assert mapping.mapping_type == "mitigates"


def test_technique_id_is_normalized(attack_control_mapping_data: dict[str, Any]) -> None:
    attack_control_mapping_data["technique_id"] = "t1556.009"
    mapping = AttackControlMapping(**attack_control_mapping_data)
    assert mapping.technique_id == "T1556.009"


def test_invalid_technique_id_raises(attack_control_mapping_data: dict[str, Any]) -> None:
    attack_control_mapping_data["technique_id"] = "not-a-technique"
    with pytest.raises(ValidationError, match="Invalid ATT&CK technique identifier"):
        AttackControlMapping(**attack_control_mapping_data)


def test_comments_default_to_none(attack_control_mapping_data: dict[str, Any]) -> None:
    del attack_control_mapping_data["comments"]
    mapping = AttackControlMapping(**attack_control_mapping_data)
    assert mapping.comments is None


def test_extra_field_forbidden(attack_control_mapping_data: dict[str, Any]) -> None:
    attack_control_mapping_data["tenant_id"] = "acme-corp"
    with pytest.raises(ValidationError, match="tenant_id"):
        AttackControlMapping(**attack_control_mapping_data)


def test_json_roundtrip(attack_control_mapping_data: dict[str, Any]) -> None:
    original = AttackControlMapping(**attack_control_mapping_data)

    restored = AttackControlMapping.model_validate_json(original.model_dump_json())

    assert restored == original
