from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import UnifiedAttackTechnique


def test_valid_technique_constructs(attack_technique_data: dict[str, Any]) -> None:
    technique = UnifiedAttackTechnique(**attack_technique_data)

    assert technique.technique_id == "T1055.011"
    assert technique.is_subtechnique is True
    assert technique.parent_technique_id == "T1055"
    assert technique.tactics == ["defense-evasion", "privilege-escalation"]


def test_technique_id_is_normalized(attack_technique_data: dict[str, Any]) -> None:
    attack_technique_data["technique_id"] = "t1055.011"
    technique = UnifiedAttackTechnique(**attack_technique_data)
    assert technique.technique_id == "T1055.011"


def test_invalid_technique_id_raises(attack_technique_data: dict[str, Any]) -> None:
    attack_technique_data["technique_id"] = "not-a-technique"
    with pytest.raises(ValidationError, match="Invalid ATT&CK technique identifier"):
        UnifiedAttackTechnique(**attack_technique_data)


def test_tactics_are_lowercased_and_deduplicated(attack_technique_data: dict[str, Any]) -> None:
    attack_technique_data["tactics"] = ["Defense-Evasion", "defense-evasion", "Persistence"]
    technique = UnifiedAttackTechnique(**attack_technique_data)
    assert technique.tactics == ["defense-evasion", "persistence"]


def test_top_level_technique_has_no_parent(attack_technique_data: dict[str, Any]) -> None:
    attack_technique_data["technique_id"] = "T1055"
    attack_technique_data["is_subtechnique"] = False
    del attack_technique_data["parent_technique_id"]
    technique = UnifiedAttackTechnique(**attack_technique_data)

    assert technique.is_subtechnique is False
    assert technique.parent_technique_id is None


def test_extra_field_forbidden(attack_technique_data: dict[str, Any]) -> None:
    attack_technique_data["tenant_id"] = "acme-corp"
    with pytest.raises(ValidationError, match="tenant_id"):
        UnifiedAttackTechnique(**attack_technique_data)


def test_json_roundtrip(attack_technique_data: dict[str, Any]) -> None:
    original = UnifiedAttackTechnique(**attack_technique_data)

    restored = UnifiedAttackTechnique.model_validate_json(original.model_dump_json())

    assert restored == original
