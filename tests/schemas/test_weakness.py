from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import UnifiedWeakness


def test_valid_weakness_constructs(weakness_data: dict[str, Any]) -> None:
    weakness = UnifiedWeakness(**weakness_data)

    assert weakness.weakness_id == "CWE-79"
    assert weakness.abstraction == "Base"
    assert weakness.related_weakness_ids == ["CWE-74"]


def test_weakness_id_is_normalized(weakness_data: dict[str, Any]) -> None:
    weakness_data["weakness_id"] = "cwe-79"
    weakness = UnifiedWeakness(**weakness_data)
    assert weakness.weakness_id == "CWE-79"


def test_invalid_weakness_id_raises(weakness_data: dict[str, Any]) -> None:
    weakness_data["weakness_id"] = "not-a-cwe"
    with pytest.raises(ValidationError, match="Invalid CWE identifier"):
        UnifiedWeakness(**weakness_data)


def test_related_weakness_ids_deduplicated_and_normalized(weakness_data: dict[str, Any]) -> None:
    weakness_data["related_weakness_ids"] = ["cwe-74", "CWE-74", "cwe-20"]
    weakness = UnifiedWeakness(**weakness_data)
    assert weakness.related_weakness_ids == ["CWE-74", "CWE-20"]


def test_extra_field_forbidden(weakness_data: dict[str, Any]) -> None:
    weakness_data["tenant_id"] = "acme-corp"
    with pytest.raises(ValidationError, match="tenant_id"):
        UnifiedWeakness(**weakness_data)


def test_defaults_for_optional_fields(weakness_data: dict[str, Any]) -> None:
    del weakness_data["extended_description"]
    del weakness_data["abstraction"]
    del weakness_data["status"]
    del weakness_data["related_weakness_ids"]
    weakness = UnifiedWeakness(**weakness_data)

    assert weakness.extended_description is None
    assert weakness.abstraction is None
    assert weakness.status is None
    assert weakness.related_weakness_ids == []


def test_json_roundtrip(weakness_data: dict[str, Any]) -> None:
    original = UnifiedWeakness(**weakness_data)

    restored = UnifiedWeakness.model_validate_json(original.model_dump_json())

    assert restored == original
