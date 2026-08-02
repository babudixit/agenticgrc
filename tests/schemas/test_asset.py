from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import AssetCriticality, AssetType, UnifiedAsset


def test_valid_asset_constructs(asset_data: dict[str, Any]) -> None:
    asset = UnifiedAsset(**asset_data)

    assert asset.asset_id == "prod-web-01"
    assert asset.asset_type is AssetType.HOST
    assert asset.criticality is AssetCriticality.HIGH
    assert asset.ip_addresses == ["10.0.4.55"]


def test_default_criticality_is_unknown(asset_data: dict[str, Any]) -> None:
    del asset_data["criticality"]
    asset = UnifiedAsset(**asset_data)
    assert asset.criticality is AssetCriticality.UNKNOWN


def test_invalid_ip_address_raises(asset_data: dict[str, Any]) -> None:
    asset_data["ip_addresses"] = ["999.999.999.999"]
    with pytest.raises(ValidationError, match="Invalid IP address"):
        UnifiedAsset(**asset_data)


def test_ip_addresses_are_deduplicated(asset_data: dict[str, Any]) -> None:
    asset_data["ip_addresses"] = ["10.0.4.55", "10.0.4.55"]
    asset = UnifiedAsset(**asset_data)
    assert asset.ip_addresses == ["10.0.4.55"]


def test_missing_required_source_system_raises(asset_data: dict[str, Any]) -> None:
    del asset_data["source_system"]
    with pytest.raises(ValidationError, match="source_system"):
        UnifiedAsset(**asset_data)


def test_json_roundtrip(asset_data: dict[str, Any]) -> None:
    original = UnifiedAsset(**asset_data)

    restored = UnifiedAsset.model_validate_json(original.model_dump_json())

    assert restored == original
