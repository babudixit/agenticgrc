"""UnifiedAsset — the scope of assessment (spec §6.6).

Assets typically come from a CMDB or cloud provider inventory and provide
criticality, ownership, and environment context that scanner/CSPM/SIEM
findings often lack on their own (used by FR-606 to escalate severity on
production-critical assets).
"""

from __future__ import annotations

from pydantic import Field, field_validator

from grc_agent.schemas.base import UnifiedRecordBase
from grc_agent.schemas.enums import AssetCriticality, AssetType, CloudProvider
from grc_agent.schemas.validators import normalize_ip_address, validate_id_list


class UnifiedAsset(UnifiedRecordBase):
    """A single asset (host, cloud resource, container, ...) in scope for assessment."""

    asset_id: str = Field(
        description="Canonical asset identifier used for graph lookups, e.g. hostname or ARN."
    )
    hostname: str | None = None
    fqdn: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    cloud_provider: CloudProvider | None = None
    cloud_resource_id: str | None = Field(
        default=None, description="Cloud resource ARN/ID, when applicable."
    )
    operating_system: str | None = None
    asset_type: AssetType = AssetType.OTHER
    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    environment: str | None = Field(
        default=None, description="Free-text deployment environment, e.g. 'production'."
    )
    owner: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    source_system: str = Field(
        description="The inventory source this asset record came from, e.g. 'AWS Config'."
    )

    @field_validator("ip_addresses")
    @classmethod
    def _validate_ip_addresses(cls, v: list[str]) -> list[str]:
        return validate_id_list(v, normalize_ip_address)
