"""Canonical, bounded vocabularies shared across Unified* schemas.

These are deliberately kept small and spec-driven (§3.1, §4.4, §6.1). Anything
open-ended — vendor names, source system names, asset owners — stays a plain
`str` field on the models instead of an enum, so adding a new vendor never
requires touching the schema layer (NFR-02).
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Canonical severity scale every vendor severity is normalized to (FR-205)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @property
    def rank(self) -> int:
        """Higher is more severe; useful for sorting and escalation comparisons."""
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Framework(StrEnum):
    """Compliance framework catalogs in scope for Phase 1 (spec §6.1).

    Values match the exact `framework` property spec §9's worked example uses
    on `(:Control)` nodes (e.g. `framework: 'NIST_SP_800-53_r5'`), so they can
    be used directly as Neo4j property values without translation.
    """

    NIST_SP_800_53_R5 = "NIST_SP_800-53_r5"
    NIST_CSF_2_0 = "NIST_CSF_2.0"
    CIS_V8 = "CIS_v8"
    NIST_SP_800_171_R3 = "NIST_SP_800-171_r3"


class SourceClass(StrEnum):
    """The three customer input categories in scope for Phase 1 (FR-201/202/203)."""

    VULNERABILITY_SCANNER = "vulnerability_scanner"
    CSPM = "cspm"
    SIEM = "siem"


class AssetType(StrEnum):
    """Broad asset categories (spec §6.6: hosts, cloud resources, containers, ...)."""

    HOST = "host"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    NETWORK_DEVICE = "network_device"
    OTHER = "other"


class AssetCriticality(StrEnum):
    """Business criticality of an asset — drives severity escalation (FR-606)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


class CloudProvider(StrEnum):
    """Cloud provider an asset or CSPM finding belongs to, when applicable."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREM = "on_prem"
    OTHER = "other"
