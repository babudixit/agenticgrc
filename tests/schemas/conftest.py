"""Shared fixture data for schema tests.

Fixtures return plain dicts (not model instances) so each test can construct
a model from a known-good baseline and mutate individual fields to exercise
validation failures.
"""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture
def control_data() -> dict[str, Any]:
    return {
        "control_id": "SI-2",
        "framework": "NIST_SP_800-53_r5",
        "version": "5",
        "title": "Flaw Remediation",
        "statement": "The organization identifies, reports, and corrects information "
        "system flaws.",
        "control_family": "SI",
        "related_controls": ["SI-3", "RA-5"],
        "parameters": ["si-2_prm_1"],
        "baselines": ["low", "moderate", "high"],
        "raw_source": {"id": "si-2", "class": "SP800-53"},
    }


@pytest.fixture
def vulnerability_data() -> dict[str, Any]:
    return {
        "cve_id": "CVE-2021-3156",
        "description": "Heap-based buffer overflow in Sudo before 1.9.5p2 (Baron Samedit).",
        "cvss_v3_score": 7.8,
        "cvss_v3_severity": "High",
        "cwes": ["CWE-193", "CWE-787"],
        "cpes": ["cpe:2.3:a:openbsd:openssh:8.2"],
        "published_date": "2021-01-26T00:00:00Z",
        "in_kev": True,
        "epss_score": 0.89,
        "raw_source": {"id": "CVE-2021-3156", "source": "NVD"},
    }


@pytest.fixture
def asset_data() -> dict[str, Any]:
    return {
        "asset_id": "prod-web-01",
        "hostname": "prod-web-01",
        "fqdn": "prod-web-01.example.com",
        "ip_addresses": ["10.0.4.55"],
        "operating_system": "Ubuntu 20.04",
        "asset_type": "host",
        "criticality": "High",
        "environment": "production",
        "source_system": "AWS Config",
        "raw_source": {"fqdn": "prod-web-01.example.com"},
    }


@pytest.fixture
def finding_data() -> dict[str, Any]:
    """Directly mirrors the worked example in spec §9, Step 2."""
    return {
        "finding_id": "tenable:144982:prod-web-01",
        "source_system": "Tenable.io",
        "source_class": "vulnerability_scanner",
        "source_finding_id": "144982",
        "timestamp": "2024-05-18T02:11:00Z",
        "severity": "High",
        "vendor_severity": "high",
        "title": "OpenSSH 8.2 < 8.5 Multiple Vulnerabilities",
        "description": "OpenSSH version 8.2 is installed on the remote host...",
        "affected_assets": ["prod-web-01"],
        "cves": ["CVE-2021-3156"],
        "cwes": [],
        "cpes": ["cpe:2.3:a:openbsd:openssh:8.2"],
        "mitre_techniques": [],
        "recommended_remediation": "Upgrade to OpenSSH 8.5 or later.",
        "raw_source": {
            "plugin": {"id": 144982, "cve": ["CVE-2021-3156"]},
            "asset": {"fqdn": "prod-web-01.example.com"},
        },
    }


@pytest.fixture
def source_system_data() -> dict[str, Any]:
    return {
        "name": "Tenable.io",
        "source_class": "vulnerability_scanner",
        "vendor": "Tenable",
        "api_base_url": "https://cloud.tenable.com",
    }


@pytest.fixture
def weakness_data() -> dict[str, Any]:
    return {
        "weakness_id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation "
        "('Cross-site Scripting')",
        "description": "The product does not neutralize or incorrectly neutralizes "
        "user-controllable input before it is placed in output that is used as a web "
        "page.",
        "extended_description": "There are many variants of cross-site scripting.",
        "abstraction": "Base",
        "status": "Stable",
        "related_weakness_ids": ["CWE-74"],
        "raw_source": {"ID": "79", "Name": "Cross-site Scripting"},
    }


@pytest.fixture
def attack_technique_data() -> dict[str, Any]:
    return {
        "technique_id": "T1055.011",
        "name": "Extra Window Memory Injection",
        "description": "Adversaries may inject malicious code into process via Extra "
        "Window Memory (EWM).",
        "tactics": ["defense-evasion", "privilege-escalation"],
        "is_subtechnique": True,
        "parent_technique_id": "T1055",
        "platforms": ["Windows"],
        "raw_source": {"id": "attack-pattern--0042a9f5", "name": "Extra Window Memory Injection"},
    }


@pytest.fixture
def attack_control_mapping_data() -> dict[str, Any]:
    return {
        "technique_id": "T1556.009",
        "control_id": "AC-2",
        "control_framework": "NIST_SP_800-53_r5",
        "mapping_type": "mitigates",
        "comments": "Account Management supports monitoring for unusual activity.",
        "raw_source": {"attack_object_id": "T1556.009", "capability_id": "AC-02"},
    }


@pytest.fixture
def control_control_mapping_data() -> dict[str, Any]:
    return {
        "source_control_id": "GV.OC-01",
        "source_framework": "NIST_CSF_2.0",
        "target_control_id": "PM-11",
        "target_framework": "NIST_SP_800-53_r5",
        "mapping_type": "related",
        "confidence": None,
        "comments": "CSF Informative Reference to SP 800-53 Rev 5.",
        "raw_source": {"subcategory": "GV.OC-01", "control": "PM-11"},
    }


@pytest.fixture
def mapped_finding_data() -> dict[str, Any]:
    return {
        "finding_id": "tenable:144982:prod-web-01",
        "agent_run_id": "run-0001",
        "mapped_at": "2024-05-18T02:15:00Z",
        "model_used": "claude-sonnet-4-5",
        "matched_cves": ["CVE-2021-3156"],
        "matched_weaknesses": ["CWE-193", "CWE-787"],
        "matched_techniques": [
            {
                "technique_id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "match_method": "semantic_search",
                "confidence": 0.72,
                "rationale": "CWE-787 (out-of-bounds write) semantically matches T1068's "
                "description of exploiting memory-corruption flaws.",
            }
        ],
        "matched_controls": [
            {
                "control_id": "SI-2",
                "framework": "NIST_SP_800-53_r5",
                "title": "Flaw Remediation",
                "via_technique_ids": ["T1068"],
                "confidence": 0.72,
            }
        ],
        "reasoning": "CVE-2021-3156 (sudo heap overflow) maps to CWE-787, which has no direct "
        "graph edge to an ATT&CK technique; semantic search over technique descriptions "
        "surfaced T1068 as the closest match, which is mitigated by SI-2.",
        "overall_confidence": 0.72,
    }
