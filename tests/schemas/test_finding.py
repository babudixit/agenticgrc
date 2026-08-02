from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import Severity, SourceClass, UnifiedFinding


def test_valid_finding_matches_worked_example(finding_data: dict[str, Any]) -> None:
    finding = UnifiedFinding(**finding_data)

    assert finding.finding_id == "tenable:144982:prod-web-01"
    assert finding.source_class is SourceClass.VULNERABILITY_SCANNER
    assert finding.severity is Severity.HIGH
    assert finding.vendor_severity == "high"  # preserved verbatim, per FR-208
    assert finding.cves == ["CVE-2021-3156"]
    assert finding.mitre_techniques == []


def test_invalid_severity_value_raises(finding_data: dict[str, Any]) -> None:
    finding_data["severity"] = "Extremely High"
    with pytest.raises(ValidationError):
        UnifiedFinding(**finding_data)


def test_invalid_mitre_technique_raises(finding_data: dict[str, Any]) -> None:
    finding_data["mitre_techniques"] = ["TA0004"]  # a tactic ID, not a technique ID
    with pytest.raises(ValidationError, match="Invalid ATT&CK technique identifier"):
        UnifiedFinding(**finding_data)


def test_valid_mitre_technique_is_normalized(finding_data: dict[str, Any]) -> None:
    finding_data["mitre_techniques"] = ["t1068", "T1068.001"]
    finding = UnifiedFinding(**finding_data)
    assert finding.mitre_techniques == ["T1068", "T1068.001"]


def test_raw_source_is_required(finding_data: dict[str, Any]) -> None:
    del finding_data["raw_source"]
    with pytest.raises(ValidationError, match="raw_source"):
        UnifiedFinding(**finding_data)


def test_extra_field_forbidden(finding_data: dict[str, Any]) -> None:
    finding_data["plugin_id"] = 144982  # a vendor-specific field that must not leak through
    with pytest.raises(ValidationError, match="plugin_id"):
        UnifiedFinding(**finding_data)


def test_json_roundtrip(finding_data: dict[str, Any]) -> None:
    original = UnifiedFinding(**finding_data)

    restored = UnifiedFinding.model_validate_json(original.model_dump_json())

    assert restored == original


def test_jsonlines_roundtrip_multiple_findings(finding_data: dict[str, Any], tmp_path: Any) -> None:
    """Exercises the actual production interchange format: one JSON object per line."""
    second = dict(finding_data)
    second["finding_id"] = "tenable:144982:prod-db-02"
    second["affected_assets"] = ["prod-db-02"]

    findings = [UnifiedFinding(**finding_data), UnifiedFinding(**second)]
    jsonl_path = tmp_path / "findings.jsonl"

    with jsonl_path.open("w", encoding="utf-8") as f:
        for finding in findings:
            f.write(finding.model_dump_json() + "\n")

    with jsonl_path.open("r", encoding="utf-8") as f:
        restored = [UnifiedFinding.model_validate_json(line) for line in f if line.strip()]

    assert restored == findings
