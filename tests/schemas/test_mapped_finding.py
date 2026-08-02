from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from grc_agent.schemas import Framework, MappedFinding, MatchMethod


def test_valid_mapped_finding_constructs(mapped_finding_data: dict[str, Any]) -> None:
    mapped = MappedFinding(**mapped_finding_data)

    assert mapped.finding_id == "tenable:144982:prod-web-01"
    assert mapped.matched_cves == ["CVE-2021-3156"]
    assert mapped.matched_weaknesses == ["CWE-193", "CWE-787"]
    assert len(mapped.matched_techniques) == 1
    assert mapped.matched_techniques[0].technique_id == "T1068"
    assert mapped.matched_techniques[0].match_method is MatchMethod.SEMANTIC_SEARCH
    assert len(mapped.matched_controls) == 1
    assert mapped.matched_controls[0].control_id == "SI-2"
    assert mapped.matched_controls[0].framework is Framework.NIST_SP_800_53_R5
    assert mapped.overall_confidence == pytest.approx(0.72)


def test_no_raw_source_field(mapped_finding_data: dict[str, Any]) -> None:
    """Unlike Unified* records, MappedFinding is synthesized output, not an ingested
    record, and has no raw_source to preserve."""
    mapped = MappedFinding(**mapped_finding_data)
    assert not hasattr(mapped, "raw_source")


def test_extra_field_forbidden(mapped_finding_data: dict[str, Any]) -> None:
    mapped_finding_data["tenant_id"] = "acme-corp"
    with pytest.raises(ValidationError, match="tenant_id"):
        MappedFinding(**mapped_finding_data)


def test_confidence_out_of_range_rejected(mapped_finding_data: dict[str, Any]) -> None:
    mapped_finding_data["overall_confidence"] = 1.5
    with pytest.raises(ValidationError):
        MappedFinding(**mapped_finding_data)


def test_technique_confidence_out_of_range_rejected(mapped_finding_data: dict[str, Any]) -> None:
    mapped_finding_data["matched_techniques"][0]["confidence"] = -0.1
    with pytest.raises(ValidationError):
        MappedFinding(**mapped_finding_data)


def test_empty_matches_default_to_empty_lists() -> None:
    mapped = MappedFinding(
        finding_id="tenable:1:host",
        agent_run_id="run-0002",
        model_used="claude-sonnet-4-5",
        reasoning="No CVEs, CWEs, or techniques could be matched from this finding.",
        overall_confidence=0.0,
    )
    assert mapped.matched_cves == []
    assert mapped.matched_weaknesses == []
    assert mapped.matched_techniques == []
    assert mapped.matched_controls == []


def test_json_roundtrip(mapped_finding_data: dict[str, Any]) -> None:
    original = MappedFinding(**mapped_finding_data)

    restored = MappedFinding.model_validate_json(original.model_dump_json())

    assert restored == original
