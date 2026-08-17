"""Tests for the generic SIEM alert normalizer."""

from __future__ import annotations

from pathlib import Path

from grc_agent.normalizers.siem import normalize_finding, read_export, run
from grc_agent.schemas import Severity, SourceClass, UnifiedFinding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "siem_alerts.json"


def test_read_and_normalize_fixture() -> None:
    raw = read_export(FIXTURE_PATH)
    assert len(raw) == 3
    findings = [normalize_finding(r) for r in raw]

    splunk = findings[0]
    assert splunk.source_class is SourceClass.SIEM
    assert splunk.source_system == "Splunk ES"
    assert splunk.severity is Severity.HIGH
    assert splunk.mitre_techniques == ["T1059.001", "T1027"]
    assert splunk.affected_assets == ["workstation-42"]
    assert "jdoe" in splunk.description

    elastic = findings[1]
    assert elastic.source_system == "Elastic SIEM"
    assert elastic.mitre_techniques == ["T1110.001"]
    assert elastic.severity is Severity.MEDIUM

    sentinel = findings[2]
    assert sentinel.severity is Severity.CRITICAL
    assert sentinel.cves == ["CVE-2023-44487"]
    assert sentinel.mitre_techniques == ["T1190"]


def test_run_writes_jsonlines(tmp_path: Path) -> None:
    out = tmp_path / "siem.jsonl"
    result = run(FIXTURE_PATH, out)
    assert result.success is True
    assert result.records_written == 3
    restored = [
        UnifiedFinding.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert all(f.source_class is SourceClass.SIEM for f in restored)
