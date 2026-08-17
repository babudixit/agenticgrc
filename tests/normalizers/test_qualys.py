"""Tests for the Qualys VM detection normalizer."""

from __future__ import annotations

from pathlib import Path

from grc_agent.normalizers.qualys import normalize_finding, read_export, run
from grc_agent.schemas import Severity, SourceClass, UnifiedFinding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "qualys_detections.json"


def test_read_and_normalize_fixture() -> None:
    raw = read_export(FIXTURE_PATH)
    assert len(raw) == 3
    findings = [normalize_finding(r, ingester_run_id="q-run") for r in raw]

    heartbleed = findings[0]
    assert heartbleed.finding_id == "qualys:38173:prod-web-01.example.com"
    assert heartbleed.source_class is SourceClass.VULNERABILITY_SCANNER
    assert heartbleed.severity is Severity.CRITICAL
    assert heartbleed.vendor_severity == "5"
    assert heartbleed.cves == ["CVE-2014-0160"]
    assert heartbleed.recommended_remediation is not None

    ssh = findings[1]
    assert ssh.severity is Severity.MEDIUM
    assert ssh.cves == []
    assert ssh.affected_assets == ["corp-file-02"]

    log4j = findings[2]
    assert log4j.source_finding_id == "91342"
    assert log4j.cves == ["CVE-2021-44228", "CVE-2021-45046"]
    assert log4j.severity is Severity.CRITICAL


def test_run_writes_jsonlines(tmp_path: Path) -> None:
    out = tmp_path / "qualys.jsonl"
    result = run(FIXTURE_PATH, out)
    assert result.success is True
    assert result.records_written == 3
    restored = [
        UnifiedFinding.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert all(f.source_system == "Qualys VM" for f in restored)
