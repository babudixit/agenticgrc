"""Tests for the generic CSPM finding normalizer."""

from __future__ import annotations

from pathlib import Path

from grc_agent.normalizers.cspm import normalize_finding, read_export, run
from grc_agent.schemas import Severity, SourceClass, UnifiedFinding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cspm_findings.json"


def test_read_and_normalize_fixture() -> None:
    raw = read_export(FIXTURE_PATH)
    assert len(raw) == 3
    findings = [normalize_finding(r) for r in raw]

    wiz = findings[0]
    assert wiz.source_class is SourceClass.CSPM
    assert wiz.source_system == "Wiz"
    assert wiz.severity is Severity.HIGH
    assert wiz.affected_assets == ["arn:aws:s3:::acme-public-assets"]
    assert "CIS AWS" in wiz.description

    security_hub = findings[1]
    assert security_hub.source_system == "Security Hub"
    assert security_hub.severity is Severity.MEDIUM
    assert security_hub.affected_assets == [
        "arn:aws:s3:::aws-cloudtrail-logs-111122223333"
    ]
    assert security_hub.recommended_remediation is not None

    prisma = findings[2]
    assert prisma.severity is Severity.CRITICAL
    assert prisma.mitre_techniques == ["T1078.004"]
    assert prisma.affected_assets == ["arn:aws:iam::111122223333:role/admin-breakglass"]


def test_run_writes_jsonlines(tmp_path: Path) -> None:
    out = tmp_path / "cspm.jsonl"
    result = run(FIXTURE_PATH, out)
    assert result.success is True
    assert result.records_written == 3
    restored = [
        UnifiedFinding.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert all(f.source_class is SourceClass.CSPM for f in restored)
