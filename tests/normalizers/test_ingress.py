"""Tests for the multi-vendor ingress router."""

from __future__ import annotations

from pathlib import Path

import pytest

from grc_agent.normalizers.ingress import _run_cli, run
from grc_agent.schemas import SourceClass, UnifiedFinding

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("source", "fixture", "expected_class", "expected_count"),
    [
        ("tenable", "tenable_vulns_export.json", SourceClass.VULNERABILITY_SCANNER, 6),
        ("qualys", "qualys_detections.json", SourceClass.VULNERABILITY_SCANNER, 3),
        ("siem", "siem_alerts.json", SourceClass.SIEM, 3),
        ("cspm", "cspm_findings.json", SourceClass.CSPM, 3),
    ],
)
def test_ingress_routes_each_source(
    source: str,
    fixture: str,
    expected_class: SourceClass,
    expected_count: int,
    tmp_path: Path,
) -> None:
    out = tmp_path / f"{source}.jsonl"
    result = run(source, FIXTURES / fixture, out)
    assert result.success is True
    assert result.records_written == expected_count
    restored = [
        UnifiedFinding.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert all(f.source_class is expected_class for f in restored)


def test_ingress_rejects_unknown_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown source"):
        run("nessus", FIXTURES / "siem_alerts.json", tmp_path / "out.jsonl")


def test_cli_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out.jsonl"
    code = _run_cli(
        [
            "--source",
            "qualys",
            "--input",
            str(FIXTURES / "qualys_detections.json"),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert "Normalized 3 qualys records" in capsys.readouterr().out
