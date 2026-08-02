"""Tests for the Tenable.io normalizer, using a real vulnerability export
(tests/normalizers/fixtures/tenable_vulns_export.json — 6 findings covering
single-CVE, multi-CVE, and zero-CVE/compliance-check patterns across
critical/high/medium severities) plus synthetic fixtures for edge cases the
real export doesn't happen to contain (informational severity, missing
fields, malformed data).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from grc_agent.normalizers.tenable import (
    _asset_identifier,
    _normalize_severity,
    _run_cli,
    normalize_finding,
    read_export,
    run,
)
from grc_agent.schemas import Severity, SourceClass, UnifiedFinding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "tenable_vulns_export.json"


@pytest.fixture
def raw_findings() -> list[dict[str, Any]]:
    return read_export(FIXTURE_PATH)


@pytest.fixture
def findings_by_plugin_id(raw_findings: list[dict[str, Any]]) -> dict[int, UnifiedFinding]:
    return {
        raw["plugin"]["id"]: normalize_finding(raw, ingester_run_id="test-run")
        for raw in raw_findings
    }


def test_read_export_parses_wrapped_findings_array(raw_findings: list[dict[str, Any]]) -> None:
    assert len(raw_findings) == 6


def test_read_export_also_accepts_bare_array(tmp_path: Path, raw_findings: list) -> None:
    bare_path = tmp_path / "bare.json"
    bare_path.write_text(json.dumps(raw_findings[:2]), encoding="utf-8")
    assert len(read_export(bare_path)) == 2


def test_read_export_rejects_unrecognized_shape(tmp_path: Path) -> None:
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"not_findings": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unrecognized Tenable export format"):
        read_export(bad_path)


# --- Real-data pattern coverage -------------------------------------------------


def test_baron_samedit_single_cve_high_severity(
    findings_by_plugin_id: dict[int, UnifiedFinding],
) -> None:
    f = findings_by_plugin_id[145997]
    assert f.finding_id == "tenable:145997:prod-web-01"
    assert f.source_system == "Tenable.io"
    assert f.source_class is SourceClass.VULNERABILITY_SCANNER
    assert f.severity is Severity.HIGH
    assert f.vendor_severity == "high"
    assert f.cves == ["CVE-2021-3156"]
    assert f.cpes == ["cpe:/a:sudo_project:sudo"]
    assert f.affected_assets == ["prod-web-01"]
    assert "Baron Samedit" in f.title
    assert "Fixed version" in f.description  # plugin.output merged in
    assert f.recommended_remediation == "Update the affected sudo and / or sudo-ldap packages."
    assert f.cwes == []
    assert f.mitre_techniques == []


def test_log4shell_multi_cve_critical_severity(
    findings_by_plugin_id: dict[int, UnifiedFinding],
) -> None:
    f = findings_by_plugin_id[156032]
    assert f.severity is Severity.CRITICAL
    assert f.cves == ["CVE-2021-44228", "CVE-2021-45046"]
    assert f.affected_assets == ["prod-db-01"]


def test_ssh_weak_mac_zero_cve_medium_severity(
    findings_by_plugin_id: dict[int, UnifiedFinding],
) -> None:
    f = findings_by_plugin_id[71049]
    assert f.severity is Severity.MEDIUM
    assert f.cves == []
    assert f.cpes == ["cpe:/a:openbsd:openssh"]


def test_openssl_multi_cve_high_severity(findings_by_plugin_id: dict[int, UnifiedFinding]) -> None:
    f = findings_by_plugin_id[166478]
    assert f.severity is Severity.HIGH
    assert f.cves == ["CVE-2022-3602", "CVE-2022-3786"]


def test_ssh_permit_root_login_zero_cve_compliance_check(
    findings_by_plugin_id: dict[int, UnifiedFinding],
) -> None:
    f = findings_by_plugin_id[21745]
    assert f.severity is Severity.MEDIUM
    assert f.cves == []
    assert f.recommended_remediation is not None


def test_windows_kb_single_cve_high_severity(
    findings_by_plugin_id: dict[int, UnifiedFinding],
) -> None:
    f = findings_by_plugin_id[177541]
    assert f.severity is Severity.HIGH
    assert f.cves == ["CVE-2023-32046"]
    assert f.affected_assets == ["corp-file-02"]


def test_raw_source_preserves_original_dict(raw_findings: list[dict[str, Any]]) -> None:
    original = raw_findings[0]
    finding = normalize_finding(original)
    assert finding.raw_source == original


def test_timestamp_prefers_last_found(raw_findings: list[dict[str, Any]]) -> None:
    finding = normalize_finding(raw_findings[0])
    assert finding.timestamp.isoformat().startswith("2024-05-18T02:11:23.451")


# --- Severity normalization -------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("High", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.INFORMATIONAL),
        ("informational", Severity.INFORMATIONAL),
        (" high ", Severity.HIGH),
    ],
)
def test_normalize_severity_valid(raw: str, expected: Severity) -> None:
    assert _normalize_severity(raw) is expected


def test_normalize_severity_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Unrecognized Tenable severity"):
        _normalize_severity("apocalyptic")


# --- Asset identifier fallback chain -------------------------------------------------


def test_asset_identifier_prefers_hostname() -> None:
    asset = {"hostname": "host1", "fqdn": "host1.example.com", "ipv4": "1.2.3.4"}
    assert _asset_identifier(asset) == "host1"


def test_asset_identifier_falls_back_to_fqdn() -> None:
    assert _asset_identifier({"fqdn": "host1.example.com", "ipv4": "1.2.3.4"}) == (
        "host1.example.com"
    )


def test_asset_identifier_falls_back_to_ipv4() -> None:
    assert _asset_identifier({"ipv4": "1.2.3.4", "uuid": "abc"}) == "1.2.3.4"


def test_asset_identifier_falls_back_to_uuid() -> None:
    assert _asset_identifier({"uuid": "abc-123"}) == "abc-123"


def test_asset_identifier_raises_when_nothing_available() -> None:
    with pytest.raises(ValueError, match="no hostname, fqdn, ipv4"):
        _asset_identifier({})


# --- Malformed / edge-case input handling -------------------------------------------------


def _minimal_finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "asset": {"hostname": "test-host"},
        "plugin": {"id": 99999, "name": "Test Plugin", "description": "Test description."},
        "severity": "low",
        "last_found": "2024-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def test_missing_plugin_id_raises() -> None:
    finding = _minimal_finding()
    del finding["plugin"]["id"]
    with pytest.raises(ValueError, match="missing plugin.id"):
        normalize_finding(finding)


def test_missing_severity_raises() -> None:
    finding = _minimal_finding()
    del finding["severity"]
    with pytest.raises(ValueError, match="missing 'severity'"):
        normalize_finding(finding)


def test_missing_timestamp_fields_raises() -> None:
    finding = _minimal_finding()
    del finding["last_found"]
    with pytest.raises(ValueError, match="no last_found, first_found, or indexed_at"):
        normalize_finding(finding)


def test_cve_key_entirely_missing_defaults_to_empty_list() -> None:
    finding = _minimal_finding()
    result = normalize_finding(finding)
    assert result.cves == []


def test_cve_explicit_null_defaults_to_empty_list() -> None:
    finding = _minimal_finding()
    finding["plugin"]["cve"] = None
    result = normalize_finding(finding)
    assert result.cves == []


def test_malformed_cve_raises_validation_error() -> None:
    finding = _minimal_finding()
    finding["plugin"]["cve"] = ["not-a-real-cve"]
    with pytest.raises(ValueError, match="Invalid CVE identifier"):
        normalize_finding(finding)


def test_missing_solution_yields_none_remediation() -> None:
    finding = _minimal_finding()
    result = normalize_finding(finding)
    assert result.recommended_remediation is None


def test_empty_string_solution_yields_none_remediation() -> None:
    finding = _minimal_finding()
    finding["plugin"]["solution"] = ""
    result = normalize_finding(finding)
    assert result.recommended_remediation is None


def test_falls_back_to_first_found_when_last_found_missing() -> None:
    finding = _minimal_finding()
    del finding["last_found"]
    finding["first_found"] = "2023-06-01T00:00:00Z"
    result = normalize_finding(finding)
    assert result.timestamp.year == 2023


def test_ingester_run_id_propagated() -> None:
    finding = normalize_finding(_minimal_finding(), ingester_run_id="run-xyz")
    assert finding.ingester_run_id == "run-xyz"


def test_description_without_output_omits_scan_output_section() -> None:
    finding = normalize_finding(_minimal_finding())
    assert "Scan output" not in finding.description


# --- End-to-end run() and CLI -------------------------------------------------


def test_run_end_to_end_writes_six_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "tenable_findings.jsonl"

    result = run(FIXTURE_PATH, output_path)

    assert result.success is True
    assert result.records_written == 6
    assert result.records_failed == 0

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 6
    restored = [UnifiedFinding.model_validate_json(line) for line in lines]
    assert all(f.ingester_run_id == result.run_id for f in restored)
    assert {f.source_finding_id for f in restored} == {
        "145997",
        "156032",
        "71049",
        "166478",
        "21745",
        "177541",
    }


def test_run_continues_past_bad_records_and_reports_failure(tmp_path: Path) -> None:
    input_path = tmp_path / "mixed.json"
    input_path.write_text(
        json.dumps({"findings": [_minimal_finding(), {"plugin": {"id": 1}}]}), encoding="utf-8"
    )
    output_path = tmp_path / "out.jsonl"

    result = run(input_path, output_path)

    assert result.success is False
    assert result.records_written == 1
    assert result.records_failed == 1
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "out.jsonl"
    exit_code = _run_cli(["--input", str(FIXTURE_PATH), "--output", str(output_path)])
    assert exit_code == 0
    assert "Wrote 6 findings" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_input(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--input", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1


def test_cli_returns_nonzero_when_any_record_fails(tmp_path: Path) -> None:
    input_path = tmp_path / "mixed.json"
    input_path.write_text(json.dumps({"findings": [{"plugin": {"id": 1}}]}), encoding="utf-8")
    exit_code = _run_cli(["--input", str(input_path), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
