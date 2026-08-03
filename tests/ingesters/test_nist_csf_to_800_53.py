"""Tests for the CSF 2.0 -> SP 800-53 Informative References crosswalk ingester.

Uses a hand-crafted minimal .xlsx fixture that mirrors the real CSF Reference
Tool export's sheet name/columns (see
tests/ingesters/fixtures/csf_to_800_53_sample.xlsx). No live network calls.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.nist_csf_to_800_53 import (
    _normalize_control_id,
    _run_cli,
    fetch_workbook,
    parse_workbook,
    run,
)
from grc_agent.schemas import ControlControlMapping, Framework

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "csf_to_800_53_sample.xlsx"


@pytest.fixture
def workbook_bytes() -> bytes:
    return FIXTURE_PATH.read_bytes()


@pytest.fixture
def mappings(workbook_bytes: bytes) -> list[ControlControlMapping]:
    return list(parse_workbook(workbook_bytes, ingester_run_id="test-run-csf-xwalk"))


def test_emits_expected_mappings_and_dedupes_minor_revisions(
    mappings: list[ControlControlMapping],
) -> None:
    pairs = {(m.source_control_id, m.target_control_id) for m in mappings}
    # GV.OC-01: PM-11 appears under both Rev 5.1.1 and 5.2.0 — kept once.
    # GV.OC-04: CP-02(08) -> CP-2(8), plus PM-11; bare "PT" family label skipped.
    # GV.OC-99: no 800-53 refs — produces nothing.
    assert pairs == {
        ("GV.OC-01", "PM-11"),
        ("GV.OC-04", "CP-2(8)"),
        ("GV.OC-04", "PM-11"),
    }


def test_frameworks_and_mapping_type(mappings: list[ControlControlMapping]) -> None:
    assert all(m.source_framework is Framework.NIST_CSF_2_0 for m in mappings)
    assert all(m.target_framework is Framework.NIST_SP_800_53_R5 for m in mappings)
    assert all(m.mapping_type == "related" for m in mappings)


def test_keeps_latest_revision_in_comments(mappings: list[ControlControlMapping]) -> None:
    pm11 = next(m for m in mappings if m.source_control_id == "GV.OC-01")
    assert "Rev 5.2.0" in (pm11.comments or "")
    assert pm11.raw_source["sp800_53_revision"] == "5.2.0"


def test_normalize_control_id() -> None:
    assert _normalize_control_id("AC-01") == "AC-1"
    assert _normalize_control_id("CP-02(08)") == "CP-2(8)"
    assert _normalize_control_id("PM-11") == "PM-11"


def test_ingester_run_id_propagated(mappings: list[ControlControlMapping]) -> None:
    assert all(m.ingester_run_id == "test-run-csf-xwalk" for m in mappings)


def test_fetch_workbook_reads_local_file(workbook_bytes: bytes) -> None:
    assert fetch_workbook(str(FIXTURE_PATH)) == workbook_bytes


def test_fetch_workbook_fetches_over_http(workbook_bytes: bytes) -> None:
    mock_response = MagicMock()
    mock_response.content = workbook_bytes
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_workbook("https://example.com/csf.xlsx")

    mock_get.assert_called_once()
    assert result == workbook_bytes


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "csf_xwalk.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 3
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [ControlControlMapping.model_validate_json(line) for line in lines]
    assert {(m.source_control_id, m.target_control_id) for m in restored} == {
        ("GV.OC-01", "PM-11"),
        ("GV.OC-04", "CP-2(8)"),
        ("GV.OC-04", "PM-11"),
    }


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "out.jsonl"
    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])
    assert exit_code == 0
    assert "Wrote 3 mappings" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.xlsx"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
