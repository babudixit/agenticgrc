"""Tests for the SP 800-171 Rev 3 -> SP 800-53 CUI Overlay crosswalk ingester.

Uses a hand-crafted minimal .xlsx fixture that mirrors the real CUI Overlay's
sheet name/columns (see
tests/ingesters/fixtures/sp800_171_cui_overlay_sample.xlsx). No live network
calls.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.nist_sp800_171_to_800_53 import (
    _normalize_control_id,
    _run_cli,
    fetch_workbook,
    parse_workbook,
    run,
)
from grc_agent.schemas import ControlControlMapping, Framework

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sp800_171_cui_overlay_sample.xlsx"


@pytest.fixture
def workbook_bytes() -> bytes:
    return FIXTURE_PATH.read_bytes()


@pytest.fixture
def mappings(workbook_bytes: bytes) -> list[ControlControlMapping]:
    return list(parse_workbook(workbook_bytes, ingester_run_id="test-run-171-xwalk"))


def test_emits_expected_cui_mappings_and_skips_nco_and_statement_rows(
    mappings: list[ControlControlMapping],
) -> None:
    pairs = {(m.source_control_id, m.target_control_id) for m in mappings}
    # AC-01 -> 03.15.01 (CUI); statement-level child row deduped away.
    # AC-02 -> 03.01.01 (CUI).
    # AC-02(03) -> 03.01.01 (CUI enhancement, zero-pad normalized).
    # AC-02(01) is NCO — skipped.
    assert pairs == {
        ("03.15.01", "AC-1"),
        ("03.01.01", "AC-2"),
        ("03.01.01", "AC-2(3)"),
    }


def test_frameworks_and_mapping_type(mappings: list[ControlControlMapping]) -> None:
    assert all(m.source_framework is Framework.NIST_SP_800_171_R3 for m in mappings)
    assert all(m.target_framework is Framework.NIST_SP_800_53_R5 for m in mappings)
    assert all(m.mapping_type == "derived_from" for m in mappings)


def test_normalize_control_id() -> None:
    assert _normalize_control_id("AC-01") == "AC-1"
    assert _normalize_control_id("AC-02(03)") == "AC-2(3)"
    assert _normalize_control_id("PM-11") == "PM-11"


def test_ingester_run_id_propagated(mappings: list[ControlControlMapping]) -> None:
    assert all(m.ingester_run_id == "test-run-171-xwalk" for m in mappings)


def test_fetch_workbook_reads_local_file(workbook_bytes: bytes) -> None:
    assert fetch_workbook(str(FIXTURE_PATH)) == workbook_bytes


def test_fetch_workbook_fetches_over_http(workbook_bytes: bytes) -> None:
    mock_response = MagicMock()
    mock_response.content = workbook_bytes
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_workbook("https://example.com/overlay.xlsx")

    mock_get.assert_called_once()
    assert result == workbook_bytes


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "171_xwalk.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 3
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [ControlControlMapping.model_validate_json(line) for line in lines]
    assert {(m.source_control_id, m.target_control_id) for m in restored} == {
        ("03.15.01", "AC-1"),
        ("03.01.01", "AC-2"),
        ("03.01.01", "AC-2(3)"),
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
