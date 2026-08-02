"""End-to-end tests for the CTID ATT&CK-to-NIST-800-53 mapping ingester, using
a small hand-crafted fixture (see
tests/ingesters/fixtures/ctid_attack_control_mappings_sample.json).
No live network calls are made anywhere in this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.ctid_attack_control_mappings import (
    _normalize_control_id,
    _run_cli,
    fetch_mappings,
    parse_mappings,
    run,
)
from grc_agent.schemas import AttackControlMapping, Framework

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "ctid_attack_control_mappings_sample.json"


@pytest.fixture
def doc() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def mappings(doc: dict) -> list[AttackControlMapping]:
    return list(parse_mappings(doc, ingester_run_id="test-run-123"))


def test_only_complete_mappings_are_included(mappings: list[AttackControlMapping]) -> None:
    technique_ids = {m.technique_id for m in mappings}
    assert technique_ids == {"T1666", "T1556.009"}
    assert "T1496.002" not in technique_ids  # non_mappable, must be excluded


def test_control_id_is_normalized_from_zero_padded_form(
    mappings: list[AttackControlMapping],
) -> None:
    by_technique = {m.technique_id: m for m in mappings}
    assert by_technique["T1666"].control_id == "CM-3"
    assert by_technique["T1556.009"].control_id == "AC-2"


def test_control_framework_is_nist_800_53_r5(mappings: list[AttackControlMapping]) -> None:
    assert all(m.control_framework is Framework.NIST_SP_800_53_R5 for m in mappings)


def test_mapping_type_and_comments(mappings: list[AttackControlMapping]) -> None:
    by_technique = {m.technique_id: m for m in mappings}
    assert by_technique["T1666"].mapping_type == "mitigates"
    assert "Monitoring and reviewing" in (by_technique["T1666"].comments or "")
    assert by_technique["T1556.009"].comments is None


def test_ingester_run_id_propagated(mappings: list[AttackControlMapping]) -> None:
    assert all(m.ingester_run_id == "test-run-123" for m in mappings)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("AC-02", "AC-2"), ("CM-03", "CM-3"), ("AC-20", "AC-20"), ("SI-100", "SI-100")],
)
def test_normalize_control_id(raw: str, expected: str) -> None:
    assert _normalize_control_id(raw) == expected


def test_fetch_mappings_reads_local_file(doc: dict) -> None:
    assert fetch_mappings(str(FIXTURE_PATH)) == doc


def test_fetch_mappings_fetches_over_http(doc: dict) -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = doc
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_mappings("https://example.com/mappings.json")

    mock_get.assert_called_once()
    assert result == doc


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "attack_control_mappings.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 2
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [AttackControlMapping.model_validate_json(line) for line in lines]
    assert {m.technique_id for m in restored} == {"T1666", "T1556.009"}


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "attack_control_mappings.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 2 mappings" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
