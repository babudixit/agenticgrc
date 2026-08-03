"""End-to-end tests for the NIST SP 800-171 Rev 3 OSCAL ingester, using a
small, hand-crafted fixture that mirrors the real `-min` catalog's structure
(see tests/ingesters/fixtures/sp800_171_sample_catalog.json). No live network
calls are made anywhere in this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.nist_sp800_171 import _run_cli, fetch_catalog, parse_catalog, run
from grc_agent.schemas import Framework, UnifiedControl

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sp800_171_sample_catalog.json"


@pytest.fixture
def catalog_doc() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def controls(catalog_doc: dict) -> dict[str, UnifiedControl]:
    return {c.control_id: c for c in parse_catalog(catalog_doc, ingester_run_id="test-run-171")}


def test_parses_expected_number_of_requirements(controls: dict[str, UnifiedControl]) -> None:
    assert set(controls.keys()) == {"03.01.01", "03.01.02", "03.05.01"}


def test_requirement_id_derived_by_stripping_prefix_not_from_label_prop(
    controls: dict[str, UnifiedControl],
) -> None:
    # The `label` prop is "Account Management (03.01.01)" (title+id combined);
    # control_id must be the bare dotted-decimal id, not that combined string.
    req = controls["03.01.01"]
    assert req.control_id == "03.01.01"
    assert req.title == "Account Management"


def test_requirement_basic_fields(controls: dict[str, UnifiedControl]) -> None:
    req = controls["03.01.01"]
    assert req.framework is Framework.NIST_SP_800_171_R3
    assert req.version == "3"
    assert req.control_family == "Access Control (03.01)"
    assert req.parent_control_id is None
    assert "Manage system accounts" in req.statement
    assert req.parameters == ["time period"]


def test_second_family_requirement(controls: dict[str, UnifiedControl]) -> None:
    req = controls["03.05.01"]
    assert req.control_family == "Identification and Authentication (03.05)"
    assert "Uniquely identify and authenticate" in req.statement


def test_bibliography_reference_links_are_not_treated_as_related_controls(
    controls: dict[str, UnifiedControl],
) -> None:
    # SP 800-171's own `rel: reference` links point at back-matter UUIDs, not
    # sibling requirements — they must never surface as `related_controls`.
    assert controls["03.01.01"].related_controls == []


def test_ingester_run_id_propagated(controls: dict[str, UnifiedControl]) -> None:
    assert all(c.ingester_run_id == "test-run-171" for c in controls.values())


def test_raw_source_preserves_original_control_dict(
    catalog_doc: dict, controls: dict[str, UnifiedControl]
) -> None:
    original = catalog_doc["catalog"]["groups"][0]["controls"][0]
    assert controls["03.01.01"].raw_source == original


def test_fetch_catalog_reads_local_file(catalog_doc: dict) -> None:
    assert fetch_catalog(str(FIXTURE_PATH)) == catalog_doc


def test_fetch_catalog_fetches_over_http_when_source_is_a_url(catalog_doc: dict) -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = catalog_doc
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_catalog("https://example.com/catalog.json")

    mock_get.assert_called_once()
    assert result == catalog_doc


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "sp800_171.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 3
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [UnifiedControl.model_validate_json(line) for line in lines]
    assert {c.control_id for c in restored} == {"03.01.01", "03.01.02", "03.05.01"}


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "sp800_171.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 3 controls" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
