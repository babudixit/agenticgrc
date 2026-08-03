"""End-to-end tests for the NIST CSF 2.0 OSCAL ingester, using a small,
hand-crafted fixture that mirrors the real catalog's 3-level Function ->
Category -> Subcategory structure (see
tests/ingesters/fixtures/csf_sample_catalog.json). No live network calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.nist_csf import _run_cli, fetch_catalog, parse_catalog, run
from grc_agent.schemas import Framework, UnifiedControl

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "csf_sample_catalog.json"


@pytest.fixture
def catalog_doc() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def controls(catalog_doc: dict) -> dict[str, UnifiedControl]:
    return {c.control_id: c for c in parse_catalog(catalog_doc, ingester_run_id="test-run-csf")}


def test_parses_both_categories_and_subcategories(controls: dict[str, UnifiedControl]) -> None:
    assert set(controls.keys()) == {"GV.OC", "GV.OC-01", "GV.OC-05", "ID.BE", "ID.BE-01"}


def test_category_fields(controls: dict[str, UnifiedControl]) -> None:
    category = controls["GV.OC"]
    assert category.framework is Framework.NIST_CSF_2_0
    assert category.version == "2.0"
    assert category.control_family == "GOVERN (GV)"
    assert category.title == "Organizational Context"
    assert category.parent_control_id is None
    assert "cybersecurity risk management decisions are understood" in category.statement


def test_subcategory_parent_is_its_category(controls: dict[str, UnifiedControl]) -> None:
    subcat = controls["GV.OC-01"]
    assert subcat.parent_control_id == "GV.OC"
    assert subcat.control_family == "GOVERN (GV)"
    # Subcategories have no independent title in real CSF OSCAL data.
    assert subcat.title == "GV.OC-01"


def test_subcategory_statement_excludes_implementation_examples(
    controls: dict[str, UnifiedControl],
) -> None:
    subcat = controls["GV.OC-01"]
    assert subcat.statement == (
        "The organizational mission is understood and informs cybersecurity risk management"
    )
    assert "Share the organization's mission" not in subcat.statement


def test_subcategory_related_link_resolved(controls: dict[str, UnifiedControl]) -> None:
    assert controls["GV.OC-01"].related_controls == ["GV.OC-05"]


def test_withdrawn_category_and_subcategory(controls: dict[str, UnifiedControl]) -> None:
    category = controls["ID.BE"]
    assert category.statement == "This item has been withdrawn from CSF 2.0."
    assert category.related_controls == []

    subcat = controls["ID.BE-01"]
    assert subcat.statement == (
        "This item has been withdrawn from CSF 2.0. Incorporated into: GV.OC-05."
    )
    assert subcat.parent_control_id == "ID.BE"


def test_ingester_run_id_propagated(controls: dict[str, UnifiedControl]) -> None:
    assert all(c.ingester_run_id == "test-run-csf" for c in controls.values())


def test_raw_source_preserves_original_control_dict(
    catalog_doc: dict, controls: dict[str, UnifiedControl]
) -> None:
    original = catalog_doc["catalog"]["groups"][0]["controls"][0]
    assert controls["GV.OC"].raw_source == original


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
    output_path = tmp_path / "csf.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 5
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [UnifiedControl.model_validate_json(line) for line in lines]
    assert {c.control_id for c in restored} == {
        "GV.OC",
        "GV.OC-01",
        "GV.OC-05",
        "ID.BE",
        "ID.BE-01",
    }


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "csf.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 5 controls" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
