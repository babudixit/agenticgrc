"""End-to-end tests for the NIST SP 800-53 OSCAL ingester, using a small,
hand-crafted fixture that mirrors the real catalog's structure (see
tests/ingesters/fixtures/oscal_sample_catalog.json) rather than the full
~10MB real file. No live network calls are made anywhere in this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.nist_sp800_53 import (
    _family_label,
    _guess_canonical_id,
    _run_cli,
    fetch_catalog,
    parse_catalog,
    run,
)
from grc_agent.schemas import Framework, UnifiedControl

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "oscal_sample_catalog.json"


@pytest.fixture
def catalog_doc() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def controls(catalog_doc: dict) -> dict[str, UnifiedControl]:
    return {c.control_id: c for c in parse_catalog(catalog_doc, ingester_run_id="test-run-123")}


def test_parses_expected_number_of_controls(controls: dict[str, UnifiedControl]) -> None:
    assert set(controls.keys()) == {"AC-1", "AC-2", "AC-2(1)", "AC-13", "IA-1"}


def test_ac1_basic_fields_and_multi_part_statement(controls: dict[str, UnifiedControl]) -> None:
    ac1 = controls["AC-1"]

    assert ac1.framework is Framework.NIST_SP_800_53_R5
    assert ac1.version == "5.1.1"
    assert ac1.control_family == "AC"
    assert ac1.title == "Policy and Procedures"
    assert ac1.parent_control_id is None
    assert "a. Develop, document, and disseminate" in ac1.statement
    assert "b. Review and update" in ac1.statement
    # Guidance parts must not leak into the statement text.
    assert "guidance parts are ignored" not in ac1.statement


def test_ac1_resolves_parameter_placeholder(controls: dict[str, UnifiedControl]) -> None:
    ac1 = controls["AC-1"]
    assert "[organization-defined personnel or roles]" in ac1.statement
    assert "{{ insert:" not in ac1.statement
    assert ac1.parameters == ["organization-defined personnel or roles"]


def test_ac1_related_controls_resolved_cross_group_and_via_fallback(
    controls: dict[str, UnifiedControl],
) -> None:
    ac1 = controls["AC-1"]
    # IA-1 exists in the fixture (cross-group resolution); PM-9 does not, so it
    # falls back to the best-effort canonical-id guess.
    assert ac1.related_controls == ["IA-1", "PM-9"]


def test_ac2_single_prose_statement_no_subparts(controls: dict[str, UnifiedControl]) -> None:
    ac2 = controls["AC-2"]
    assert ac2.statement == (
        "Define and document the types of accounts allowed and specifically "
        "prohibited for use within the system."
    )
    assert ac2.related_controls == ["AC-3"]  # not in fixture -> guessed fallback


def test_enhancement_parent_and_control_id(controls: dict[str, UnifiedControl]) -> None:
    enhancement = controls["AC-2(1)"]
    assert enhancement.parent_control_id == "AC-2"
    assert enhancement.control_family == "AC"
    assert enhancement.title == "Automated System Account Management"
    assert enhancement.statement == (
        "Support the management of system accounts using automated mechanisms."
    )


def test_withdrawn_control_statement_and_incorporated_into(
    controls: dict[str, UnifiedControl],
) -> None:
    ac13 = controls["AC-13"]
    assert ac13.related_controls == []
    assert ac13.statement == "This control has been withdrawn. Incorporated into: AC-2, AU-6."


def test_second_group_family_label(controls: dict[str, UnifiedControl]) -> None:
    assert controls["IA-1"].control_family == "IA"


def test_ingester_run_id_propagated_to_every_control(controls: dict[str, UnifiedControl]) -> None:
    assert all(c.ingester_run_id == "test-run-123" for c in controls.values())


def test_raw_source_preserves_original_control_dict(
    catalog_doc: dict, controls: dict[str, UnifiedControl]
) -> None:
    original_ac1 = catalog_doc["catalog"]["groups"][0]["controls"][0]
    assert controls["AC-1"].raw_source == original_ac1


def test_guess_canonical_id() -> None:
    assert _guess_canonical_id("au-6") == "AU-6"
    assert _guess_canonical_id("ac-2.1") == "AC-2(1)"


def test_family_label_falls_back_to_group_id_when_no_label_prop() -> None:
    assert _family_label({"id": "zz", "controls": []}) == "ZZ"


def test_fetch_catalog_reads_local_file(catalog_doc: dict) -> None:
    result = fetch_catalog(str(FIXTURE_PATH))
    assert result == catalog_doc


def test_fetch_catalog_fetches_over_http_when_source_is_a_url(catalog_doc: dict) -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = catalog_doc
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_catalog("https://example.com/catalog.json")

    mock_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()
    assert result == catalog_doc


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "sp800_53.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 5
    assert result.records_failed == 0
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    restored = [UnifiedControl.model_validate_json(line) for line in lines]
    assert {c.control_id for c in restored} == {"AC-1", "AC-2", "AC-2(1)", "AC-13", "IA-1"}
    assert all(c.ingester_run_id == result.run_id for c in restored)


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "sp800_53.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 5 controls" in capsys.readouterr().out
    assert output_path.exists()


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
