"""End-to-end tests for the MITRE CWE ingester, using a small hand-crafted
XML fixture that mirrors the real catalog's structure (see
tests/ingesters/fixtures/cwe_sample.xml). No live network calls are made.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.mitre_cwe import _run_cli, fetch_catalog, parse_catalog, run
from grc_agent.schemas import UnifiedWeakness

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cwe_sample.xml"


@pytest.fixture
def xml_content() -> bytes:
    return FIXTURE_PATH.read_bytes()


@pytest.fixture
def weaknesses(xml_content: bytes) -> dict[str, UnifiedWeakness]:
    return {w.weakness_id: w for w in parse_catalog(xml_content, ingester_run_id="test-run-123")}


def test_parses_expected_number_of_weaknesses(weaknesses: dict[str, UnifiedWeakness]) -> None:
    assert set(weaknesses.keys()) == {"CWE-79", "CWE-89", "CWE-20", "CWE-1187"}


def test_cwe79_basic_fields(weaknesses: dict[str, UnifiedWeakness]) -> None:
    cwe79 = weaknesses["CWE-79"]

    assert cwe79.abstraction == "Base"
    assert cwe79.status == "Stable"
    assert "Cross-site Scripting" in cwe79.name
    assert "does not neutralize" in cwe79.description


def test_cwe79_extended_description_joins_paragraphs(
    weaknesses: dict[str, UnifiedWeakness],
) -> None:
    cwe79 = weaknesses["CWE-79"]
    assert cwe79.extended_description == (
        "There are many variants of cross-site scripting, characterized by a "
        "variety of terms or involving different attack topologies."
    )


def test_cwe79_related_weaknesses_filtered_to_primary_view(
    weaknesses: dict[str, UnifiedWeakness],
) -> None:
    cwe79 = weaknesses["CWE-79"]
    # View 1003 duplicate of ChildOf-74 must not appear twice or leak through.
    assert cwe79.related_weakness_ids == ["CWE-74", "CWE-494", "CWE-352"]


def test_cwe89_single_related_weakness(weaknesses: dict[str, UnifiedWeakness]) -> None:
    assert weaknesses["CWE-89"].related_weakness_ids == ["CWE-943"]


def test_cwe20_has_no_related_weaknesses_element(weaknesses: dict[str, UnifiedWeakness]) -> None:
    assert weaknesses["CWE-20"].related_weakness_ids == []
    assert weaknesses["CWE-20"].extended_description is None


def test_deprecated_weakness_status_preserved(weaknesses: dict[str, UnifiedWeakness]) -> None:
    assert weaknesses["CWE-1187"].status == "Deprecated"


def test_ingester_run_id_propagated(weaknesses: dict[str, UnifiedWeakness]) -> None:
    assert all(w.ingester_run_id == "test-run-123" for w in weaknesses.values())


def test_raw_source_preserves_raw_xml(weaknesses: dict[str, UnifiedWeakness]) -> None:
    raw = weaknesses["CWE-79"].raw_source
    assert raw["ID"] == "79"
    assert "Related_Weakness" in raw["raw_xml"]


def test_fetch_catalog_reads_local_xml_file(xml_content: bytes) -> None:
    assert fetch_catalog(str(FIXTURE_PATH)) == xml_content


def test_fetch_catalog_unzips_local_zip_file(xml_content: bytes, tmp_path: Path) -> None:
    zip_path = tmp_path / "cwe_sample.xml.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("cwec_v4.20.xml", xml_content)

    assert fetch_catalog(str(zip_path)) == xml_content


def test_fetch_catalog_fetches_and_unzips_over_http(xml_content: bytes) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("cwec_v4.20.xml", xml_content)

    mock_response = MagicMock()
    mock_response.content = buffer.getvalue()
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_catalog("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")

    mock_get.assert_called_once()
    assert result == xml_content


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "cwe.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 4
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [UnifiedWeakness.model_validate_json(line) for line in lines]
    assert {w.weakness_id for w in restored} == {"CWE-79", "CWE-89", "CWE-20", "CWE-1187"}


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "cwe.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 4 weaknesses" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.xml"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
