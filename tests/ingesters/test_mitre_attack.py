"""End-to-end tests for the MITRE ATT&CK ingester, using a small hand-crafted
STIX bundle fixture (see tests/ingesters/fixtures/attack_sample.json).
No live network calls are made anywhere in this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.ingesters.mitre_attack import _run_cli, fetch_bundle, parse_bundle, run
from grc_agent.schemas import UnifiedAttackTechnique

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "attack_sample.json"


@pytest.fixture
def bundle() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def techniques(bundle: dict) -> dict[str, UnifiedAttackTechnique]:
    return {t.technique_id: t for t in parse_bundle(bundle, ingester_run_id="test-run-123")}


def test_parses_expected_techniques_and_excludes_revoked_and_deprecated(
    techniques: dict[str, UnifiedAttackTechnique],
) -> None:
    assert set(techniques.keys()) == {"T1057", "T1055", "T1055.011"}


def test_non_subtechnique_fields(techniques: dict[str, UnifiedAttackTechnique]) -> None:
    t1057 = techniques["T1057"]

    assert t1057.name == "Process Discovery"
    assert t1057.is_subtechnique is False
    assert t1057.parent_technique_id is None
    assert t1057.tactics == ["discovery"]
    assert t1057.platforms == ["Windows", "Linux", "macOS"]


def test_technique_with_multiple_tactics(techniques: dict[str, UnifiedAttackTechnique]) -> None:
    t1055 = techniques["T1055"]
    assert t1055.tactics == ["defense-evasion", "privilege-escalation"]


def test_subtechnique_parent_derived_from_id(
    techniques: dict[str, UnifiedAttackTechnique],
) -> None:
    sub = techniques["T1055.011"]
    assert sub.is_subtechnique is True
    assert sub.parent_technique_id == "T1055"


def test_ingester_run_id_propagated(techniques: dict[str, UnifiedAttackTechnique]) -> None:
    assert all(t.ingester_run_id == "test-run-123" for t in techniques.values())


def test_raw_source_preserves_original_stix_object(
    bundle: dict, techniques: dict[str, UnifiedAttackTechnique]
) -> None:
    original = bundle["objects"][0]
    assert techniques["T1057"].raw_source == original


def test_fetch_bundle_reads_local_file(bundle: dict) -> None:
    assert fetch_bundle(str(FIXTURE_PATH)) == bundle


def test_fetch_bundle_fetches_over_http(bundle: dict) -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = bundle
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_bundle("https://example.com/enterprise-attack.json")

    mock_get.assert_called_once()
    assert result == bundle


def test_run_end_to_end_writes_valid_jsonlines(tmp_path: Path) -> None:
    output_path = tmp_path / "attack_techniques.jsonl"

    result = run(str(FIXTURE_PATH), output_path)

    assert result.success is True
    assert result.records_written == 3
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [UnifiedAttackTechnique.model_validate_json(line) for line in lines]
    assert {t.technique_id for t in restored} == {"T1057", "T1055", "T1055.011"}


def test_cli_success_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "attack_techniques.jsonl"

    exit_code = _run_cli(["--source", str(FIXTURE_PATH), "--output", str(output_path)])

    assert exit_code == 0
    assert "Wrote 3 techniques" in capsys.readouterr().out


def test_cli_returns_nonzero_for_missing_source(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    exit_code = _run_cli(["--source", str(missing), "--output", str(tmp_path / "out.jsonl")])
    assert exit_code == 1
