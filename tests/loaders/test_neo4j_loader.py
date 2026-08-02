"""Unit tests for the Neo4j loader's data-transformation and orchestration
logic, using a mocked driver — no live Neo4j connection required. See
tests/loaders/test_neo4j_loader_integration.py for tests against a real,
running Neo4j instance.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from grc_agent.loaders.neo4j_loader import (
    _attack_technique_to_node_params,
    _chunks,
    _control_to_node_params,
    _mapping_to_edge_params,
    _run_cli,
    _vulnerability_to_node_params,
    _weakness_to_node_params,
    load_attack_control_mappings,
    load_attack_techniques,
    load_controls,
    load_vulnerabilities,
    load_weaknesses,
    read_jsonl,
)
from grc_agent.schemas import (
    AttackControlMapping,
    Framework,
    Severity,
    UnifiedAttackTechnique,
    UnifiedControl,
    UnifiedVulnerability,
    UnifiedWeakness,
)


@pytest.fixture
def base_control() -> UnifiedControl:
    return UnifiedControl(
        control_id="AC-2(1)",
        framework=Framework.NIST_SP_800_53_R5,
        version="5.1.1",
        title="Automated System Account Management",
        statement="Support the management of system accounts using automated mechanisms.",
        control_family="AC",
        parent_control_id="AC-2",
        related_controls=["AC-3"],
        parameters=[],
        baselines=[],
        raw_source={"id": "ac-2.1", "class": "SP800-53-enhancement"},
        ingester_run_id="ingest-run-1",
    )


def _mock_driver() -> MagicMock:
    driver = MagicMock()
    driver.__enter__.return_value = driver
    driver.__exit__.return_value = False
    summary = MagicMock()
    summary.counters.relationships_created = 1
    driver.execute_query.return_value = ([], summary, [])
    return driver


def test_control_to_node_params_serializes_raw_source_and_enum(
    base_control: UnifiedControl,
) -> None:
    params = _control_to_node_params(base_control)

    assert params["control_id"] == "AC-2(1)"
    assert params["framework"] == "NIST_SP_800-53_r5"  # enum -> plain string value
    assert params["parent_control_id"] == "AC-2"
    assert isinstance(params["ingested_at"], str)  # datetime -> ISO string
    assert json.loads(params["raw_source_json"]) == base_control.raw_source


def test_chunks_splits_into_expected_batches() -> None:
    items = list(range(7))
    batches = list(_chunks(items, 3))
    assert batches == [[0, 1, 2], [3, 4, 5], [6]]


def test_chunks_handles_empty_list() -> None:
    assert list(_chunks([], 3)) == []


def test_read_jsonl_skips_blank_lines(tmp_path: Path, base_control: UnifiedControl) -> None:
    path = tmp_path / "controls.jsonl"
    path.write_text(
        base_control.model_dump_json() + "\n\n" + base_control.model_dump_json() + "\n",
        encoding="utf-8",
    )

    records = list(read_jsonl(path, UnifiedControl))

    assert len(records) == 2
    assert all(r.control_id == "AC-2(1)" for r in records)


def test_load_controls_writes_nodes_and_relationships(base_control: UnifiedControl) -> None:
    driver = _mock_driver()

    result = load_controls(
        [base_control],
        driver=driver,
        database="neo4j",
        loader_run_id="loader-run-1",
    )

    assert result.success is True
    assert result.records_written == 1
    assert result.run_id == "loader-run-1"

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert any("CREATE CONSTRAINT" in q for q in queries)
    assert any("MERGE (c:Control" in q for q in queries)
    assert any("RELATES_TO" in q for q in queries)  # from related_controls=["AC-3"]
    assert any("ENHANCES" in q for q in queries)  # from parent_control_id="AC-2"


def test_load_controls_skips_relationship_queries_when_none_needed() -> None:
    driver = _mock_driver()
    lonely_control = UnifiedControl(
        control_id="ZZ-1",
        framework=Framework.NIST_SP_800_53_R5,
        version="5.1.1",
        title="Solo control",
        statement="No relationships here.",
        raw_source={},
    )

    load_controls([lonely_control], driver=driver, database="neo4j", loader_run_id="run-2")

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert not any("RELATES_TO" in q for q in queries)
    assert not any("ENHANCES" in q for q in queries)


def test_load_controls_batches_large_inputs(base_control: UnifiedControl) -> None:
    driver = _mock_driver()
    controls = [base_control.model_copy(update={"control_id": f"AC-{i}"}) for i in range(5)]

    load_controls(controls, driver=driver, database="neo4j", loader_run_id="run-3", batch_size=2)

    node_upsert_calls = [
        call for call in driver.execute_query.call_args_list if "MERGE (c:Control" in call.args[0]
    ]
    assert len(node_upsert_calls) == 3  # ceil(5 / 2)


@pytest.fixture
def base_weakness() -> UnifiedWeakness:
    return UnifiedWeakness(
        weakness_id="CWE-79",
        name="Cross-site Scripting",
        description="Improper neutralization of input during web page generation.",
        abstraction="Base",
        status="Stable",
        related_weakness_ids=["CWE-74"],
        raw_source={"ID": "79"},
        ingester_run_id="ingest-run-1",
    )


@pytest.fixture
def base_technique() -> UnifiedAttackTechnique:
    return UnifiedAttackTechnique(
        technique_id="T1055.011",
        name="Extra Window Memory Injection",
        description="Adversaries may inject malicious code into process via EWM.",
        tactics=["defense-evasion", "privilege-escalation"],
        is_subtechnique=True,
        parent_technique_id="T1055",
        platforms=["Windows"],
        raw_source={"id": "attack-pattern--test"},
        ingester_run_id="ingest-run-1",
    )


@pytest.fixture
def base_vulnerability() -> UnifiedVulnerability:
    return UnifiedVulnerability(
        cve_id="CVE-2021-3156",
        description="Heap-based buffer overflow in Sudo.",
        cvss_v3_score=7.8,
        cvss_v3_severity=Severity.HIGH,
        cwes=["CWE-193", "CWE-787"],
        cpes=["cpe:2.3:a:openbsd:openssh:8.2"],
        raw_source={"id": "CVE-2021-3156"},
        ingester_run_id="ingest-run-1",
    )


@pytest.fixture
def base_mapping() -> AttackControlMapping:
    return AttackControlMapping(
        technique_id="T1556.009",
        control_id="AC-2",
        control_framework=Framework.NIST_SP_800_53_R5,
        mapping_type="mitigates",
        comments="Justification text.",
        raw_source={"attack_object_id": "T1556.009"},
        ingester_run_id="ingest-run-1",
    )


def test_weakness_to_node_params_serializes_raw_source(base_weakness: UnifiedWeakness) -> None:
    params = _weakness_to_node_params(base_weakness)

    assert params["weakness_id"] == "CWE-79"
    assert params["related_weakness_ids"] == ["CWE-74"]
    assert json.loads(params["raw_source_json"]) == base_weakness.raw_source


def test_load_weaknesses_writes_nodes_and_relates_to_edges(
    base_weakness: UnifiedWeakness,
) -> None:
    driver = _mock_driver()

    result = load_weaknesses(
        [base_weakness], driver=driver, database="neo4j", loader_run_id="loader-run-w"
    )

    assert result.success is True
    assert result.records_written == 1

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert any("CREATE CONSTRAINT" in q and "Weakness" in q for q in queries)
    assert any("MERGE (w:Weakness" in q for q in queries)
    assert any("MATCH (a:Weakness" in q for q in queries)  # from related_weakness_ids


def test_attack_technique_to_node_params_serializes_lists(
    base_technique: UnifiedAttackTechnique,
) -> None:
    params = _attack_technique_to_node_params(base_technique)

    assert params["technique_id"] == "T1055.011"
    assert params["is_subtechnique"] is True
    assert params["parent_technique_id"] == "T1055"


def test_load_attack_techniques_writes_nodes_only(
    base_technique: UnifiedAttackTechnique,
) -> None:
    driver = _mock_driver()

    result = load_attack_techniques(
        [base_technique], driver=driver, database="neo4j", loader_run_id="loader-run-t"
    )

    assert result.success is True
    assert result.records_written == 1

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert any("MERGE (t:AttackTechnique" in q for q in queries)
    assert not any("MAPS_TO" in q for q in queries)  # no edges from this loader


def test_vulnerability_to_node_params_flattens_severity_enum(
    base_vulnerability: UnifiedVulnerability,
) -> None:
    params = _vulnerability_to_node_params(base_vulnerability)

    assert params["cve_id"] == "CVE-2021-3156"
    assert params["cvss_v3_severity"] == "High"  # enum -> plain string value
    assert params["cwes"] == ["CWE-193", "CWE-787"]


def test_load_vulnerabilities_writes_nodes_and_maps_to_weakness_edges(
    base_vulnerability: UnifiedVulnerability,
) -> None:
    driver = _mock_driver()

    result = load_vulnerabilities(
        [base_vulnerability], driver=driver, database="neo4j", loader_run_id="loader-run-v"
    )

    assert result.success is True
    assert result.records_written == 1

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert any("MERGE (v:Vulnerability" in q for q in queries)
    assert any("MATCH (v:Vulnerability" in q and "MAPS_TO" in q for q in queries)


def test_mapping_to_edge_params_derives_control_uid(base_mapping: AttackControlMapping) -> None:
    params = _mapping_to_edge_params(base_mapping)

    assert params["technique_id"] == "T1556.009"
    assert params["control_uid"] == "NIST_SP_800-53_r5:AC-2"
    assert params["mapping_type"] == "mitigates"


def test_load_attack_control_mappings_creates_no_nodes(
    base_mapping: AttackControlMapping,
) -> None:
    driver = _mock_driver()

    result = load_attack_control_mappings(
        [base_mapping], driver=driver, database="neo4j", loader_run_id="loader-run-m"
    )

    assert result.success is True
    assert result.records_written == 1

    queries = [call.args[0] for call in driver.execute_query.call_args_list]
    assert len(queries) == 1
    assert "MATCH (t:AttackTechnique" in queries[0]
    assert "MATCH (c:Control" in queries[0]
    assert "MAPS_TO" in queries[0]
    assert not any("CREATE CONSTRAINT" in q for q in queries)


def test_cli_returns_nonzero_when_input_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    exit_code = _run_cli(["--input", str(missing)])
    assert exit_code == 1


def test_cli_success_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    input_path = tmp_path / "controls.jsonl"
    input_path.write_text("", encoding="utf-8")

    from grc_agent.schemas import IngestionResult

    fake_result = IngestionResult(source_name="neo4j_loader:nist_sp800_53")
    fake_result.record_success(count=3)
    fake_result.finish()

    with patch("grc_agent.loaders.neo4j_loader.run", return_value=fake_result):
        exit_code = _run_cli(["--input", str(input_path)])

    assert exit_code == 0
    assert "Loaded 3 controls" in capsys.readouterr().out


def test_cli_success_path_for_non_default_record_type(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "cwe.jsonl"
    input_path.write_text("", encoding="utf-8")

    from grc_agent.schemas import IngestionResult

    fake_result = IngestionResult(source_name="neo4j_loader:mitre_cwe")
    fake_result.record_success(count=4)
    fake_result.finish()

    with patch("grc_agent.loaders.neo4j_loader.run", return_value=fake_result) as mock_run:
        exit_code = _run_cli(["--input", str(input_path), "--record-type", "weakness"])

    mock_run.assert_called_once_with(input_path, "weakness")
    assert exit_code == 0
    assert "Loaded 4 weaknesses" in capsys.readouterr().out


def test_cli_returns_nonzero_when_run_raises(tmp_path: Path) -> None:
    input_path = tmp_path / "controls.jsonl"
    input_path.write_text("", encoding="utf-8")

    with patch("grc_agent.loaders.neo4j_loader.run", side_effect=ConnectionError("no db")):
        exit_code = _run_cli(["--input", str(input_path)])

    assert exit_code == 1
