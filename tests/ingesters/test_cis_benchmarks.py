"""Tests for the CIS Benchmark recommendation spreadsheet ingester.

Uses a hand-crafted minimal .xlsx fixture with OOXML inlineStr cells
(matching the real CIS Benchmark exports). No live network calls; copyrighted
CIS content is never committed — only this tiny synthetic sample.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from grc_agent.ingesters.cis_benchmarks import (
    normalize_attack_technique_id,
    normalize_nist_control_id,
    parse_benchmark_file,
    parse_benchmark_filename,
    parse_list_cell,
    run,
)
from grc_agent.schemas import (
    AttackControlMapping,
    ControlControlMapping,
    Framework,
    UnifiedControl,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cis_benchmark_sample.xlsx"
SAMPLE_FILENAME = "CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.xlsx"


@pytest.fixture
def benchmark_dir(tmp_path: Path) -> Path:
    dest = tmp_path / SAMPLE_FILENAME
    shutil.copy(FIXTURE_PATH, dest)
    return tmp_path


def test_parse_benchmark_filename() -> None:
    meta = parse_benchmark_filename(Path(SAMPLE_FILENAME))
    assert meta is not None
    assert meta.product_slug == "ubuntu_linux_24.04_lts"
    assert meta.version == "1.0.0"
    assert "Ubuntu" in meta.product_title

    pdf_meta = parse_benchmark_filename(Path("CIS_GitHub_Benchmark_v1.2.0_PDF.xlsx"))
    assert pdf_meta is not None
    assert pdf_meta.product_slug == "github"
    assert pdf_meta.version == "1.2.0"


def test_parse_list_cell_python_repr_and_json() -> None:
    assert parse_list_cell("['CM-7', 'CE-12345']") == ["CM-7", "CE-12345"]
    assert parse_list_cell('["T1190"]') == ["T1190"]
    assert parse_list_cell("[]") == []
    assert parse_list_cell(None) == []


def test_normalize_nist_skips_cis_assessment_ids() -> None:
    assert normalize_nist_control_id("CM-7") == "CM-7"
    assert normalize_nist_control_id("AC-02") == "AC-2"
    assert normalize_nist_control_id("AC-02(03)") == "AC-2(3)"
    assert normalize_nist_control_id("CE-12345") is None
    assert normalize_nist_control_id("VP-9501") is None
    assert normalize_nist_control_id("VE-2016") is None


def test_normalize_attack_technique_id() -> None:
    assert normalize_attack_technique_id("T1190") == "T1190"
    assert normalize_attack_technique_id("t1059.001") == "T1059.001"
    assert normalize_attack_technique_id("not-a-tech") is None


def test_parse_benchmark_file_emits_controls_and_edges(benchmark_dir: Path) -> None:
    meta = parse_benchmark_filename(benchmark_dir / SAMPLE_FILENAME)
    assert meta is not None
    controls, nist_maps, attack_maps = parse_benchmark_file(
        meta, ingester_run_id="test-cis-bench"
    )

    assert len(controls) == 3
    assert all(c.framework is Framework.CIS_BENCHMARK for c in controls)
    assert {c.control_id for c in controls} == {
        "ubuntu_linux_24.04_lts:1.1.1",
        "ubuntu_linux_24.04_lts:1.1.2",
        "ubuntu_linux_24.04_lts:2.1",
    }
    assert all(c.ingester_run_id == "test-cis-bench" for c in controls)

    nist_pairs = {(m.source_control_id, m.target_control_id) for m in nist_maps}
    assert nist_pairs == {
        ("ubuntu_linux_24.04_lts:1.1.1", "CM-7"),
        ("ubuntu_linux_24.04_lts:1.1.2", "AC-2"),
        ("ubuntu_linux_24.04_lts:1.1.2", "CM-7"),
    }
    assert all(m.source_framework is Framework.CIS_BENCHMARK for m in nist_maps)
    assert all(m.target_framework is Framework.NIST_SP_800_53_R5 for m in nist_maps)

    assert len(attack_maps) == 1
    assert attack_maps[0].technique_id == "T1190"
    assert attack_maps[0].control_id == "ubuntu_linux_24.04_lts:1.1.2"
    assert attack_maps[0].control_framework is Framework.CIS_BENCHMARK


def test_run_writes_three_jsonl_files(benchmark_dir: Path, tmp_path: Path) -> None:
    controls_out = tmp_path / "controls.jsonl"
    nist_out = tmp_path / "nist.jsonl"
    attack_out = tmp_path / "attack.jsonl"

    outputs = run(benchmark_dir, controls_out, nist_out, attack_out)

    assert outputs.controls.success is True
    assert outputs.controls.records_written == 3
    assert outputs.nist_mappings.records_written == 3
    assert outputs.attack_mappings.records_written == 1

    restored_controls = [
        UnifiedControl.model_validate_json(line)
        for line in controls_out.read_text(encoding="utf-8").splitlines()
    ]
    restored_nist = [
        ControlControlMapping.model_validate_json(line)
        for line in nist_out.read_text(encoding="utf-8").splitlines()
    ]
    restored_attack = [
        AttackControlMapping.model_validate_json(line)
        for line in attack_out.read_text(encoding="utf-8").splitlines()
    ]
    assert len(restored_controls) == 3
    assert len(restored_nist) == 3
    assert len(restored_attack) == 1
