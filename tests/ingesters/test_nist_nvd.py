"""Tests for the NVD bulk CVE ingester.

`parse_cve` is exercised against real-shaped fixture dicts (see
tests/ingesters/fixtures/nvd_sample_cves.json). Pagination, date-windowing,
and retry logic are exercised with mocked `requests.get`/`time.sleep` calls —
no live network calls are made anywhere in this file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from grc_agent.ingesters.nist_nvd import (
    _date_windows,
    _run_cli,
    fetch_all_cves,
    fetch_cve_page,
    parse_cve,
    run,
)
from grc_agent.schemas import Severity, UnifiedVulnerability

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "nvd_sample_cves.json"


@pytest.fixture
def raw_cves() -> list[dict]:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def test_parse_cve_with_cvss_v3_cwes_cpes_and_dedup_references(raw_cves: list[dict]) -> None:
    vuln = parse_cve(raw_cves[0], ingester_run_id="test-run-123")

    assert vuln.cve_id == "CVE-2024-21732"
    assert vuln.description.startswith("FlyCms")
    assert vuln.cvss_v3_score == pytest.approx(6.1)
    assert vuln.cvss_v3_severity is Severity.MEDIUM
    assert vuln.cwes == ["CWE-79"]
    assert vuln.cpes == ["cpe:2.3:a:flycms_project:flycms:*:*:*:*:*:*:*:*"]
    assert vuln.references == ["https://github.com/Ghostfox2003/cms/blob/main/1.md"]
    assert vuln.ingester_run_id == "test-run-123"


def test_parse_cve_falls_back_to_cvss_v2(raw_cves: list[dict]) -> None:
    vuln = parse_cve(raw_cves[1])

    assert vuln.cve_id == "CVE-2003-0001"
    assert vuln.cvss_v3_score is None
    assert vuln.cvss_v3_severity is None
    assert vuln.cvss_v2_score == pytest.approx(5.0)


def test_parse_cve_filters_out_nvd_placeholder_cwe(raw_cves: list[dict]) -> None:
    vuln = parse_cve(raw_cves[2])

    assert vuln.cve_id == "CVE-2024-99999"
    assert vuln.cwes == []


def test_parse_cve_raw_source_preserves_original(raw_cves: list[dict]) -> None:
    vuln = parse_cve(raw_cves[0])
    assert vuln.raw_source == raw_cves[0]


def test_date_windows_splits_on_120_day_boundary() -> None:
    from datetime import timedelta

    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 6, 1, tzinfo=UTC)  # 152 days -> 2 windows

    windows = list(_date_windows(start, end))

    assert len(windows) == 2
    assert windows[0] == (start, start + timedelta(days=120))
    # Windows must not overlap: the next window starts 1ms after the previous ended.
    assert windows[1] == (start + timedelta(days=120, milliseconds=1), end)


def test_date_windows_covers_full_range_without_gaps_or_overlap() -> None:
    start = datetime(2022, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 1, tzinfo=UTC)  # ~2 years -> 6 windows

    windows = list(_date_windows(start, end))

    assert windows[0][0] == start
    assert windows[-1][1] == end
    for (_, prev_end), (next_start, _) in zip(windows, windows[1:], strict=False):
        assert (next_start - prev_end).total_seconds() == pytest.approx(0.001)


def test_date_windows_single_window_when_within_limit() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 2, 1, tzinfo=UTC)

    windows = list(_date_windows(start, end))

    assert windows == [(start, end)]


def test_fetch_cve_page_sends_api_key_header_when_provided() -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulnerabilities": [],
        "resultsPerPage": 0,
        "totalResults": 0,
    }
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        fetch_cve_page(
            pub_start_date="2024-01-01T00:00:00.000",
            pub_end_date="2024-01-02T00:00:00.000",
            start_index=0,
            results_per_page=2000,
            api_key="test-key",
        )

    _, kwargs = mock_get.call_args
    assert kwargs["headers"] == {"apiKey": "test-key"}


def test_fetch_cve_page_omits_header_without_api_key() -> None:
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulnerabilities": [],
        "resultsPerPage": 0,
        "totalResults": 0,
    }
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response) as mock_get:
        fetch_cve_page(
            pub_start_date="2024-01-01T00:00:00.000",
            pub_end_date="2024-01-02T00:00:00.000",
            start_index=0,
            results_per_page=2000,
            api_key=None,
        )

    _, kwargs = mock_get.call_args
    assert kwargs["headers"] == {}


def test_fetch_all_cves_paginates_within_a_single_window(raw_cves: list[dict]) -> None:
    page1 = MagicMock()
    page1.json.return_value = {
        "vulnerabilities": [{"cve": raw_cves[0]}],
        "resultsPerPage": 1,
        "totalResults": 2,
    }
    page1.raise_for_status.return_value = None
    page2 = MagicMock()
    page2.json.return_value = {
        "vulnerabilities": [{"cve": raw_cves[1]}],
        "resultsPerPage": 1,
        "totalResults": 2,
    }
    page2.raise_for_status.return_value = None

    with (
        patch("requests.get", side_effect=[page1, page2]) as mock_get,
        patch("time.sleep") as mock_sleep,
    ):
        results = list(
            fetch_all_cves(
                start_date=datetime(2024, 1, 1, tzinfo=UTC),
                end_date=datetime(2024, 1, 15, tzinfo=UTC),
                api_key="test-key",
                results_per_page=1,
            )
        )

    assert [r["id"] for r in results] == ["CVE-2024-21732", "CVE-2003-0001"]
    assert mock_get.call_count == 2
    assert mock_sleep.call_count == 2


def test_fetch_all_cves_retries_on_rate_limit_then_succeeds(raw_cves: list[dict]) -> None:
    rate_limited = MagicMock()
    http_error = requests.exceptions.HTTPError(response=MagicMock(status_code=429))
    rate_limited.raise_for_status.side_effect = http_error

    success = MagicMock()
    success.json.return_value = {
        "vulnerabilities": [{"cve": raw_cves[0]}],
        "resultsPerPage": 1,
        "totalResults": 1,
    }
    success.raise_for_status.return_value = None

    with (
        patch("requests.get", side_effect=[rate_limited, success]),
        patch("time.sleep") as mock_sleep,
    ):
        results = list(
            fetch_all_cves(
                start_date=datetime(2024, 1, 1, tzinfo=UTC),
                end_date=datetime(2024, 1, 15, tzinfo=UTC),
                api_key="test-key",
                max_retries=3,
            )
        )

    assert [r["id"] for r in results] == ["CVE-2024-21732"]
    assert mock_sleep.called  # backoff sleep + rate-limit-pacing sleep


def test_run_end_to_end_writes_valid_jsonlines(raw_cves: list[dict], tmp_path: Path) -> None:
    page = MagicMock()
    page.json.return_value = {
        "vulnerabilities": [{"cve": c} for c in raw_cves],
        "resultsPerPage": 3,
        "totalResults": 3,
    }
    page.raise_for_status.return_value = None
    output_path = tmp_path / "nvd_cves.jsonl"

    with patch("requests.get", return_value=page), patch("time.sleep"):
        result = run(
            start_date=datetime(2024, 1, 1, tzinfo=UTC),
            end_date=datetime(2024, 2, 1, tzinfo=UTC),
            output_path=output_path,
            api_key="test-key",
        )

    assert result.success is True
    assert result.records_written == 3
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    restored = [UnifiedVulnerability.model_validate_json(line) for line in lines]
    assert {v.cve_id for v in restored} == {"CVE-2024-21732", "CVE-2003-0001", "CVE-2024-99999"}


def test_cli_success_exit_code(raw_cves: list[dict], tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    page = MagicMock()
    page.json.return_value = {
        "vulnerabilities": [{"cve": raw_cves[0]}],
        "resultsPerPage": 1,
        "totalResults": 1,
    }
    page.raise_for_status.return_value = None
    output_path = tmp_path / "nvd_cves.jsonl"

    with patch("requests.get", return_value=page), patch("time.sleep"):
        exit_code = _run_cli(
            [
                "--start-date",
                "2024-01-01",
                "--end-date",
                "2024-01-31",
                "--output",
                str(output_path),
                "--api-key",
                "test-key",
            ]
        )

    assert exit_code == 0
    assert "Wrote 1 CVEs" in capsys.readouterr().out


def test_cli_returns_nonzero_for_invalid_date() -> None:
    exit_code = _run_cli(["--start-date", "not-a-date", "--end-date", "2024-01-31"])
    assert exit_code == 1
