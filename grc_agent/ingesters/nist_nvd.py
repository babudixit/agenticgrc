"""Bulk-ingest NVD CVE records (by publication date range) into UnifiedVulnerability records.

Fetches from the NVD CVE 2.0 REST API, paginating within NVD's own 120-day
date-range window limit, and writes one UnifiedVulnerability per line to a
JSON-Lines file. Part of the Deliverable 5 reference-data expansion — this is
the "CVE" leg of the CVE->CWE->ATT&CK->Controls traversal chain.

Scope (per user decision): bulk ingestion by publication date range (e.g. the
last 2 years), not a targeted per-CVE-ID lookup — that path belongs to the
mapping agent (Deliverable 5's `agents/mapping_agent.py`), which will query
already-loaded graph data instead of hitting the NVD API live per finding.

API notes (see the real API at services.nvd.nist.gov/rest/json/cves/2.0):
- A single request's `pubStartDate`/`pubEndDate` window cannot exceed 120
  consecutive days — `_date_windows()` chunks an arbitrary range accordingly.
- Pagination within a window uses `startIndex`/`resultsPerPage`
  (`resultsPerPage` maxes out at 2000); the response's `totalResults` and
  `resultsPerPage` together tell us when a window is exhausted.
- The public rate limit is 5 requests/30s; an API key raises it to 50
  requests/30s (NFR: `NVD_API_KEY` in `.env`, optional but strongly
  recommended for a multi-year bulk pull). `request_delay` defaults
  accordingly and is only overridable for tests.
- `weaknesses[].description[].value` sometimes holds an NVD placeholder like
  `NVD-CWE-noinfo` instead of a real CWE ID — these are filtered out rather
  than passed to `UnifiedVulnerability`, which would otherwise reject them.
- `configurations` is an arbitrarily nested tree of AND/OR condition nodes;
  `_extract_cpes()` walks it structurally (via generic dict/list recursion)
  instead of assuming a fixed nesting depth, so deeply-nested boolean
  configurations don't get silently truncated.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import requests
import structlog

from grc_agent.config.settings import get_settings
from grc_agent.schemas import IngestionResult, Severity, UnifiedVulnerability

logger = structlog.get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120
DEFAULT_RESULTS_PER_PAGE = 2000
DEFAULT_OUTPUT_PATH = Path("data/nvd_cves.jsonl")

# A real CWE ID, as opposed to NVD placeholders like "NVD-CWE-noinfo"/"NVD-CWE-Other".
_CWE_ID_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

_RATE_LIMITED_DELAY_WITH_KEY = 0.7
_RATE_LIMITED_DELAY_WITHOUT_KEY = 6.5

_CVSS_SEVERITY_MAP: dict[str, Severity] = {
    "NONE": Severity.INFORMATIONAL,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _date_windows(
    start: datetime, end: datetime, *, max_days: int = MAX_WINDOW_DAYS
) -> Iterator[tuple[datetime, datetime]]:
    """Split [start, end] into consecutive, non-overlapping windows of at most `max_days`."""
    step = timedelta(days=max_days)
    window_start = start
    while window_start < end:
        window_end = min(window_start + step, end)
        yield window_start, window_end
        window_start = window_end + timedelta(milliseconds=1)


def _format_nvd_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    for entry in descriptions:
        if entry.get("lang") == "en":
            value: str = entry.get("value", "")
            return value
    return descriptions[0].get("value", "") if descriptions else ""


def _pick_primary_metric(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0] if entries else None


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, Severity | None, float | None]:
    v3_score: float | None = None
    v3_severity: Severity | None = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            metric = _pick_primary_metric(entries)
            data = (metric or {}).get("cvssData", {})
            v3_score = data.get("baseScore")
            base_severity = data.get("baseSeverity")
            v3_severity = _CVSS_SEVERITY_MAP.get(base_severity) if base_severity else None
            break

    v2_score: float | None = None
    v2_entries = metrics.get("cvssMetricV2")
    if v2_entries:
        metric = _pick_primary_metric(v2_entries)
        v2_score = (metric or {}).get("cvssData", {}).get("baseScore")

    return v3_score, v3_severity, v2_score


def _extract_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if _CWE_ID_RE.match(value):
                cwes.append(value)
    return cwes


def _extract_cpes(configurations: list[dict[str, Any]]) -> list[str]:
    """Walk an arbitrarily nested `configurations` tree, collecting every CPE criteria string."""
    cpes: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria:
                    cpes.append(criteria)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(configurations)
    return cpes


def _extract_references(references: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for ref in references:
        url = ref.get("url")
        if url:
            seen.setdefault(url, None)
    return list(seen.keys())


def parse_cve(raw: dict[str, Any], *, ingester_run_id: str | None = None) -> UnifiedVulnerability:
    """Parse a single raw NVD `cve` object (already loaded as a dict) into a UnifiedVulnerability.

    A pure, network-free function so it can be unit-tested directly against
    fixture dicts — all I/O (fetching, pagination, writing) happens outside it.
    """
    v3_score, v3_severity, v2_score = _extract_cvss(raw.get("metrics", {}))

    return UnifiedVulnerability(
        cve_id=raw["id"],
        description=_extract_description(raw.get("descriptions", [])),
        cvss_v3_score=v3_score,
        cvss_v3_severity=v3_severity,
        cvss_v2_score=v2_score,
        cwes=_extract_cwes(raw.get("weaknesses", [])),
        cpes=_extract_cpes(raw.get("configurations", [])),
        published_date=raw.get("published"),
        last_modified_date=raw.get("lastModified"),
        references=_extract_references(raw.get("references", [])),
        raw_source=raw,
        ingester_run_id=ingester_run_id,
    )


def fetch_cve_page(
    *,
    pub_start_date: str,
    pub_end_date: str,
    start_index: int,
    results_per_page: int,
    api_key: str | None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Fetch a single page of the NVD CVE 2.0 API response for one date window."""
    headers = {"apiKey": api_key} if api_key else {}
    params: dict[str, str | int] = {
        "pubStartDate": pub_start_date,
        "pubEndDate": pub_end_date,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    return dict(response.json())


def _fetch_page_with_retry(
    *,
    pub_start_date: str,
    pub_end_date: str,
    start_index: int,
    results_per_page: int,
    api_key: str | None,
    max_retries: int,
) -> dict[str, Any]:
    for attempt in range(max_retries):
        try:
            return fetch_cve_page(
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                start_index=start_index,
                results_per_page=results_per_page,
                api_key=api_key,
            )
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (403, 429) and attempt < max_retries - 1:
                backoff = 2**attempt * 2.0
                logger.warning("nvd_rate_limited_retrying", status=status, backoff_seconds=backoff)
                time.sleep(backoff)
                continue
            raise
    raise RuntimeError("unreachable: retry loop exited without returning or raising")


def fetch_all_cves(
    *,
    start_date: datetime,
    end_date: datetime,
    api_key: str | None = None,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
    request_delay: float | None = None,
    max_retries: int = 5,
) -> Iterator[dict[str, Any]]:
    """Yield every raw CVE dict published in [start_date, end_date], across all pages/windows."""
    delay = request_delay
    if delay is None:
        delay = _RATE_LIMITED_DELAY_WITH_KEY if api_key else _RATE_LIMITED_DELAY_WITHOUT_KEY

    for window_start, window_end in _date_windows(start_date, end_date):
        pub_start = _format_nvd_datetime(window_start)
        pub_end = _format_nvd_datetime(window_end)
        logger.info("nvd_fetching_window", pub_start_date=pub_start, pub_end_date=pub_end)

        start_index = 0
        while True:
            data = _fetch_page_with_retry(
                pub_start_date=pub_start,
                pub_end_date=pub_end,
                start_index=start_index,
                results_per_page=results_per_page,
                api_key=api_key,
                max_retries=max_retries,
            )
            for item in data.get("vulnerabilities", []):
                yield item["cve"]

            per_page = data.get("resultsPerPage", 0)
            total = data.get("totalResults", 0)
            start_index += per_page
            time.sleep(delay)
            if per_page == 0 or start_index >= total:
                break


def run(
    *,
    start_date: datetime,
    end_date: datetime,
    output_path: Path,
    api_key: str | None = None,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
    request_delay: float | None = None,
) -> IngestionResult:
    result = IngestionResult(source_name="nist_nvd")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for raw_cve in fetch_all_cves(
            start_date=start_date,
            end_date=end_date,
            api_key=api_key,
            results_per_page=results_per_page,
            request_delay=request_delay,
        ):
            try:
                vuln = parse_cve(raw_cve, ingester_run_id=result.run_id)
                f.write(vuln.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue, don't abort the run
                result.record_error(f"{raw_cve.get('id', '?')}: {exc}")
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "nist_nvd_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk-ingest NVD CVEs (by publication date range) into "
        "UnifiedVulnerability JSON-Lines."
    )
    parser.add_argument("--start-date", required=True, help="Inclusive window start, YYYY-MM-DD.")
    parser.add_argument("--end-date", required=True, help="Inclusive window end, YYYY-MM-DD.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key (default: NVD_API_KEY from .env/environment, if set).",
    )
    parser.add_argument("--results-per-page", type=int, default=DEFAULT_RESULTS_PER_PAGE)
    args = parser.parse_args(argv)

    api_key = args.api_key
    if api_key is None:
        settings_key = get_settings().nvd_api_key
        api_key = settings_key.get_secret_value() if settings_key else None

    try:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=UTC)
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").replace(tzinfo=UTC)
        result = run(
            start_date=start_date,
            end_date=end_date,
            output_path=args.output,
            api_key=api_key,
            results_per_page=args.results_per_page,
        )
    except (requests.RequestException, OSError, ValueError, KeyError) as exc:
        logger.error("nist_nvd_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_nvd_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} CVEs to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
