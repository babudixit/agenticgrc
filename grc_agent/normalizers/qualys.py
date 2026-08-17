"""Normalize Qualys VM / host-detection findings into UnifiedFinding records.

Accepts a pragmatic JSON detection export (Qualys XML/API payloads are usually
converted to JSON before pipeline use). Supported shapes:

- `{"detections": [...]}` / `{"findings": [...]}` / bare JSON array
- Per-record fields commonly seen in Qualys Host Detection / KB-enriched
  exports: `qid`, `title`, `severity` (1–5 or named), `cve_list` /
  `cve_id_list`, optional `cwe`, `ip` / `dns` / `hostname`, `diagnosis` /
  `threat`, `solution`, `first_found` / `last_found`.

CVE-bearing detections feed the existing CVE→CWE→ATT&CK→Controls walkthrough;
compliance-style QIDs without CVEs still become UnifiedFindings for semantic /
policy mapping later.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import structlog

from grc_agent.normalizers._common import (
    as_str_list,
    extract_cves,
    extract_cwes,
    first_nonempty,
    normalize_severity,
    read_json_records,
)
from grc_agent.schemas import IngestionResult, SourceClass, UnifiedFinding

logger = structlog.get_logger(__name__)

DEFAULT_OUTPUT_PATH = Path("data/qualys_findings.jsonl")


def _asset_identifier(raw: dict[str, Any]) -> str:
    identifier = first_nonempty(
        raw.get("hostname"),
        raw.get("dns"),
        raw.get("fqdn"),
        raw.get("ip"),
        raw.get("ip_address"),
        raw.get("host_id"),
        (raw.get("asset") or {}).get("hostname") if isinstance(raw.get("asset"), dict) else None,
        (raw.get("asset") or {}).get("ip") if isinstance(raw.get("asset"), dict) else None,
    )
    if not identifier:
        raise ValueError("Qualys finding has no hostname/dns/ip/host_id asset identifier")
    return identifier


def _timestamp(raw: dict[str, Any]) -> str:
    timestamp = first_nonempty(
        raw.get("last_found"),
        raw.get("last_found_datetime"),
        raw.get("LAST_FOUND_DATETIME"),
        raw.get("first_found"),
        raw.get("first_found_datetime"),
        raw.get("datetime"),
        raw.get("timestamp"),
    )
    if not timestamp:
        raise ValueError("Qualys finding has no last_found/first_found/timestamp")
    return timestamp


def _build_description(raw: dict[str, Any]) -> str:
    parts = [
        first_nonempty(raw.get("diagnosis"), raw.get("DIAGNOSIS"), raw.get("threat"), raw.get("THREAT")),
        first_nonempty(raw.get("consequence"), raw.get("CONSEQUENCE")),
        first_nonempty(raw.get("results"), raw.get("RESULT"), raw.get("output")),
    ]
    text = "\n\n".join(p for p in parts if p)
    return text or first_nonempty(raw.get("title"), raw.get("TITLE"), "(no description)") or ""


def normalize_finding(raw: dict[str, Any], *, ingester_run_id: str | None = None) -> UnifiedFinding:
    """Convert one Qualys detection dict into a UnifiedFinding."""
    qid = first_nonempty(raw.get("qid"), raw.get("QID"), raw.get("id"))
    if not qid:
        raise ValueError("Qualys finding is missing qid")

    title = first_nonempty(raw.get("title"), raw.get("TITLE"), f"Qualys QID {qid}")
    assert title is not None
    raw_severity = first_nonempty(
        raw.get("severity"),
        raw.get("SEVERITY"),
        raw.get("severity_level"),
    )
    asset_id = _asset_identifier(raw)
    vendor_severity = str(raw_severity)

    return UnifiedFinding(
        finding_id=f"qualys:{qid}:{asset_id}",
        source_system=first_nonempty(raw.get("source_system"), "Qualys VM") or "Qualys VM",
        source_class=SourceClass.VULNERABILITY_SCANNER,
        source_finding_id=str(qid),
        timestamp=_timestamp(raw),  # type: ignore[arg-type]
        severity=normalize_severity(raw_severity, vendor="Qualys"),
        vendor_severity=vendor_severity,
        title=title,
        description=_build_description(raw),
        affected_assets=[asset_id],
        cves=extract_cves(
            raw.get("cve_list"),
            raw.get("cve_id_list"),
            raw.get("CVE_ID_LIST"),
            raw.get("cves"),
            raw.get("cve"),
        ),
        cwes=extract_cwes(raw.get("cwe"), raw.get("cwe_list"), raw.get("cwes")),
        cpes=as_str_list(raw.get("cpe") or raw.get("cpes")),
        mitre_techniques=[],
        recommended_remediation=first_nonempty(
            raw.get("solution"), raw.get("SOLUTION"), raw.get("remediation")
        ),
        raw_source=raw,
        ingester_run_id=ingester_run_id,
    )


def read_export(path: Path) -> list[dict[str, Any]]:
    return read_json_records(
        path,
        vendor="Qualys",
        list_keys=("detections", "findings", "HOST_LIST_VM_DETECTION_OUTPUT", "results"),
    )


def run(input_path: Path, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="qualys")
    raw_findings = read_export(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for raw in raw_findings:
            try:
                finding = normalize_finding(raw, ingester_run_id=result.run_id)
            except (ValueError, KeyError, TypeError) as exc:
                qid = raw.get("qid") or raw.get("QID") or "unknown"
                result.record_error(f"qid {qid}: {exc}")
                continue
            f.write(finding.model_dump_json() + "\n")
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "qualys_normalization_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a Qualys detection export into UnifiedFinding JSON-Lines."
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to Qualys JSON export.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("qualys_normalizer_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input, args.output)
    except (OSError, ValueError) as exc:
        logger.error("qualys_normalizer_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "qualys_normalizer_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} findings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
