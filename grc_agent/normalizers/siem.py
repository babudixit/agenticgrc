"""Normalize generic SIEM alert exports into UnifiedFinding records.

SIEM products vary widely (Splunk ES, Elastic SIEM, Microsoft Sentinel, …).
This adapter accepts a *common alert envelope* rather than one proprietary
API dump — connectors upstream can reshape vendor alerts into this envelope
before calling the normalizer:

Required-ish fields: `alert_id`, `title`/`rule_name`, `severity`, `timestamp`.
Useful optional fields: `description`, `host`/`asset`/`device`,
`mitre_techniques` / `attack_techniques` / `tactic_technique`, `cves`,
`source_system`, `remediation`.

When ATT&CK technique IDs are present they become `mitre_techniques` with
`match_method=direct` later in the mapping agent — the main SIEM advantage
over scanner findings.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import structlog

from grc_agent.normalizers._common import (
    extract_cves,
    extract_cwes,
    extract_techniques,
    first_nonempty,
    normalize_severity,
    read_json_records,
)
from grc_agent.schemas import IngestionResult, SourceClass, UnifiedFinding

logger = structlog.get_logger(__name__)

DEFAULT_OUTPUT_PATH = Path("data/siem_findings.jsonl")


def _asset_identifier(raw: dict[str, Any]) -> str:
    host = raw.get("host")
    if isinstance(host, dict):
        host_name = first_nonempty(host.get("hostname"), host.get("name"), host.get("ip"))
    else:
        host_name = first_nonempty(host)

    identifier = first_nonempty(
        host_name,
        raw.get("hostname"),
        raw.get("asset"),
        raw.get("device"),
        raw.get("src_host"),
        raw.get("dest_host"),
        raw.get("computer_name"),
        raw.get("agent_id"),
    )
    if not identifier:
        # SIEM alerts are sometimes identity/cloud events without a host —
        # fall back to a stable synthetic asset so finding_id stays unique.
        return "siem-unscoped"
    return identifier


def _timestamp(raw: dict[str, Any]) -> str:
    timestamp = first_nonempty(
        raw.get("timestamp"),
        raw.get("@timestamp"),
        raw.get("event_time"),
        raw.get("detection_time"),
        raw.get("created"),
        raw.get("start"),
    )
    if not timestamp:
        raise ValueError("SIEM alert has no timestamp/@timestamp/event_time")
    return timestamp


def _build_description(raw: dict[str, Any]) -> str:
    parts = [
        first_nonempty(raw.get("description"), raw.get("message"), raw.get("summary")),
        first_nonempty(raw.get("rule_description")),
    ]
    extras = []
    for key in ("user", "src_ip", "dest_ip", "process_name", "command_line"):
        value = first_nonempty(raw.get(key))
        if value:
            extras.append(f"{key}={value}")
    if extras:
        parts.append("Context: " + ", ".join(extras))
    text = "\n\n".join(p for p in parts if p)
    return text or first_nonempty(raw.get("title"), raw.get("rule_name"), "(no description)") or ""


def normalize_finding(raw: dict[str, Any], *, ingester_run_id: str | None = None) -> UnifiedFinding:
    """Convert one SIEM alert envelope into a UnifiedFinding."""
    alert_id = first_nonempty(
        raw.get("alert_id"),
        raw.get("id"),
        raw.get("event_id"),
        raw.get("detection_id"),
    )
    if not alert_id:
        raise ValueError("SIEM alert is missing alert_id/id")

    title = first_nonempty(raw.get("title"), raw.get("rule_name"), raw.get("name"), f"SIEM alert {alert_id}")
    assert title is not None
    raw_severity = first_nonempty(raw.get("severity"), raw.get("risk_score_severity"), raw.get("urgency"))
    asset_id = _asset_identifier(raw)
    source_system = first_nonempty(raw.get("source_system"), raw.get("vendor"), "SIEM") or "SIEM"

    techniques = extract_techniques(
        raw.get("mitre_techniques"),
        raw.get("attack_techniques"),
        raw.get("technique_id"),
        raw.get("techniques"),
        raw.get("threat.technique.id") if isinstance(raw.get("threat"), dict) else None,
        (raw.get("threat") or {}).get("technique") if isinstance(raw.get("threat"), dict) else None,
    )
    # Nested Elastic-style threat.technique can be a list of objects with id=
    threat = raw.get("threat")
    if isinstance(threat, dict):
        technique_field = threat.get("technique")
        if isinstance(technique_field, list):
            for item in technique_field:
                if isinstance(item, dict):
                    techniques.extend(extract_techniques(item.get("id"), item.get("technique_id")))
                else:
                    techniques.extend(extract_techniques(item))
        elif isinstance(technique_field, dict):
            techniques.extend(
                extract_techniques(technique_field.get("id"), technique_field.get("technique_id"))
            )

    # Deduplicate while preserving order
    seen_tech: set[str] = set()
    unique_techniques: list[str] = []
    for tech in techniques:
        if tech not in seen_tech:
            seen_tech.add(tech)
            unique_techniques.append(tech)

    return UnifiedFinding(
        finding_id=f"siem:{alert_id}:{asset_id}",
        source_system=source_system,
        source_class=SourceClass.SIEM,
        source_finding_id=str(alert_id),
        timestamp=_timestamp(raw),  # type: ignore[arg-type]
        severity=normalize_severity(raw_severity, vendor="SIEM"),
        vendor_severity=str(raw_severity),
        title=title,
        description=_build_description(raw),
        affected_assets=[asset_id],
        cves=extract_cves(raw.get("cves"), raw.get("cve"), raw.get("vulnerability_ids")),
        cwes=extract_cwes(raw.get("cwes"), raw.get("cwe")),
        cpes=[],
        mitre_techniques=unique_techniques,
        recommended_remediation=first_nonempty(raw.get("remediation"), raw.get("recommended_action")),
        raw_source=raw,
        ingester_run_id=ingester_run_id,
    )


def read_export(path: Path) -> list[dict[str, Any]]:
    return read_json_records(
        path,
        vendor="SIEM",
        list_keys=("alerts", "findings", "hits", "results", "detections"),
    )


def run(input_path: Path, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="siem")
    raw_findings = read_export(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for raw in raw_findings:
            try:
                finding = normalize_finding(raw, ingester_run_id=result.run_id)
            except (ValueError, KeyError, TypeError) as exc:
                alert_id = raw.get("alert_id") or raw.get("id") or "unknown"
                result.record_error(f"alert {alert_id}: {exc}")
                continue
            f.write(finding.model_dump_json() + "\n")
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "siem_normalization_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a generic SIEM alert export into UnifiedFinding JSON-Lines."
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to SIEM alert JSON export.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("siem_normalizer_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input, args.output)
    except (OSError, ValueError) as exc:
        logger.error("siem_normalizer_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "siem_normalizer_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} findings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
