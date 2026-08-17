"""Normalize generic CSPM / cloud-security findings into UnifiedFinding records.

Covers a common envelope for tools like AWS Security Hub, Wiz, Prisma Cloud,
and Defender for Cloud after an upstream connector has flattened vendor JSON:

- `finding_id` / `id`, `title`, `severity`, `timestamp` / `UpdatedAt`
- `resource_id` / `resource.arn` / `cloud_resource_id` (asset)
- `description` / `description_text`
- optional `remediation`, `related_cves`, `compliance` / `control_ids`
- optional `source_system` / `product_name`

CSPM findings are often CVE-sparse; they still enter the same UnifiedFinding
→ mapping-agent path, leaning more on description + eventual control
crosswalks than on CVE→CWE graph hops.
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

DEFAULT_OUTPUT_PATH = Path("data/cspm_findings.jsonl")


def _resource_identifier(raw: dict[str, Any]) -> str:
    resource = raw.get("resource")
    resource_id = None
    if isinstance(resource, dict):
        resource_id = first_nonempty(
            resource.get("id"),
            resource.get("uid"),
            resource.get("arn"),
            resource.get("name"),
            resource.get("ResourceId"),
        )

    resources = raw.get("Resources")
    resources_id = None
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resources_id = first_nonempty(first.get("Id"), first.get("id"), first.get("Arn"))
        else:
            resources_id = str(first).strip() or None

    identifier = first_nonempty(
        resource_id,
        resources_id,
        raw.get("resource_id"),
        raw.get("cloud_resource_id"),
        raw.get("resourceArn"),
        raw.get("asset_id"),
    )
    if not identifier:
        raise ValueError("CSPM finding has no resource_id/arn/asset identifier")
    return str(identifier)


def _timestamp(raw: dict[str, Any]) -> str:
    timestamp = first_nonempty(
        raw.get("timestamp"),
        raw.get("UpdatedAt"),
        raw.get("updated_at"),
        raw.get("CreatedAt"),
        raw.get("created_at"),
        raw.get("FirstObservedAt"),
        raw.get("observed_at"),
    )
    if not timestamp:
        raise ValueError("CSPM finding has no timestamp/UpdatedAt/created_at")
    return timestamp


def _build_description(raw: dict[str, Any]) -> str:
    parts = [
        first_nonempty(
            raw.get("description"),
            raw.get("Description"),
            raw.get("description_text"),
            raw.get("message"),
        ),
        first_nonempty(raw.get("recommendation"), raw.get("RemediationText")),
    ]
    compliance = raw.get("compliance") or raw.get("Compliance")
    if isinstance(compliance, dict):
        status = first_nonempty(compliance.get("Status"), compliance.get("status"))
        related = compliance.get("RelatedRequirements") or compliance.get("controls")
        if status:
            parts.append(f"Compliance status: {status}")
        if related:
            parts.append(f"Related requirements: {related}")
    elif isinstance(compliance, list) and compliance:
        parts.append(f"Related requirements: {compliance}")

    text = "\n\n".join(p for p in parts if p)
    return text or first_nonempty(raw.get("title"), raw.get("Title"), "(no description)") or ""


def normalize_finding(raw: dict[str, Any], *, ingester_run_id: str | None = None) -> UnifiedFinding:
    """Convert one CSPM finding envelope into a UnifiedFinding."""
    source_finding_id = first_nonempty(
        raw.get("finding_id"),
        raw.get("Id"),
        raw.get("id"),
        raw.get("uid"),
        raw.get("alert_id"),
    )
    if not source_finding_id:
        raise ValueError("CSPM finding is missing finding_id/id")

    title = first_nonempty(raw.get("title"), raw.get("Title"), f"CSPM finding {source_finding_id}")
    assert title is not None
    # AWS Security Hub nests Severity as {"Label": "HIGH", ...}; others use a string.
    severity_obj = raw.get("Severity")
    nested_severity = None
    if isinstance(severity_obj, dict):
        nested_severity = first_nonempty(severity_obj.get("Label"), severity_obj.get("Normalized"))
    elif severity_obj is not None and not isinstance(severity_obj, (dict, list)):
        nested_severity = str(severity_obj)

    raw_severity = first_nonempty(
        raw.get("severity"),
        raw.get("severity_label"),
        nested_severity,
    )

    asset_id = _resource_identifier(raw)
    source_system = (
        first_nonempty(
            raw.get("source_system"),
            raw.get("ProductName"),
            raw.get("product_name"),
            raw.get("provider"),
            "CSPM",
        )
        or "CSPM"
    )

    remediation = raw.get("remediation") or raw.get("Remediation")
    if isinstance(remediation, dict):
        remediation_text = first_nonempty(
            remediation.get("text"),
            remediation.get("Recommendation"),
            remediation.get("recommendation"),
            (remediation.get("Recommendation") or {}).get("Text")
            if isinstance(remediation.get("Recommendation"), dict)
            else None,
        )
    else:
        remediation_text = first_nonempty(remediation)

    return UnifiedFinding(
        finding_id=f"cspm:{source_finding_id}:{asset_id}",
        source_system=source_system,
        source_class=SourceClass.CSPM,
        source_finding_id=str(source_finding_id),
        timestamp=_timestamp(raw),  # type: ignore[arg-type]
        severity=normalize_severity(raw_severity, vendor="CSPM"),
        vendor_severity=str(raw_severity),
        title=title,
        description=_build_description(raw),
        affected_assets=[asset_id],
        cves=extract_cves(
            raw.get("related_cves"),
            raw.get("cves"),
            raw.get("Vulnerabilities"),
            raw.get("cve"),
        ),
        cwes=extract_cwes(raw.get("cwes"), raw.get("cwe")),
        cpes=[],
        mitre_techniques=extract_techniques(
            raw.get("mitre_techniques"),
            raw.get("attack_techniques"),
            raw.get("types"),
        ),
        recommended_remediation=remediation_text,
        raw_source=raw,
        ingester_run_id=ingester_run_id,
    )


def read_export(path: Path) -> list[dict[str, Any]]:
    return read_json_records(
        path,
        vendor="CSPM",
        list_keys=("findings", "Findings", "alerts", "results", "items"),
    )


def run(input_path: Path, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="cspm")
    raw_findings = read_export(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for raw in raw_findings:
            try:
                finding = normalize_finding(raw, ingester_run_id=result.run_id)
            except (ValueError, KeyError, TypeError) as exc:
                fid = raw.get("finding_id") or raw.get("Id") or raw.get("id") or "unknown"
                result.record_error(f"finding {fid}: {exc}")
                continue
            f.write(finding.model_dump_json() + "\n")
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "cspm_normalization_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a generic CSPM finding export into UnifiedFinding JSON-Lines."
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to CSPM JSON export.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("cspm_normalizer_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input, args.output)
    except (OSError, ValueError) as exc:
        logger.error("cspm_normalizer_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "cspm_normalizer_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} findings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
