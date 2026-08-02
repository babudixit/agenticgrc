"""Normalize Tenable.io vulnerability-scan findings into UnifiedFinding records.

Vendor field mapping notes (see tests/normalizers/fixtures/tenable_vulns_export.json
for a real, representative export):

- `finding_id` is built as '<source>:<plugin.id>:<asset-identifier>' — Tenable's
  plugin ID identifies the *check* (many assets can share one plugin ID), so
  the asset identifier is required to make the finding globally unique.
- `severity` (top-level, e.g. "high") is authoritative and gets normalized to
  our canonical scale; `plugin.risk_factor` is a separate, sometimes-divergent
  Tenable rating and is deliberately not used for normalization — only
  `severity` is preserved verbatim as `vendor_severity` (FR-208).
- `description` combines Tenable's generic `plugin.description` with the
  per-host `output` text (installed/fixed version, specific config values,
  etc.), since `output` is often the single most audit-useful piece of
  evidence for *this* asset and there's no separate "evidence" field in
  UnifiedFinding.
- `timestamp` prefers `last_found` (most recent confirmation the finding is
  still present) over `first_found` over `indexed_at`.
- Tenable's standard vulnerability export has no CWE mapping, and scanner
  findings don't carry ATT&CK technique IDs directly (see UnifiedFinding's
  own docstring) — both are left as empty lists here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import structlog

from grc_agent.schemas import IngestionResult, Severity, SourceClass, UnifiedFinding

logger = structlog.get_logger(__name__)

DEFAULT_OUTPUT_PATH = Path("data/tenable_findings.jsonl")

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
}


def _normalize_severity(raw_severity: str) -> Severity:
    key = raw_severity.strip().lower()
    try:
        return _SEVERITY_MAP[key]
    except KeyError:
        raise ValueError(
            f"Unrecognized Tenable severity: {raw_severity!r} "
            f"(expected one of {sorted(_SEVERITY_MAP)})"
        ) from None


def _asset_identifier(asset: dict[str, Any]) -> str:
    identifier = (
        asset.get("hostname")
        or asset.get("fqdn")
        or asset.get("ipv4")
        or asset.get("ipv6")
        or asset.get("uuid")
    )
    if not identifier:
        raise ValueError("Tenable finding's asset has no hostname, fqdn, ipv4, ipv6, or uuid")
    return str(identifier)


def _timestamp(finding: dict[str, Any]) -> str:
    timestamp = finding.get("last_found") or finding.get("first_found") or finding.get("indexed_at")
    if not timestamp:
        raise ValueError("Tenable finding has no last_found, first_found, or indexed_at")
    return str(timestamp)


def _build_description(plugin: dict[str, Any], output: str | None) -> str:
    description = (plugin.get("description") or "").strip()
    if output and output.strip():
        description = f"{description}\n\nScan output:\n{output.strip()}"
    return description


def normalize_finding(raw: dict[str, Any], *, ingester_run_id: str | None = None) -> UnifiedFinding:
    """Convert one raw Tenable.io finding dict (one element of a `findings` export) into a
    UnifiedFinding. Raises ValueError/pydantic.ValidationError on unrecoverably malformed input.
    """
    plugin = raw.get("plugin") or {}
    asset = raw.get("asset") or {}

    plugin_id = plugin.get("id")
    if plugin_id is None:
        raise ValueError("Tenable finding is missing plugin.id")

    asset_id = _asset_identifier(asset)
    raw_severity = raw.get("severity")
    if not raw_severity:
        raise ValueError(f"Tenable finding for plugin {plugin_id} is missing 'severity'")

    return UnifiedFinding(
        finding_id=f"tenable:{plugin_id}:{asset_id}",
        source_system="Tenable.io",
        source_class=SourceClass.VULNERABILITY_SCANNER,
        source_finding_id=str(plugin_id),
        timestamp=_timestamp(raw),  # type: ignore[arg-type]  # pydantic parses the ISO string
        severity=_normalize_severity(raw_severity),
        vendor_severity=raw_severity,
        title=plugin.get("name", ""),
        description=_build_description(plugin, raw.get("output")),
        affected_assets=[asset_id],
        cves=plugin.get("cve") or [],
        cwes=[],
        cpes=plugin.get("cpe") or [],
        mitre_techniques=[],
        recommended_remediation=plugin.get("solution") or None,
        raw_source=raw,
        ingester_run_id=ingester_run_id,
    )


def read_export(path: Path) -> list[dict[str, Any]]:
    """Read a Tenable export file, supporting both a top-level {'findings': [...]}
    wrapper and a bare JSON array of finding objects.
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "findings" in data:
        return list(data["findings"])
    if isinstance(data, list):
        return data
    raise ValueError(
        f"Unrecognized Tenable export format in {path}: expected a top-level "
        "'findings' array or a bare JSON array of finding objects."
    )


def run(input_path: Path, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="tenable")
    raw_findings = read_export(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for raw in raw_findings:
            try:
                finding = normalize_finding(raw, ingester_run_id=result.run_id)
            except (ValueError, KeyError) as exc:
                plugin_id = (raw.get("plugin") or {}).get("id", "unknown")
                result.record_error(f"plugin {plugin_id}: {exc}")
                continue
            f.write(finding.model_dump_json() + "\n")
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "tenable_normalization_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a Tenable.io vulnerability export into UnifiedFinding JSON-Lines."
    )
    parser.add_argument(
        "--input", type=Path, required=True, help="Path to the Tenable export JSON file."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("tenable_normalizer_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input, args.output)
    except (OSError, ValueError) as exc:
        logger.error("tenable_normalizer_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "tenable_normalizer_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} findings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
