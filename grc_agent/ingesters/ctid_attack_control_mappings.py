"""Ingest the CTID ATT&CK-to-NIST-800-53 mapping dataset into AttackControlMapping records.

Fetches the Center for Threat-Informed Defense (CTID) "Mappings Explorer"
NIST SP 800-53 Rev 5 mapping file, parses it deterministically, and writes
one AttackControlMapping per line to a JSON-Lines file. This is what closes
the CVE->CWE->ATT&CK->Controls traversal chain (per user decision): without
it, `UnifiedAttackTechnique` nodes have no edge back into the control graph.

Parsing notes (see the real dataset at github.com/center-for-threat-informed-defense/
mappings-explorer, path `mappings/nist_800_53/attack-<version>/nist_800_53-rev5/enterprise/`):
- The file is `{"metadata": {...}, "mapping_objects": [...]}`; each mapping
  object pairs one ATT&CK technique/sub-technique with one NIST control.
- `status` is either `"complete"` (a real, human-reviewed mapping) or
  `"non_mappable"` (CTID explicitly determined ATT&CK has no mitigating
  control for this technique) — only `"complete"` entries carry a
  `capability_id` and are worth an edge; `"non_mappable"` ones are skipped.
- `capability_id` uses zero-padded two-digit control numbers (e.g. `"AC-02"`,
  `"CM-03"`), which doesn't match this project's own `control_id` convention
  (`"AC-2"`, from the OSCAL ingester's canonical labels) — normalized here so
  the loader's control lookup actually matches existing `(:Control)` nodes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import structlog

from grc_agent.schemas import AttackControlMapping, Framework, IngestionResult

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "mappings-explorer/main/mappings/nist_800_53/attack-16.1/nist_800_53-rev5/"
    "enterprise/nist_800_53-rev5_attack-16.1-enterprise.json"
)
DEFAULT_OUTPUT_PATH = Path("data/attack_control_mappings.jsonl")

_COMPLETE_STATUS = "complete"
_ZERO_PADDED_CONTROL_NUMBER = re.compile(r"-0*(\d)")


def fetch_mappings(source: str, *, timeout: float = 60.0) -> dict[str, Any]:
    """Load the CTID mapping document from a local file path or an HTTP(S) URL."""
    if source.startswith(("http://", "https://")):
        logger.info("fetching_ctid_mappings", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        return dict(response.json())

    path = Path(source)
    logger.info("reading_ctid_mappings", source=str(path))
    with path.open("r", encoding="utf-8") as f:
        return dict(json.load(f))


def _normalize_control_id(capability_id: str) -> str:
    """'AC-02' -> 'AC-2', matching the OSCAL ingester's canonical control_id form."""
    return _ZERO_PADDED_CONTROL_NUMBER.sub(r"-\1", capability_id)


def parse_mappings(
    doc: dict[str, Any],
    *,
    ingester_run_id: str | None = None,
) -> Iterator[AttackControlMapping]:
    """Parse a CTID mapping document (already loaded as a dict) into AttackControlMapping records.

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, writing) happens outside this function.
    """
    for obj in doc.get("mapping_objects", []):
        if obj.get("status") != _COMPLETE_STATUS:
            continue
        capability_id = obj.get("capability_id")
        if not capability_id:
            logger.warning(
                "ctid_mapping_missing_capability_id_despite_complete_status",
                attack_object_id=obj.get("attack_object_id"),
            )
            continue

        yield AttackControlMapping(
            technique_id=obj["attack_object_id"],
            control_id=_normalize_control_id(capability_id),
            control_framework=Framework.NIST_SP_800_53_R5,
            mapping_type=obj.get("mapping_type") or "mitigates",
            comments=obj.get("comments") or None,
            raw_source=obj,
            ingester_run_id=ingester_run_id,
        )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="ctid_attack_control_mappings")
    doc = fetch_mappings(source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for mapping in parse_mappings(doc, ingester_run_id=result.run_id):
            try:
                f.write(mapping.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue, don't abort the run
                result.record_error(f"{mapping.technique_id}->{mapping.control_id}: {exc}")
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "ctid_attack_control_mappings_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the CTID ATT&CK-to-NIST-800-53 mapping dataset into "
        "AttackControlMapping JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="CTID mapping JSON URL or local file path (default: the mappings-explorer mirror).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    try:
        result = run(args.source, args.output)
    except (requests.RequestException, OSError, KeyError) as exc:
        logger.error("ctid_attack_control_mappings_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "ctid_attack_control_mappings_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} mappings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
