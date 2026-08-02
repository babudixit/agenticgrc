"""Ingest the MITRE ATT&CK Enterprise STIX bundle into UnifiedAttackTechnique records.

Fetches the ATT&CK Enterprise STIX 2.1 bundle (the community-maintained
`mitre-attack/attack-stix-data` mirror, updated on every ATT&CK release),
parses it deterministically, and writes one UnifiedAttackTechnique per line
to a JSON-Lines file. Part of the Deliverable 5 reference-data expansion.

Scope (per user decision): techniques, sub-techniques, and their tactics
only (~800 objects) — mitigations, groups, software, campaigns, and the
Mobile/ICS ATT&CK domains are all out of scope for Phase 1.

Parsing notes (see the real bundle at github.com/mitre-attack/attack-stix-data):
- A technique/sub-technique is an `attack-pattern` STIX object. Its stable,
  human-facing ID (e.g. "T1055.011") lives in `external_references`, in the
  entry whose `source_name == "mitre-attack"` — the STIX `id` field itself is
  an internal UUID-based identifier (`attack-pattern--<uuid>`) and is never
  used as the graph key.
- `revoked: true` and `x_mitre_deprecated: true` objects are both excluded:
  ATT&CK keeps them in the bundle for referential history, but they're
  superseded/retired and would otherwise pollute the graph with dead ends.
- A sub-technique's parent is derivable directly from its own ID
  (`T1055.011` -> `T1055`) — more reliable than resolving the separate
  `subtechnique-of` relationship objects, which point at STIX UUIDs that
  would need a second lookup pass.
- `kill_chain_phases` entries with `kill_chain_name == "mitre-attack"` give
  the technique's tactic(s), as short, kebab-case names (e.g.
  "privilege-escalation") that match ATT&CK's own tactic short names.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import structlog

from grc_agent.schemas import IngestionResult, UnifiedAttackTechnique

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT_PATH = Path("data/attack_techniques.jsonl")

_ATTACK_KILL_CHAIN = "mitre-attack"
_ATTACK_SOURCE_NAME = "mitre-attack"


def fetch_bundle(source: str, *, timeout: float = 120.0) -> dict[str, Any]:
    """Load the STIX bundle JSON from a local file path or an HTTP(S) URL."""
    if source.startswith(("http://", "https://")):
        logger.info("fetching_attack_bundle", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        return dict(response.json())

    path = Path(source)
    logger.info("reading_attack_bundle", source=str(path))
    with path.open("r", encoding="utf-8") as f:
        return dict(json.load(f))


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == _ATTACK_SOURCE_NAME and "external_id" in ref:
            id_: str = ref["external_id"]
            return id_
    return None


def _tactics(obj: dict[str, Any]) -> list[str]:
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == _ATTACK_KILL_CHAIN
    ]


def parse_bundle(
    bundle: dict[str, Any],
    *,
    ingester_run_id: str | None = None,
) -> Iterator[UnifiedAttackTechnique]:
    """Parse a STIX bundle (already loaded as a dict) into UnifiedAttackTechnique records.

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, writing) happens outside this function.
    """
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _external_id(obj)
        if technique_id is None:
            logger.warning("attack_pattern_missing_external_id", stix_id=obj.get("id"))
            continue

        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
        parent_technique_id = technique_id.split(".")[0] if is_subtechnique else None

        yield UnifiedAttackTechnique(
            technique_id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=_tactics(obj),
            is_subtechnique=is_subtechnique,
            parent_technique_id=parent_technique_id,
            platforms=obj.get("x_mitre_platforms", []),
            raw_source=obj,
            ingester_run_id=ingester_run_id,
        )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="mitre_attack")
    bundle = fetch_bundle(source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for technique in parse_bundle(bundle, ingester_run_id=result.run_id):
            try:
                f.write(technique.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue, don't abort the run
                result.record_error(f"{technique.technique_id}: {exc}")
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "mitre_attack_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the MITRE ATT&CK Enterprise STIX bundle into "
        "UnifiedAttackTechnique JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="STIX bundle URL or local file path (default: the attack-stix-data mirror).",
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
        logger.error("mitre_attack_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "mitre_attack_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} techniques to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
