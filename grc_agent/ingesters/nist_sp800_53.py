"""Ingest the NIST SP 800-53 Rev 5 OSCAL catalog into UnifiedControl records.

Fetches the OSCAL JSON catalog (FR-101), parses it deterministically (no LLM
involved — see architecture principle "deterministic modules for data
movement"), and writes one UnifiedControl per line to a JSON-Lines file.

Parsing notes (see the real catalog at github.com/usnistgov/oscal-content):
- Controls are nested under `catalog.groups[].controls[]`; control
  enhancements (e.g. AC-2(1)) are nested recursively inside their base
  control's own `controls` array.
- Each control's canonical display ID (e.g. "AC-1") lives in a `props` entry
  with `name == "label"` and no `class` key — other label variants exist for
  zero-padded and SP800-53A forms and are deliberately ignored.
- The normative control text lives in a `parts` entry with `name ==
  "statement"`, itself a tree of "item" parts (a, b, c, ...) that must be
  flattened into a single string.
- Parameter placeholders (`{{ insert: param, ac-1_prm_1 }}`) are resolved to
  their human-readable label so the statement text is self-contained.
- ~2% of controls are withdrawn (no statement) and instead carry
  `rel: incorporated-into` links to the control(s) that superseded them.
- Cross-control references use `rel: related` links whose `href` is a
  `#<raw-id>` fragment, resolved against every other control's canonical
  label — a two-pass approach (index every control's label first, then
  resolve links) handles forward references regardless of catalog order.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import structlog

from grc_agent.ingesters._oscal_common import (
    build_label_index,
    canonical_label,
    extract_statement,
    fetch_catalog,
    group_label,
    guess_canonical_id,
    is_withdrawn,
    iter_controls_recursive,
    param_display,
    resolve_href_ids,
)
from grc_agent.schemas import Framework, IngestionResult, UnifiedControl

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
DEFAULT_OUTPUT_PATH = Path("data/sp800_53.jsonl")

# Re-exported under their original private names so existing call sites/tests
# (`fetch_catalog`, `_canonical_label`, `_guess_canonical_id`, ...) keep working
# unchanged now that the actual implementations live in `_oscal_common.py`
# (shared with `nist_csf.py`/`nist_sp800_171.py` — see that module's docstring).
_canonical_label = canonical_label
_family_label = group_label
_guess_canonical_id = guess_canonical_id
_is_withdrawn = is_withdrawn
_iter_controls_recursive = iter_controls_recursive
_build_label_index = build_label_index
_resolve_href_ids = resolve_href_ids
_param_display = param_display
_extract_statement = extract_statement


def parse_catalog(
    catalog_doc: dict[str, Any],
    *,
    ingester_run_id: str | None = None,
) -> Iterator[UnifiedControl]:
    """Parse an OSCAL catalog document (already loaded as a dict) into UnifiedControl records.

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, writing) happens outside this function.
    """
    catalog = catalog_doc["catalog"]
    version = catalog.get("metadata", {}).get("version", "unknown")
    groups = catalog.get("groups", [])
    label_index = _build_label_index(groups)

    for group in groups:
        family = _family_label(group)
        for control, parent_raw_id in _iter_controls_recursive(group.get("controls", [])):
            params_by_id = {p["id"]: _param_display(p) for p in control.get("params", [])}
            withdrawn = _is_withdrawn(control)

            if withdrawn:
                incorporated_into = _resolve_href_ids(
                    control, "incorporated-into", label_index, control["id"]
                )
                statement = "This control has been withdrawn."
                if incorporated_into:
                    statement += f" Incorporated into: {', '.join(incorporated_into)}."
                related_controls: list[str] = []
            else:
                statement = _extract_statement(control, params_by_id) or "(no statement text)"
                related_controls = _resolve_href_ids(control, "related", label_index, control["id"])

            yield UnifiedControl(
                control_id=_canonical_label(control.get("props", []), control["id"]),
                framework=Framework.NIST_SP_800_53_R5,
                version=str(version),
                title=control.get("title", ""),
                statement=statement,
                control_family=family,
                parent_control_id=(label_index.get(parent_raw_id) if parent_raw_id else None),
                related_controls=related_controls,
                parameters=[_param_display(p) for p in control.get("params", [])],
                baselines=[],
                raw_source=control,
                ingester_run_id=ingester_run_id,
            )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="nist_sp800_53")
    catalog_doc = fetch_catalog(source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for control in parse_catalog(catalog_doc, ingester_run_id=result.run_id):
            try:
                f.write(control.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue, don't abort the run
                result.record_error(f"{control.control_id}: {exc}")
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "nist_sp800_53_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the NIST SP 800-53 Rev 5 OSCAL catalog into UnifiedControl JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="OSCAL catalog URL or local file path (default: NIST's GitHub-hosted catalog).",
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
        logger.error("nist_sp800_53_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_sp800_53_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} controls to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
