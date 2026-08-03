"""Ingest the NIST SP 800-171 Rev 3 OSCAL catalog into UnifiedControl records.

Fetches the OSCAL JSON catalog (same public-domain NIST/OSCAL toolchain as
`nist_sp800_53.py`; see `_oscal_common.py` for the shared parsing helpers)
and writes one UnifiedControl per line to a JSON-Lines file.

800-171-specific parsing notes (see the real catalog at github.com/usnistgov/
oscal-content, path `nist.gov/SP800-171/rev3`):
- Uses the `-min` catalog variant (`NIST_SP800-171_rev3_catalog-min.json`),
  not the plain `_catalog.json` one: the latter bundles in the full
  SP 800-171A *assessment procedures* (per-requirement EXAMINE/INTERVIEW/TEST
  objects, ~10x the file size) which this project doesn't need — Deliverable
  3's 800-53 ingester only ever consumed the 800-53 *catalog*, not 800-53A,
  so this keeps the same scope for 800-171.
- Structurally flat and 800-53-like: `groups[]` are the 17 requirement
  families (e.g. "Access Control"), each family's `controls[]` are
  requirements directly (`class: "requirement"`) with no further nesting
  (800-171 has no enhancement concept) and their own ODP `params` (Organization-
  Defined Parameters, 800-171's equivalent of 800-53's parameters).
- Unlike 800-53, the `props[label]` value is a combined "Title (ID)" string
  (e.g. "Account Management (03.01.01)"), not a bare ID — the same quirk as
  CSF Categories (see `nist_csf.py`). Raw OSCAL ids here are consistently
  `SP_800_171_<family>.<requirement>` (e.g. "SP_800_171_03.01.01"); stripping
  the fixed `SP_800_171_` prefix yields NIST's own official dotted-decimal
  numbering ("03.01.01") directly and unambiguously, so — like `nist_csf.py`
  — this ingester derives `control_id` from the raw id rather than the
  `label` prop.
- The catalog's own `links` are all `rel: "reference"` UUID hrefs into
  `back-matter` bibliography resources (citations to other NIST pubs) — not
  a per-requirement crosswalk to specific SP 800-53 controls. NIST does
  publish a 800-171<->800-53 "source control" mapping (Rev 3 Appendix D),
  but not embedded in this OSCAL catalog; it's ingested separately (see
  `nist_sp800_171_to_800_53.py`) rather than invented here.
- The document's own `metadata.version` is the OSCAL conversion version
  (e.g. "1.1.0"), not the SP 800-171 revision — the framework version is
  hardcoded as "3" here instead, matching how `nist_sp800_53.py` labels its
  Framework enum member by revision number rather than OSCAL doc version.
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
    extract_statement,
    fetch_catalog,
    group_label,
    is_withdrawn,
    iter_controls_recursive,
    param_display,
    resolve_href_ids,
)
from grc_agent.schemas import Framework, IngestionResult, UnifiedControl

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog-min.json"
)
DEFAULT_OUTPUT_PATH = Path("data/sp800_171.jsonl")

_ID_PREFIX = "SP_800_171_"
_SP800_171_FRAMEWORK_VERSION = "3"


def _strip_id_prefix(raw_id: str) -> str:
    """'SP_800_171_03.01.01' -> '03.01.01' (see module docstring)."""
    return raw_id.removeprefix(_ID_PREFIX)


def _identity_id_index(groups: list[dict[str, Any]]) -> dict[str, str]:
    """Raw ids need only prefix-stripping (not `props[label]` lookup) to reach
    their canonical display form — see module docstring. Same role as
    `nist_csf.py`'s `_identity_id_index`: lets `resolve_href_ids` be reused
    unchanged for a framework whose ids don't need `_oscal_common`'s
    label-prop-based resolution.
    """
    return {
        control["id"]: _strip_id_prefix(control["id"])
        for group in groups
        for control, _parent in iter_controls_recursive(group.get("controls", []))
    }


def parse_catalog(
    catalog_doc: dict[str, Any],
    *,
    ingester_run_id: str | None = None,
) -> Iterator[UnifiedControl]:
    """Parse an SP 800-171 Rev 3 OSCAL catalog document into UnifiedControl records.

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, writing) happens outside this function.
    """
    catalog = catalog_doc["catalog"]
    groups = catalog.get("groups", [])
    id_index = _identity_id_index(groups)

    for group in groups:
        family = group_label(group)
        for control, parent_raw_id in iter_controls_recursive(group.get("controls", [])):
            params_by_id = {p["id"]: param_display(p) for p in control.get("params", [])}
            withdrawn = is_withdrawn(control)

            if withdrawn:
                incorporated_into = resolve_href_ids(
                    control, "incorporated-into", id_index, control["id"]
                )
                statement = "This requirement has been withdrawn."
                if incorporated_into:
                    statement += f" Incorporated into: {', '.join(incorporated_into)}."
                related_controls: list[str] = []
            else:
                statement = extract_statement(control, params_by_id) or "(no statement text)"
                related_controls = resolve_href_ids(control, "related", id_index, control["id"])

            yield UnifiedControl(
                control_id=_strip_id_prefix(control["id"]),
                framework=Framework.NIST_SP_800_171_R3,
                version=_SP800_171_FRAMEWORK_VERSION,
                title=control.get("title", ""),
                statement=statement,
                control_family=family,
                parent_control_id=(_strip_id_prefix(parent_raw_id) if parent_raw_id else None),
                related_controls=related_controls,
                parameters=[param_display(p) for p in control.get("params", [])],
                baselines=[],
                raw_source=control,
                ingester_run_id=ingester_run_id,
            )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="nist_sp800_171")
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
        "nist_sp800_171_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the NIST SP 800-171 Rev 3 OSCAL catalog into UnifiedControl "
        "JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="OSCAL catalog URL or local file path (default: NIST's GitHub-hosted -min catalog).",
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
        logger.error("nist_sp800_171_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_sp800_171_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} controls to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
