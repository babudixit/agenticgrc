"""Ingest the NIST Cybersecurity Framework (CSF) 2.0 OSCAL catalog into UnifiedControl records.

Fetches the OSCAL JSON catalog (same public-domain NIST/OSCAL toolchain as
`nist_sp800_53.py`; see `_oscal_common.py` for the shared parsing helpers)
and writes one UnifiedControl per line to a JSON-Lines file.

CSF-specific parsing notes (see the real catalog at github.com/usnistgov/
oscal-content, path `nist.gov/CSF/v2.0`):
- CSF nests three levels instead of 800-53's two: `groups[]` are the six CSF
  **Functions** (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER); each
  Function's `controls[]` are **Categories** (`class: "category"`, e.g.
  "GV.OC" Organizational Context); each Category's own nested `controls[]`
  are **Subcategories** (`class: "subcategory"`, e.g. "GV.OC-01") — the
  finest-grained CSF outcome statements, and what most crosswalks (including
  the CSF->SP-800-53 informative references, see
  `nist_csf_to_800_53.py`) key off of.
- Unlike 800-53, *both* Categories and Subcategories are emitted as their own
  `UnifiedControl` — Categories carry real descriptive statement text of
  their own (not just a grouping label), so dropping them would lose that
  content. Functions are not emitted as controls (mirroring 800-53's
  families): the Function's label becomes every descendant's
  `control_family` instead. `_oscal_common.iter_controls_recursive`'s
  single-level `parent_raw_id` tracking naturally gives Subcategories their
  owning Category as `parent_control_id`, and Categories `None` — the same
  shape as 800-53's enhancement->base-control parent tracking.
- CSF's OSCAL catalog embeds *withdrawn CSF 1.1 categories/subcategories*
  (e.g. "PR.AC", superseded by "PR.AA" in 2.0) alongside current 2.0
  content, using `status: withdrawn` + a `rel: incorporated_into` link —
  functionally identical to 800-53's withdrawn-control handling, but with a
  bare (non `#`-prefixed) href and an underscore in the rel name; both
  variants are handled by `_oscal_common.resolve_href_ids`.
- The document's own `metadata.version` is the *OSCAL conversion* version
  (e.g. "1.2.0"), not the CSF framework version — the framework version is
  hardcoded as "2.0" here instead (this ingester is CSF-2.0-specific, same
  as `nist_sp800_53.py` being Rev-5-specific).
- CSF subcategories carry no independent human-readable `title` (OSCAL sets
  `title == id`, e.g. title "GV.OC-01") — the outcome statement itself
  *is* the content; this is faithfully preserved rather than synthesized.
- "Implementation Example" `parts` (`name: "example"`) are informative,
  non-normative illustrations NIST publishes per subcategory; they're
  intentionally excluded from `statement` (which mirrors 800-53's normative
  text convention) to avoid mixing prescriptive and illustrative text.
- Unlike 800-53, raw OSCAL `id`s are *already* the canonical display ID for
  every CSF element ("GV.OC", "GV.OC-01" — never a lowercase slug needing
  `props[label]` resolution). CSF's own `label` prop instead holds a
  human-readable "Title (ID)" string for Categories (e.g. "Organizational
  Context (GV.OC)"), which is the wrong shape for `control_id` — so this
  ingester uses `control["id"]` directly and an identity-valued lookup
  index for link resolution, rather than `_oscal_common`'s
  `canonical_label`/`build_label_index` (those stay 800-53-specific).
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
    "nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
)
DEFAULT_OUTPUT_PATH = Path("data/csf_2_0.jsonl")

#: CSF's OSCAL catalog spells this rel with an underscore, not a hyphen, and
#: uses a bare href (see module docstring) — both handled by resolve_href_ids.
_INCORPORATED_INTO_REL = "incorporated_into"
_CSF_FRAMEWORK_VERSION = "2.0"


def _identity_id_index(groups: list[dict[str, Any]]) -> dict[str, str]:
    """CSF raw ids are already canonical (see module docstring) — this is a
    same-shape stand-in for `_oscal_common.build_label_index` that maps every
    id to itself, so `resolve_href_ids` can be reused unchanged.
    """
    return {
        control["id"]: control["id"]
        for group in groups
        for control, _parent in iter_controls_recursive(group.get("controls", []))
    }


def parse_catalog(
    catalog_doc: dict[str, Any],
    *,
    ingester_run_id: str | None = None,
) -> Iterator[UnifiedControl]:
    """Parse a CSF 2.0 OSCAL catalog document into UnifiedControl records
    (one per Category and one per Subcategory — see module docstring).

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, writing) happens outside this function.
    """
    catalog = catalog_doc["catalog"]
    groups = catalog.get("groups", [])
    id_index = _identity_id_index(groups)

    for group in groups:
        function_label = group_label(group)
        for control, parent_raw_id in iter_controls_recursive(group.get("controls", [])):
            params_by_id = {p["id"]: param_display(p) for p in control.get("params", [])}
            withdrawn = is_withdrawn(control)

            if withdrawn:
                incorporated_into = resolve_href_ids(
                    control, _INCORPORATED_INTO_REL, id_index, control["id"]
                )
                statement = "This item has been withdrawn from CSF 2.0."
                if incorporated_into:
                    statement += f" Incorporated into: {', '.join(incorporated_into)}."
                related_controls: list[str] = []
            else:
                statement = extract_statement(control, params_by_id) or "(no statement text)"
                related_controls = resolve_href_ids(control, "related", id_index, control["id"])

            yield UnifiedControl(
                control_id=control["id"],
                framework=Framework.NIST_CSF_2_0,
                version=_CSF_FRAMEWORK_VERSION,
                title=control.get("title", ""),
                statement=statement,
                control_family=function_label,
                parent_control_id=parent_raw_id,
                related_controls=related_controls,
                parameters=[param_display(p) for p in control.get("params", [])],
                baselines=[],
                raw_source=control,
                ingester_run_id=ingester_run_id,
            )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="nist_csf")
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
        "nist_csf_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the NIST CSF 2.0 OSCAL catalog into UnifiedControl JSON-Lines."
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
        logger.error("nist_csf_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_csf_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} controls to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
