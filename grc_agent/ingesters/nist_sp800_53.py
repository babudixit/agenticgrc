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
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import structlog

from grc_agent.schemas import Framework, IngestionResult, UnifiedControl

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
DEFAULT_OUTPUT_PATH = Path("data/sp800_53.jsonl")

_PARAM_PLACEHOLDER = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.-]+)\s*\}\}")


def fetch_catalog(source: str, *, timeout: float = 30.0) -> dict[str, Any]:
    """Load the OSCAL catalog JSON from a local file path or an HTTP(S) URL."""
    if source.startswith(("http://", "https://")):
        logger.info("fetching_oscal_catalog", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        return dict(response.json())

    path = Path(source)
    logger.info("reading_oscal_catalog", source=str(path))
    with path.open("r", encoding="utf-8") as f:
        import json

        return dict(json.load(f))


def _canonical_label(props: list[dict[str, Any]], fallback: str) -> str:
    for prop in props:
        if prop.get("name") == "label" and "class" not in prop:
            value = prop.get("value")
            if isinstance(value, str):
                return value
    return fallback


def _guess_canonical_id(raw_id: str) -> str:
    """Best-effort canonicalization for a raw OSCAL id with no resolvable label.

    'ac-2' -> 'AC-2', 'ac-2.1' -> 'AC-2(1)'. Only used as a fallback when a
    referenced control's real label can't be found in the catalog.
    """
    prefix, _, rest = raw_id.partition("-")
    if not rest:
        return raw_id.upper()
    base, _, enhancement = rest.partition(".")
    if enhancement:
        return f"{prefix.upper()}-{base}({enhancement})"
    return f"{prefix.upper()}-{base}"


def _is_withdrawn(control: dict[str, Any]) -> bool:
    return any(
        prop.get("name") == "status" and prop.get("value") == "withdrawn"
        for prop in control.get("props", [])
    )


def _iter_controls_recursive(
    controls: list[dict[str, Any]], parent_raw_id: str | None = None
) -> Iterator[tuple[dict[str, Any], str | None]]:
    """Yield every (control, parent_raw_id) pair, descending into enhancements."""
    for control in controls:
        yield control, parent_raw_id
        nested = control.get("controls")
        if nested:
            yield from _iter_controls_recursive(nested, parent_raw_id=control["id"])


def _build_label_index(groups: list[dict[str, Any]]) -> dict[str, str]:
    """Map every control's raw OSCAL id to its canonical display label."""
    index: dict[str, str] = {}
    for group in groups:
        for control, _parent in _iter_controls_recursive(group.get("controls", [])):
            index[control["id"]] = _canonical_label(control.get("props", []), control["id"])
    return index


def _resolve_href_ids(
    control: dict[str, Any], rel: str, label_index: dict[str, str], self_raw_id: str
) -> list[str]:
    resolved: dict[str, None] = {}
    for link in control.get("links", []):
        if link.get("rel") != rel:
            continue
        href = link.get("href", "")
        if not href.startswith("#"):
            continue
        raw_ref = href[1:]
        if raw_ref == self_raw_id:
            continue
        label = label_index.get(raw_ref) or _guess_canonical_id(raw_ref)
        resolved.setdefault(label, None)
    return list(resolved.keys())


def _param_display(param: dict[str, Any]) -> str:
    if isinstance(param.get("label"), str):
        return param["label"]
    select = param.get("select")
    if select and select.get("choice"):
        return "one of: " + ", ".join(select["choice"])
    return str(param.get("id", ""))


def _resolve_param_placeholders(text: str, params_by_id: dict[str, str]) -> str:
    def _sub(match: re.Match[str]) -> str:
        label = params_by_id.get(match.group(1))
        return f"[{label}]" if label else match.group(0)

    return _PARAM_PLACEHOLDER.sub(_sub, text)


def _flatten_statement_parts(
    parts: list[dict[str, Any]], params_by_id: dict[str, str], depth: int = 0
) -> list[str]:
    lines: list[str] = []
    for part in parts:
        label = next((p["value"] for p in part.get("props", []) if p.get("name") == "label"), "")
        prose = part.get("prose")
        if prose:
            resolved = _resolve_param_placeholders(prose, params_by_id)
            prefix = f"{label} " if label else ""
            lines.append(("  " * depth) + f"{prefix}{resolved}")
        if part.get("parts"):
            lines.extend(_flatten_statement_parts(part["parts"], params_by_id, depth + 1))
    return lines


def _extract_statement(control: dict[str, Any], params_by_id: dict[str, str]) -> str:
    statement_part = next(
        (p for p in control.get("parts", []) if p.get("name") == "statement"), None
    )
    if statement_part is None:
        return ""
    lines: list[str] = []
    if statement_part.get("prose"):
        lines.append(_resolve_param_placeholders(statement_part["prose"], params_by_id))
    lines.extend(_flatten_statement_parts(statement_part.get("parts", []), params_by_id))
    return "\n".join(lines)


def _family_label(group: dict[str, Any]) -> str:
    return next(
        (p["value"] for p in group.get("props", []) if p.get("name") == "label"),
        group["id"].upper(),
    )


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
