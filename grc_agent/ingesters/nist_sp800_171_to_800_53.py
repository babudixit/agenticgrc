"""Ingest the NIST SP 800-171 Rev 3 CUI Overlay into ControlControlMapping records.

Fetches NIST's supplemental "CUI Overlay" spreadsheet
(`sp800-171r3-cui-overlay.xlsx` on the SP 800-171 Rev 3 publication page),
parses the "CUI Overlay" sheet deterministically, and writes one
ControlControlMapping per (800-171 requirement, SP 800-53 control) pair.

Parsing notes (see the real spreadsheet's header row):
- Column B — `SP 800-53 Rev 5 Control & Control Enhancement`: either a control
  header (`"AC-01  Policy and Procedures"`, `"AC-02(03)  Account Management |
  Disable Accounts"`) or a statement fragment (`"a. Develop, document..."`).
  Only cells that *start* with a control id are used as the target; statement
  fragments are skipped (their parent control appears on an earlier row).
- Column C — `Tailoring Decision`: one of `CUI` / `NCO` / `FED` / `ORC`. Only
  `CUI` rows are kept — those are the 800-53 controls NIST selected into the
  CUI baseline that underpins 800-171. `NCO` ("Not directly related to
  protecting the confidentiality of CUI") / `FED` / `ORC` are intentionally
  out of scope for 800-171 and produce no edge.
- Column E — `SP 800-171 Rev 3 Security Requirement`: `"03.15.01  Policy and
  Procedures"` or a sub-part `"03.15.01.a. ..."`. The source id is the
  dotted-decimal requirement (`03.15.01`); sub-part suffixes (`.a`, `.b`, ...)
  are stripped so the edge lands on the same `(:Control)` node the
  `nist_sp800_171` catalog ingester emits. Rows with no 800-171 id (blank /
  em-dash placeholders used for NCO rows) are skipped.
- Control IDs are zero-padded in the overlay (`AC-01`, `AC-02(03)`); normalized
  to the project's unpadded form (`AC-1`, `AC-2(3)`) so the loader's
  `(:Control {uid})` lookup against the already-loaded 800-53 catalog matches.
- Many statement-level rows under the same (requirement, control) pair repeat
  the same mapping — deduplicated so the graph gets one edge per pair.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import requests
import structlog

from grc_agent.schemas import ControlControlMapping, Framework, IngestionResult

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = (
    "https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r3-cui-overlay.xlsx"
)
DEFAULT_OUTPUT_PATH = Path("data/sp800_171_to_800_53.jsonl")

_XLSX_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_REL_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

#: "AC-01  Policy...", "AC-02(03)  Account Management | ..."
_SP800_53_CONTROL = re.compile(r"^(?P<control_id>[A-Z]{2}-\d+(?:\(\d+\))?)\s")
#: "03.15.01  Policy..." or "03.15.01.a. Develop..." — capture the requirement.
_SP800_171_REQUIREMENT = re.compile(r"^(?P<requirement_id>\d{2}\.\d{2}\.\d{2})")
_ZERO_PADDED_CONTROL_NUMBER = re.compile(r"(?<=-|\()\b0+(\d+)")
_CUI_DECISION = "CUI"


def fetch_workbook(source: str, *, timeout: float = 60.0) -> bytes:
    """Load the CUI Overlay spreadsheet (xlsx bytes) from a path or HTTP(S) URL."""
    if source.startswith(("http://", "https://")):
        logger.info("fetching_cui_overlay", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        return response.content

    path = Path(source)
    logger.info("reading_cui_overlay", source=str(path))
    return path.read_bytes()


def _normalize_control_id(control_id: str) -> str:
    """'AC-01' -> 'AC-1', 'AC-02(03)' -> 'AC-2(3)'."""
    return _ZERO_PADDED_CONTROL_NUMBER.sub(r"\1", control_id)


def _load_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        raw = archive.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(raw)
    return [
        "".join(t.text or "" for t in si.findall(".//m:t", _XLSX_NS))
        for si in root.findall("m:si", _XLSX_NS)
    ]


def _sheet_path_for_name(archive: zipfile.ZipFile, sheet_name: str) -> str:
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    rid_to_target = {
        rel.attrib["Id"]: rel.attrib["Target"] for rel in rels.findall("r:Relationship", _REL_NS)
    }
    for sheet in workbook.findall("m:sheets/m:sheet", _XLSX_NS):
        if sheet.attrib.get("name") == sheet_name:
            rid = sheet.attrib[
                "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
            ]
            target = rid_to_target[rid]
            return target if target.startswith("xl/") else f"xl/{target}"
    raise KeyError(f"Sheet {sheet_name!r} not found in workbook")


def _cell_value(cell: ET.Element, shared_strings: list[str]) -> str | None:
    value_el = cell.find("m:v", _XLSX_NS)
    if value_el is None or value_el.text is None:
        return None
    if cell.attrib.get("t") == "s":
        return shared_strings[int(value_el.text)]
    return value_el.text


def _iter_sheet_rows(archive: zipfile.ZipFile, sheet_name: str) -> Iterator[list[str | None]]:
    shared_strings = _load_shared_strings(archive)
    sheet_path = _sheet_path_for_name(archive, sheet_name)
    sheet = ET.fromstring(archive.read(sheet_path))
    for row in sheet.findall("m:sheetData/m:row", _XLSX_NS):
        cells_by_col: dict[int, str | None] = {}
        max_col = -1
        for cell in row.findall("m:c", _XLSX_NS):
            ref = cell.attrib.get("r", "A1")
            col_letters = "".join(ch for ch in ref if ch.isalpha())
            col_idx = 0
            for ch in col_letters:
                col_idx = col_idx * 26 + (ord(ch.upper()) - ord("A") + 1)
            col_idx -= 1
            cells_by_col[col_idx] = _cell_value(cell, shared_strings)
            max_col = max(max_col, col_idx)
        yield [cells_by_col.get(i) for i in range(max_col + 1)]


def parse_workbook(
    workbook_bytes: bytes,
    *,
    ingester_run_id: str | None = None,
) -> Iterator[ControlControlMapping]:
    """Parse a CUI Overlay xlsx (already loaded as bytes) into
    ControlControlMapping records.

    A pure, network-free function so it can be unit-tested against a small
    fixture workbook — all I/O (fetching, writing) happens outside.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}

    with zipfile.ZipFile(io.BytesIO(workbook_bytes)) as archive:
        rows = _iter_sheet_rows(archive, "CUI Overlay")
        header = next(rows, None)
        if header is None:
            raise ValueError("CUI Overlay sheet is empty")

        for row in rows:
            while len(row) < 5:
                row.append(None)
            sp53_cell, decision, sp171_cell = row[1], row[2], row[4]
            if not sp53_cell or not decision or not sp171_cell:
                continue
            if decision.strip() != _CUI_DECISION:
                continue

            control_match = _SP800_53_CONTROL.match(sp53_cell.strip())
            if control_match is None:
                continue
            requirement_match = _SP800_171_REQUIREMENT.match(sp171_cell.strip())
            if requirement_match is None:
                continue

            source_id = requirement_match.group("requirement_id")
            target_id = _normalize_control_id(control_match.group("control_id"))
            key = (source_id, target_id)
            if key in seen:
                continue
            seen[key] = {
                "source_control_id": source_id,
                "target_control_id": target_id,
                "sp53_cell": sp53_cell,
                "sp171_cell": sp171_cell,
            }

    for (_source, _target), payload in sorted(seen.items()):
        yield ControlControlMapping(
            source_control_id=payload["source_control_id"],
            source_framework=Framework.NIST_SP_800_171_R3,
            target_control_id=payload["target_control_id"],
            target_framework=Framework.NIST_SP_800_53_R5,
            mapping_type="derived_from",
            comments="SP 800-171 Rev 3 CUI Overlay (tailoring decision: CUI)",
            raw_source={
                "sp800_53_cell": payload["sp53_cell"],
                "sp800_171_cell": payload["sp171_cell"],
                "tailoring_decision": _CUI_DECISION,
            },
            ingester_run_id=ingester_run_id,
        )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="nist_sp800_171_to_800_53")
    workbook_bytes = fetch_workbook(source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for mapping in parse_workbook(workbook_bytes, ingester_run_id=result.run_id):
            try:
                f.write(mapping.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue
                result.record_error(
                    f"{mapping.source_control_id}->{mapping.target_control_id}: {exc}"
                )
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "nist_sp800_171_to_800_53_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the NIST SP 800-171 Rev 3 CUI Overlay into "
        "ControlControlMapping JSON-Lines (800-171 -> SP 800-53)."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="CUI Overlay .xlsx URL or local path (default: NIST's publication-page download).",
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
    except (requests.RequestException, OSError, KeyError, ValueError) as exc:
        logger.error("nist_sp800_171_to_800_53_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_sp800_171_to_800_53_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} mappings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
