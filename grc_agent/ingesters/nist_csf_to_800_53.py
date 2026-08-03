"""Ingest NIST CSF 2.0 Informative References to SP 800-53 as ControlControlMapping records.

Fetches the CSF 2.0 Reference Tool export (despite the URL saying `json`, NIST
currently returns an `.xlsx` workbook — see
https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all),
parses the "CSF 2.0" sheet's Subcategory / Informative References columns
deterministically, and writes one ControlControlMapping per (CSF subcategory,
SP 800-53 control) pair to a JSON-Lines file.

Parsing notes:
- Each Subcategory cell is `"<id>: <statement>"` (e.g. `"GV.OC-01: The
  organizational mission..."`); the id before the first `": "` is the
  `source_control_id`.
- Informative References is a newline-separated list mixing many frameworks
  (`ISO/IEC 27001:2022: ...`, `CRI Profile v2.0: ...`, `SCF: ...`, etc.).
  Only lines matching `SP 800-53 Rev <version>: <control-id>` are kept —
  those are NIST's own Informative References from 800-53 into CSF.
- NIST publishes the same control under multiple 800-53 *minor* revisions
  (e.g. both `Rev 5.1.1: PM-11` and `Rev 5.2.0: PM-11`); we keep only the
  latest revision's entry for each (subcategory, control) pair so the
  graph doesn't grow a duplicate edge per minor revision. The project's
  own 800-53 catalog is Rev 5 (not pinned to a minor), so either revision
  resolves to the same `(:Control)` node once the zero-padded form is
  normalized.
- Control IDs in the export are zero-padded (`AC-01`, `CP-02(08)`); the
  project's `nist_sp800_53` ingester emits unpadded IDs (`AC-1`, `CP-2(8)`),
  so every target id is normalized with the same `_ZERO_PADDED_CONTROL_NUMBER`
  regex `ctid_attack_control_mappings.py` already uses.
- Bare family labels (`PT`, `AC`) occasionally appear as "references" — they
  aren't real control ids and are skipped.
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

DEFAULT_SOURCE_URL = "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all"
DEFAULT_OUTPUT_PATH = Path("data/csf_to_800_53.jsonl")

_XLSX_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_REL_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

#: Matches "SP 800-53 Rev 5.2.0: PM-11" / "SP 800-53 Rev 5.1.1: CP-02(08)".
_SP800_53_REF = re.compile(
    r"^SP\s*800-53\s+Rev\s+(?P<version>[\d.]+)\s*:\s*(?P<control_id>[A-Z]{2}-\d+(?:\(\d+\))?)\s*$"
)
#: "AC-01" -> "AC-1", "CP-02(08)" -> "CP-2(8)" — same regex as the CTID ingester.
_ZERO_PADDED_CONTROL_NUMBER = re.compile(r"(?<=-|\()\b0+(\d+)")
_SUBCATEGORY_ID = re.compile(r"^(?P<id>[A-Z]{2}\.[A-Z]{2}-\d{2})\s*:")


def fetch_workbook(source: str, *, timeout: float = 60.0) -> bytes:
    """Load the CSF Reference Tool export (xlsx bytes) from a path or HTTP(S) URL."""
    if source.startswith(("http://", "https://")):
        logger.info("fetching_csf_reference_tool_export", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        return response.content

    path = Path(source)
    logger.info("reading_csf_reference_tool_export", source=str(path))
    return path.read_bytes()


def _normalize_control_id(control_id: str) -> str:
    """'AC-01' -> 'AC-1', 'CP-02(08)' -> 'CP-2(8)'."""
    return _ZERO_PADDED_CONTROL_NUMBER.sub(r"\1", control_id)


def _load_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        raw = archive.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(raw)
    strings: list[str] = []
    for si in root.findall("m:si", _XLSX_NS):
        texts = [t.text or "" for t in si.findall(".//m:t", _XLSX_NS)]
        strings.append("".join(texts))
    return strings


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
        # Cells may skip columns (sparse); pad by column letter index so
        # Function/Category/Subcategory/Examples/References stay aligned.
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


def _parse_version(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def parse_workbook(
    workbook_bytes: bytes,
    *,
    ingester_run_id: str | None = None,
    preferred_revision_prefix: str = "5",
) -> Iterator[ControlControlMapping]:
    """Parse a CSF Reference Tool xlsx (already loaded as bytes) into
    ControlControlMapping records.

    A pure, network-free function so it can be unit-tested against a small
    fixture workbook — all I/O (fetching, writing) happens outside.
    """
    # Best (subcategory, control) wins: keep the highest SP 800-53 minor
    # revision that mentions it, so Rev 5.2.0 beats Rev 5.1.1.
    best: dict[tuple[str, str], tuple[tuple[int, ...], dict[str, Any]]] = {}

    with zipfile.ZipFile(io.BytesIO(workbook_bytes)) as archive:
        rows = _iter_sheet_rows(archive, "CSF 2.0")
        header = next(rows, None)
        if header is None:
            raise ValueError("CSF 2.0 sheet is empty")

        for row in rows:
            while len(row) < 5:
                row.append(None)
            subcategory_cell, refs_cell = row[2], row[4]
            if not subcategory_cell or not refs_cell:
                continue
            id_match = _SUBCATEGORY_ID.match(subcategory_cell)
            if id_match is None:
                continue
            source_id = id_match.group("id")

            for line in refs_cell.splitlines():
                ref_match = _SP800_53_REF.match(line.strip())
                if ref_match is None:
                    continue
                version = ref_match.group("version")
                if not version.startswith(preferred_revision_prefix):
                    continue
                target_id = _normalize_control_id(ref_match.group("control_id"))
                key = (source_id, target_id)
                parsed_version = _parse_version(version)
                existing = best.get(key)
                if existing is None or parsed_version > existing[0]:
                    best[key] = (
                        parsed_version,
                        {
                            "source_control_id": source_id,
                            "target_control_id": target_id,
                            "version": version,
                            "raw_line": line.strip(),
                            "subcategory_cell": subcategory_cell,
                        },
                    )

    for (_source, _target), (_version, payload) in sorted(best.items()):
        yield ControlControlMapping(
            source_control_id=payload["source_control_id"],
            source_framework=Framework.NIST_CSF_2_0,
            target_control_id=payload["target_control_id"],
            target_framework=Framework.NIST_SP_800_53_R5,
            mapping_type="related",
            comments=f"CSF 2.0 Informative Reference (SP 800-53 Rev {payload['version']})",
            raw_source={
                "subcategory": payload["subcategory_cell"],
                "informative_reference": payload["raw_line"],
                "sp800_53_revision": payload["version"],
            },
            ingester_run_id=ingester_run_id,
        )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="nist_csf_to_800_53")
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
        "nist_csf_to_800_53_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest NIST CSF 2.0 Informative References to SP 800-53 into "
        "ControlControlMapping JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="CSF Reference Tool export URL or local .xlsx path (default: NIST's export URL).",
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
        logger.error("nist_csf_to_800_53_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "nist_csf_to_800_53_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} mappings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
