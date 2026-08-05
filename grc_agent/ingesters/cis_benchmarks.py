"""Ingest CIS Benchmark recommendation spreadsheets into UnifiedControl records
plus crosswalk edges into NIST SP 800-53 and ATT&CK.

Reads the user-supplied CIS Benchmark `.xlsx` exports (one product benchmark
per file; columns: title, description, audit, recommendations, nist_mapping,
mitre_techniques, mitre_tactics, mitre_mitigations). These are *not* the CIS
Controls v8 framework — they are product hardening catalogs (Ubuntu, Azure,
Windows Server, firewalls, …). CIS content is copyrighted; this ingester only
reads local files the operator already obtained (never fetches from CIS).

What gets emitted:
1. One `UnifiedControl` per recommendation row
   (`framework=CIS_Benchmark`, `control_id="<slug>:<section>"`).
2. One `ControlControlMapping` per NIST SP 800-53 ID found in `nist_mapping`
   (CIS Benchmark recommendation → 800-53 control). CIS Assessment Tool
   element IDs (`CE-*` / `VP-*` / `VE-*`) are *not* 800-53 controls and are
   left in `raw_source` only — they need a separate CIS Controls catalog to
   resolve.
3. One `AttackControlMapping` per MITRE ATT&CK technique ID found in
   `mitre_techniques` (technique → CIS Benchmark recommendation), same edge
   shape the CTID loader already understands.

Cells use OOXML `inlineStr` (no shared-strings table), so parsing is done with
stdlib `zipfile` + `ElementTree` — no openpyxl dependency.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import structlog

from grc_agent.schemas import (
    AttackControlMapping,
    ControlControlMapping,
    Framework,
    IngestionResult,
    UnifiedControl,
)

logger = structlog.get_logger(__name__)

DEFAULT_INPUT_DIR = Path(r"C:\Cyber-GRC\Documents\CISFILES")
DEFAULT_OUTPUT_PATH = Path("data/cis_benchmarks.jsonl")
DEFAULT_NIST_MAPPINGS_PATH = Path("data/cis_benchmark_to_800_53.jsonl")
DEFAULT_ATTACK_MAPPINGS_PATH = Path("data/attack_to_cis_benchmark.jsonl")

_XLSX_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

#: CIS exports use either `..._Benchmark_v1.0.0.xlsx` or
#: `..._Benchmark_v1.2.0_PDF.xlsx` (and occasionally `_PDF` before `_v`).
_FILE_RE = re.compile(
    r"^CIS_(?P<product>.+?)_Benchmark(?:_PDF)?_v(?P<version>[\d.]+)(?:_PDF)?\.xlsx$",
    re.IGNORECASE,
)
_SECTION_RE = re.compile(r"^(?P<section>\d+(?:\.\d+)*)\b")
#: Real NIST SP 800-53 family prefixes (Rev 5). Explicit allow-list so CIS
#: Assessment Tool IDs like CE-37166 / VP-9501 / VE-2016 are not mistaken for
#: 800-53 controls (they also match a naive `[A-Z]{2}-\d+` pattern).
_NIST_FAMILIES = {
    "AC",
    "AT",
    "AU",
    "CA",
    "CM",
    "CP",
    "IA",
    "IR",
    "MA",
    "MP",
    "PE",
    "PL",
    "PM",
    "PS",
    "PT",
    "RA",
    "SA",
    "SC",
    "SI",
    "SR",
}
_NIST_CONTROL_RE = re.compile(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$")
_ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


@dataclass(frozen=True)
class BenchmarkFileMeta:
    path: Path
    product_slug: str
    product_title: str
    version: str


@dataclass
class CisIngestOutputs:
    controls: IngestionResult
    nist_mappings: IngestionResult
    attack_mappings: IngestionResult


def _slugify_product(product: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "_", product.lower()).strip("_")


def _titleize_product(product: str) -> str:
    return product.replace("_", " ")


def parse_benchmark_filename(path: Path) -> BenchmarkFileMeta | None:
    match = _FILE_RE.match(path.name)
    if match is None:
        return None
    product = match.group("product")
    return BenchmarkFileMeta(
        path=path,
        product_slug=_slugify_product(product),
        product_title=_titleize_product(product),
        version=match.group("version"),
    )


def _inline_text(cell: ET.Element) -> str | None:
    if cell.attrib.get("t") == "inlineStr":
        texts = [t.text or "" for t in cell.findall(".//m:t", _XLSX_NS)]
        return "".join(texts)
    value_el = cell.find("m:v", _XLSX_NS)
    return value_el.text if value_el is not None else None


def _col_index(ref: str) -> int:
    letters = "".join(ch for ch in ref if ch.isalpha())
    col = 0
    for ch in letters:
        col = col * 26 + (ord(ch.upper()) - ord("A") + 1)
    return col - 1


def iter_xlsx_rows(path: Path) -> Iterator[list[str | None]]:
    """Yield each row of the first worksheet as a list of cell strings."""
    with zipfile.ZipFile(path) as archive:
        sheet_path = next(n for n in archive.namelist() if n.startswith("xl/worksheets/"))
        sheet = ET.fromstring(archive.read(sheet_path))
        for row in sheet.findall("m:sheetData/m:row", _XLSX_NS):
            cells: dict[int, str | None] = {}
            max_col = -1
            for cell in row.findall("m:c", _XLSX_NS):
                idx = _col_index(cell.attrib.get("r", "A1"))
                cells[idx] = _inline_text(cell)
                max_col = max(max_col, idx)
            yield [cells.get(i) for i in range(max_col + 1)]


def parse_list_cell(raw: str | None) -> list[str]:
    """Parse a CIS mapping cell that may be JSON, a Python-repr list, or CSV."""
    if raw is None:
        return []
    text = raw.strip()
    if not text or text in ("[]", "null", "None"):
        return []

    for loader in (json.loads, ast.literal_eval):
        try:
            value: Any = loader(text)
        except (ValueError, SyntaxError, json.JSONDecodeError):
            continue
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            # Double-encoded: "['CM-7']" as a JSON string, etc.
            return parse_list_cell(value)
        return []

    return [part.strip() for part in re.split(r"[,;\n]+", text) if part.strip()]


def normalize_nist_control_id(raw: str) -> str | None:
    """Return a canonical 800-53 control id, or None if `raw` isn't one.

    'CM-7' -> 'CM-7', 'AC-02(03)' -> 'AC-2(3)'; 'CE-37166' / 'VP-9501' -> None.
    """
    text = raw.strip().upper().replace(" ", "")
    match = _NIST_CONTROL_RE.fullmatch(text)
    if match is None:
        return None
    family, number, enhancement = match.group(1), match.group(2), match.group(3)
    if family not in _NIST_FAMILIES:
        return None
    # Strip zero-padding from the numeric parts.
    number = str(int(number))
    if enhancement is not None:
        return f"{family}-{number}({int(enhancement)})"
    return f"{family}-{number}"


def normalize_attack_technique_id(raw: str) -> str | None:
    text = raw.strip().upper()
    if _ATTACK_TECHNIQUE_RE.fullmatch(text):
        return text
    return None


def extract_section_id(title: str) -> str | None:
    match = _SECTION_RE.match(title.strip())
    return match.group("section") if match else None


def _pad_row(row: list[str | None], width: int = 8) -> list[str | None]:
    padded = list(row)
    while len(padded) < width:
        padded.append(None)
    return padded


def parse_benchmark_file(
    meta: BenchmarkFileMeta,
    *,
    ingester_run_id: str | None = None,
) -> tuple[list[UnifiedControl], list[ControlControlMapping], list[AttackControlMapping]]:
    """Parse one CIS Benchmark workbook into controls + crosswalk edges."""
    rows = list(iter_xlsx_rows(meta.path))
    if not rows:
        return [], [], []

    header = [((cell or "").strip().lower()) for cell in _pad_row(rows[0])]
    expected = [
        "title",
        "description",
        "audit",
        "recommendations",
        "nist_mapping",
        "mitre_techniques",
        "mitre_tactics",
        "mitre_mitigations",
    ]
    if header[:8] != expected:
        logger.warning(
            "cis_benchmark_unexpected_header",
            path=str(meta.path),
            header=header[:8],
        )

    controls: list[UnifiedControl] = []
    nist_mappings: list[ControlControlMapping] = []
    attack_mappings: list[AttackControlMapping] = []
    seen_nist: set[tuple[str, str]] = set()
    seen_attack: set[tuple[str, str]] = set()

    for row in rows[1:]:
        cells = _pad_row(row)
        title = (cells[0] or "").strip()
        if not title:
            continue
        section = extract_section_id(title)
        if section is None:
            logger.warning(
                "cis_benchmark_row_missing_section_id",
                path=str(meta.path),
                title=title[:120],
            )
            continue

        control_id = f"{meta.product_slug}:{section}"
        description = (cells[1] or "").strip()
        recommendations = (cells[3] or "").strip()
        statement_parts = [p for p in (description, recommendations) if p]
        statement = "\n\n".join(statement_parts) or "(no statement text)"

        raw_source = {
            "benchmark_file": meta.path.name,
            "product_slug": meta.product_slug,
            "product_title": meta.product_title,
            "version": meta.version,
            "section": section,
            "title": title,
            "description": description,
            "audit": cells[2],
            "recommendations": recommendations,
            "nist_mapping": cells[4],
            "mitre_techniques": cells[5],
            "mitre_tactics": cells[6],
            "mitre_mitigations": cells[7],
        }

        controls.append(
            UnifiedControl(
                control_id=control_id,
                framework=Framework.CIS_BENCHMARK,
                version=meta.version,
                title=title,
                statement=statement,
                control_family=meta.product_title,
                parent_control_id=None,
                related_controls=[],
                parameters=[],
                baselines=[],
                raw_source=raw_source,
                ingester_run_id=ingester_run_id,
            )
        )

        for raw_nist in parse_list_cell(cells[4]):
            nist_id = normalize_nist_control_id(raw_nist)
            if nist_id is None:
                continue
            key = (control_id, nist_id)
            if key in seen_nist:
                continue
            seen_nist.add(key)
            nist_mappings.append(
                ControlControlMapping(
                    source_control_id=control_id,
                    source_framework=Framework.CIS_BENCHMARK,
                    target_control_id=nist_id,
                    target_framework=Framework.NIST_SP_800_53_R5,
                    mapping_type="related",
                    comments=f"CIS Benchmark nist_mapping ({meta.path.name})",
                    raw_source={
                        "benchmark_file": meta.path.name,
                        "section": section,
                        "raw_nist_mapping": raw_nist,
                    },
                    ingester_run_id=ingester_run_id,
                )
            )

        for raw_tech in parse_list_cell(cells[5]):
            technique_id = normalize_attack_technique_id(raw_tech)
            if technique_id is None:
                continue
            key = (technique_id, control_id)
            if key in seen_attack:
                continue
            seen_attack.add(key)
            attack_mappings.append(
                AttackControlMapping(
                    technique_id=technique_id,
                    control_id=control_id,
                    control_framework=Framework.CIS_BENCHMARK,
                    mapping_type="mitigates",
                    comments=f"CIS Benchmark mitre_techniques ({meta.path.name})",
                    raw_source={
                        "benchmark_file": meta.path.name,
                        "section": section,
                        "raw_mitre_technique": raw_tech,
                        "mitre_tactics": cells[6],
                        "mitre_mitigations": cells[7],
                    },
                    ingester_run_id=ingester_run_id,
                )
            )

    return controls, nist_mappings, attack_mappings


def discover_benchmark_files(input_dir: Path) -> list[BenchmarkFileMeta]:
    files = sorted(input_dir.glob("*.xlsx"))
    metas: list[BenchmarkFileMeta] = []
    for path in files:
        meta = parse_benchmark_filename(path)
        if meta is None:
            logger.warning("cis_benchmark_unrecognized_filename", path=str(path))
            continue
        metas.append(meta)
    return metas


def run(
    input_dir: Path,
    output_path: Path,
    nist_mappings_path: Path,
    attack_mappings_path: Path,
) -> CisIngestOutputs:
    controls_result = IngestionResult(source_name="cis_benchmarks")
    nist_result = IngestionResult(source_name="cis_benchmark_to_800_53")
    attack_result = IngestionResult(source_name="attack_to_cis_benchmark")

    metas = discover_benchmark_files(input_dir)
    if not metas:
        raise FileNotFoundError(f"No recognizable CIS Benchmark .xlsx files in {input_dir}")

    all_controls: list[UnifiedControl] = []
    all_nist: list[ControlControlMapping] = []
    all_attack: list[AttackControlMapping] = []

    for meta in metas:
        logger.info(
            "parsing_cis_benchmark",
            path=str(meta.path),
            product=meta.product_slug,
            version=meta.version,
        )
        controls, nist_maps, attack_maps = parse_benchmark_file(
            meta, ingester_run_id=controls_result.run_id
        )
        # Stamp the companion mapping runs with their own run IDs for provenance.
        for mapping in nist_maps:
            mapping.ingester_run_id = nist_result.run_id
        for mapping in attack_maps:
            mapping.ingester_run_id = attack_result.run_id
        all_controls.extend(controls)
        all_nist.extend(nist_maps)
        all_attack.extend(attack_maps)

    for path, records, result in (
        (output_path, all_controls, controls_result),
        (nist_mappings_path, all_nist, nist_result),
        (attack_mappings_path, all_attack, attack_result),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for record in records:
                try:
                    f.write(record.model_dump_json() + "\n")
                except Exception as exc:  # noqa: BLE001
                    ident = getattr(record, "control_id", None) or getattr(
                        record, "technique_id", "?"
                    )
                    result.record_error(f"{ident}: {exc}")
                    continue
                result.record_success()
        result.output_path = str(path)
        result.finish()

    logger.info(
        "cis_benchmarks_ingestion_complete",
        benchmarks=len(metas),
        controls=controls_result.records_written,
        nist_mappings=nist_result.records_written,
        attack_mappings=attack_result.records_written,
    )
    return CisIngestOutputs(
        controls=controls_result,
        nist_mappings=nist_result,
        attack_mappings=attack_result,
    )


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest local CIS Benchmark .xlsx files into UnifiedControl "
        "JSON-Lines plus NIST SP 800-53 / ATT&CK crosswalk edges."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Directory of CIS Benchmark .xlsx files (default: {DEFAULT_INPUT_DIR}).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"UnifiedControl JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--nist-mappings-output",
        type=Path,
        default=DEFAULT_NIST_MAPPINGS_PATH,
        help=f"ControlControlMapping JSON-Lines path (default: {DEFAULT_NIST_MAPPINGS_PATH}).",
    )
    parser.add_argument(
        "--attack-mappings-output",
        type=Path,
        default=DEFAULT_ATTACK_MAPPINGS_PATH,
        help=f"AttackControlMapping JSON-Lines path (default: {DEFAULT_ATTACK_MAPPINGS_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input_dir.is_dir():
        logger.error("cis_benchmark_input_dir_missing", input_dir=str(args.input_dir))
        return 1

    try:
        outputs = run(
            args.input_dir,
            args.output,
            args.nist_mappings_output,
            args.attack_mappings_output,
        )
    except (OSError, KeyError, ValueError) as exc:
        logger.error("cis_benchmarks_ingestion_failed", error=str(exc))
        return 1

    if not (
        outputs.controls.success
        and outputs.nist_mappings.success
        and outputs.attack_mappings.success
    ):
        return 1

    print(
        f"Wrote {outputs.controls.records_written} CIS Benchmark recommendations to "
        f"{outputs.controls.output_path}; "
        f"{outputs.nist_mappings.records_written} NIST mappings; "
        f"{outputs.attack_mappings.records_written} ATT&CK mappings."
    )
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
