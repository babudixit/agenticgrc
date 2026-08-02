"""Ingest the MITRE CWE catalog into UnifiedWeakness records.

Fetches the CWE XML catalog (zipped by default at the source, per MITRE's own
distribution), parses it deterministically, and writes one UnifiedWeakness
per line to a JSON-Lines file. Part of the Deliverable 5 reference-data
expansion that adds the `(:Weakness)` node type needed for the
CVE->CWE->ATT&CK->Controls traversal chain.

Parsing notes (see the real catalog at cwe.mitre.org/data/xml/cwec_latest.xml.zip):
- The catalog root is `Weakness_Catalog`, namespaced under
  `http://cwe.mitre.org/cwe-7`; individual weaknesses live under
  `Weaknesses/Weakness`, each identified by an `ID` attribute (no "CWE-"
  prefix — that's added on normalization).
- `Description` is a short plain-text element; `Extended_Description` (when
  present) wraps one or more `xhtml:p` paragraphs that must be joined.
- `Related_Weaknesses/Related_Weakness` entries carry a `Nature` (ChildOf,
  ParentOf, PeerOf, CanPrecede, ...) and a `View_ID`. Only View 1000 (CWE's
  primary "Research Concepts" hierarchy) is kept — the same relationship is
  usually repeated under other views (e.g. 1003, "Weaknesses for Simplified
  Mapping"), which would otherwise duplicate edges in the graph.
- `Categories` and `Views` (compound groupings, not individual weaknesses)
  are deliberately not iterated — Deliverable 5 only needs the leaf
  `Weakness` entries CVEs are tagged with.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
import structlog

from grc_agent.schemas import IngestionResult, UnifiedWeakness

logger = structlog.get_logger(__name__)

DEFAULT_SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DEFAULT_OUTPUT_PATH = Path("data/cwe.jsonl")

_PRIMARY_VIEW_ID = "1000"
_WHITESPACE = re.compile(r"\s+")


def fetch_catalog(source: str, *, timeout: float = 60.0) -> bytes:
    """Load the raw CWE catalog XML bytes from a local path or an HTTP(S) URL.

    Transparently unzips `.zip`-packaged sources (MITRE's own distribution
    format); a bare `.xml` file or URL is read as-is.
    """
    if source.startswith(("http://", "https://")):
        logger.info("fetching_cwe_catalog", source=source)
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        content = response.content
    else:
        logger.info("reading_cwe_catalog", source=source)
        content = Path(source).read_bytes()

    if source.lower().endswith(".zip") or content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            xml_names = [n for n in archive.namelist() if n.lower().endswith(".xml")]
            if not xml_names:
                raise ValueError(f"No .xml file found inside zip archive: {source}")
            return archive.read(xml_names[0])
    return content


def _namespace(root: ET.Element) -> str:
    return root.tag.split("}")[0].strip("{") if "}" in root.tag else ""


def _extract_text(el: ET.Element | None, *, paragraph_sep: str = "\n\n") -> str | None:
    """Flatten an element's text, joining child paragraphs (e.g. xhtml:p) if present."""
    if el is None:
        return None
    children = list(el)
    if not children:
        text = (el.text or "").strip()
        return text or None

    paragraphs = []
    for child in children:
        text = _WHITESPACE.sub(" ", "".join(child.itertext())).strip()
        if text:
            paragraphs.append(text)
    return paragraph_sep.join(paragraphs) if paragraphs else None


def parse_catalog(
    xml_content: bytes,
    *,
    ingester_run_id: str | None = None,
) -> Iterator[UnifiedWeakness]:
    """Parse a CWE catalog XML document (already loaded as bytes) into UnifiedWeakness records.

    A pure, network-free function so it can be unit-tested directly against a
    small fixture — all I/O (fetching, unzipping, writing) happens outside it.
    """
    root = ET.fromstring(xml_content)  # noqa: S314 - trusted MITRE distribution, not user input
    ns = _namespace(root)

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    weaknesses_el = root.find(q("Weaknesses"))
    if weaknesses_el is None:
        return

    for weakness in weaknesses_el.findall(q("Weakness")):
        raw_id = weakness.attrib["ID"]
        related_ids = [
            f"CWE-{rel.attrib['CWE_ID']}"
            for rel in weakness.findall(f"{q('Related_Weaknesses')}/{q('Related_Weakness')}")
            if rel.attrib.get("View_ID") == _PRIMARY_VIEW_ID
        ]

        yield UnifiedWeakness(
            weakness_id=f"CWE-{raw_id}",
            name=weakness.attrib.get("Name", ""),
            description=_extract_text(weakness.find(q("Description"))) or "",
            extended_description=_extract_text(weakness.find(q("Extended_Description"))),
            abstraction=weakness.attrib.get("Abstraction"),
            status=weakness.attrib.get("Status"),
            related_weakness_ids=related_ids,
            raw_source={
                "ID": raw_id,
                "Name": weakness.attrib.get("Name", ""),
                "raw_xml": ET.tostring(weakness, encoding="unicode"),
            },
            ingester_run_id=ingester_run_id,
        )


def run(source: str, output_path: Path) -> IngestionResult:
    result = IngestionResult(source_name="mitre_cwe")
    xml_content = fetch_catalog(source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for weakness in parse_catalog(xml_content, ingester_run_id=result.run_id):
            try:
                f.write(weakness.model_dump_json() + "\n")
            except Exception as exc:  # noqa: BLE001 - record and continue, don't abort the run
                result.record_error(f"{weakness.weakness_id}: {exc}")
                continue
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "mitre_cwe_ingestion_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        output_path=result.output_path,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the MITRE CWE catalog into UnifiedWeakness JSON-Lines."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help="CWE catalog URL or local file path, .xml or .zip (default: MITRE's zipped catalog).",
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
    except (requests.RequestException, OSError, KeyError, ET.ParseError) as exc:
        logger.error("mitre_cwe_ingestion_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "mitre_cwe_ingestion_had_failures",
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(f"Wrote {result.records_written} weaknesses to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
