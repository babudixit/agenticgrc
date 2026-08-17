"""Ingress router: pick a vendor normalizer and emit UnifiedFinding JSON-Lines.

Usage:
  python -m grc_agent.normalizers.ingress --source tenable|qualys|siem|cspm \\
      --input path\\to\\export.json --output data\\unified_findings.jsonl

All adapters converge on the same UnifiedFinding CIM used by the mapping agent.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

import structlog

from grc_agent.normalizers import cspm, qualys, siem, tenable
from grc_agent.schemas import IngestionResult

logger = structlog.get_logger(__name__)

DEFAULT_OUTPUT_PATH = Path("data/unified_findings.jsonl")

_RUNNERS: dict[str, Callable[[Path, Path], IngestionResult]] = {
    "tenable": tenable.run,
    "qualys": qualys.run,
    "siem": siem.run,
    "cspm": cspm.run,
}


def run(source: str, input_path: Path, output_path: Path) -> IngestionResult:
    key = source.strip().lower()
    try:
        runner = _RUNNERS[key]
    except KeyError:
        raise ValueError(
            f"Unknown source {source!r}; expected one of {sorted(_RUNNERS)}"
        ) from None
    return runner(input_path, output_path)


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a vendor finding/alert export into UnifiedFinding JSON-Lines."
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=sorted(_RUNNERS),
        help="Which normalizer adapter to use.",
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to vendor JSON export.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON-Lines path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("ingress_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.source, args.input, args.output)
    except (OSError, ValueError) as exc:
        logger.error("ingress_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "ingress_had_failures",
            source=args.source,
            records_failed=result.records_failed,
            errors=result.errors,
        )
        return 1

    print(
        f"Normalized {result.records_written} {args.source} records to "
        f"{result.output_path} (UnifiedFinding)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
