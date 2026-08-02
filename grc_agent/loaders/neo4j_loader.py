"""Load UnifiedControl JSON-Lines records into Neo4j as (:Control) nodes.

Implements FR-402 ((:Control) nodes), FR-403/FR-404 (RELATES_TO for
same-framework related controls, ENHANCES for control enhancements —
cross-framework mappings are deliberately out of scope here; those become
MAPS_TO edges once a cross-framework mapping ingester exists), FR-407
(idempotent reloads via MERGE), and FR-408 (provenance: both the ingester's
run ID and this loader's own run ID are stored on every node/edge touched).

Loading happens in two phases so relationship targets always already exist
regardless of file ordering:
  1. UNWIND-batched MERGE of every Control node.
  2. UNWIND-batched MERGE of RELATES_TO and ENHANCES edges between nodes
     created in phase 1.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog
from neo4j import Driver

from grc_agent.config.settings import get_settings
from grc_agent.schemas import IngestionResult, UnifiedControl
from grc_agent.tools.neo4j_tools import get_driver

logger = structlog.get_logger(__name__)

DEFAULT_INPUT_PATH = Path("data/sp800_53.jsonl")
DEFAULT_BATCH_SIZE = 500

#: Neo4j Community Edition only supports single-property uniqueness constraints
#: (composite NODE KEY constraints require Enterprise Edition — see spec §11
#: assumptions: "Neo4j Community Edition is sufficient"). `uid` is a derived
#: "<framework>:<control_id>" key so a control_id is only unique per framework.
_CONSTRAINT_QUERY = """
CREATE CONSTRAINT control_unique_uid IF NOT EXISTS
FOR (c:Control) REQUIRE c.uid IS UNIQUE
"""

_NODE_UPSERT_QUERY = """
UNWIND $records AS rec
MERGE (c:Control {uid: rec.uid})
SET c.control_id = rec.control_id,
    c.framework = rec.framework,
    c.title = rec.title,
    c.statement = rec.statement,
    c.control_family = rec.control_family,
    c.version = rec.version,
    c.parent_control_id = rec.parent_control_id,
    c.related_controls = rec.related_controls,
    c.parameters = rec.parameters,
    c.baselines = rec.baselines,
    c.ingester_run_id = rec.ingester_run_id,
    c.ingested_at = rec.ingested_at,
    c.raw_source_json = rec.raw_source_json,
    c.loader_run_id = $loader_run_id
"""

_RELATES_TO_QUERY = """
UNWIND $pairs AS pair
MATCH (a:Control {uid: pair.from_uid})
MATCH (b:Control {uid: pair.to_uid})
MERGE (a)-[r:RELATES_TO]->(b)
SET r.loader_run_id = $loader_run_id
"""

_ENHANCES_QUERY = """
UNWIND $pairs AS pair
MATCH (child:Control {uid: pair.child_uid})
MATCH (parent:Control {uid: pair.parent_uid})
MERGE (child)-[r:ENHANCES]->(parent)
SET r.loader_run_id = $loader_run_id
"""


def _uid(framework: str, control_id: str) -> str:
    return f"{framework}:{control_id}"


def read_jsonl(path: Path) -> Iterator[UnifiedControl]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield UnifiedControl.model_validate_json(line)


def _chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _control_to_node_params(control: UnifiedControl) -> dict[str, Any]:
    return {
        "uid": _uid(control.framework.value, control.control_id),
        "control_id": control.control_id,
        "framework": control.framework.value,
        "title": control.title,
        "statement": control.statement,
        "control_family": control.control_family,
        "version": control.version,
        "parent_control_id": control.parent_control_id,
        "related_controls": control.related_controls,
        "parameters": control.parameters,
        "baselines": control.baselines,
        "ingester_run_id": control.ingester_run_id,
        "ingested_at": control.ingested_at.isoformat(),
        "raw_source_json": json.dumps(control.raw_source, default=str),
    }


def ensure_constraints(driver: Driver, database: str) -> None:
    driver.execute_query(_CONSTRAINT_QUERY, database_=database)


def load_controls(
    controls: Iterable[UnifiedControl],
    *,
    driver: Driver,
    database: str,
    loader_run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestionResult:
    """Upsert every control as a node, then wire up RELATES_TO/ENHANCES edges."""
    result = IngestionResult(source_name="neo4j_loader:nist_sp800_53", run_id=loader_run_id)
    ensure_constraints(driver, database)

    all_controls = list(controls)
    node_params = [_control_to_node_params(c) for c in all_controls]

    for batch in _chunks(node_params, batch_size):
        driver.execute_query(
            _NODE_UPSERT_QUERY,
            records=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        result.record_success(count=len(batch))

    relates_pairs = [
        {
            "from_uid": _uid(c.framework.value, c.control_id),
            "to_uid": _uid(c.framework.value, related),
        }
        for c in all_controls
        for related in c.related_controls
    ]
    relationships_created = 0
    for batch in _chunks(relates_pairs, batch_size):
        _, summary, _ = driver.execute_query(
            _RELATES_TO_QUERY, pairs=batch, loader_run_id=loader_run_id, database_=database
        )
        relationships_created += summary.counters.relationships_created

    enhances_pairs = [
        {
            "child_uid": _uid(c.framework.value, c.control_id),
            "parent_uid": _uid(c.framework.value, c.parent_control_id),
        }
        for c in all_controls
        if c.parent_control_id
    ]
    for batch in _chunks(enhances_pairs, batch_size):
        _, summary, _ = driver.execute_query(
            _ENHANCES_QUERY, pairs=batch, loader_run_id=loader_run_id, database_=database
        )
        relationships_created += summary.counters.relationships_created

    result.finish()
    logger.info(
        "neo4j_load_complete",
        run_id=result.run_id,
        nodes_written=result.records_written,
        relates_to_and_enhances_attempted=len(relates_pairs) + len(enhances_pairs),
        relationships_created=relationships_created,
        duration_seconds=result.duration_seconds,
    )
    return result


def run(input_path: Path) -> IngestionResult:
    settings = get_settings()
    controls = list(read_jsonl(input_path))
    with get_driver() as driver:
        return load_controls(
            controls,
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=str(uuid4()),
        )


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Load UnifiedControl JSON-Lines records into Neo4j as (:Control) nodes."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Input JSON-Lines path (default: {DEFAULT_INPUT_PATH}).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("neo4j_loader_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input)
    except Exception as exc:  # noqa: BLE001 - surface any driver/connection failure cleanly
        logger.error("neo4j_loader_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error("neo4j_loader_had_failures", errors=result.errors)
        return 1

    print(f"Loaded {result.records_written} controls from {args.input} into Neo4j.")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
