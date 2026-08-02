"""Load Unified* JSON-Lines records into Neo4j as graph nodes/edges.

Started in Deliverable 3 as a Control-only loader; extended in Deliverable 5
to load every node type in the CVE->CWE->ATT&CK->Controls traversal chain
(FR-402/FR-403/FR-404), still idempotently (FR-407) and with provenance
(FR-408: both the ingester's run ID and this loader's own run ID are stored
on every node/edge touched). `--record-type` selects which Unified* schema
and Cypher a given `--input` file is loaded as — one file always holds one
record type, per the ingester contract.

Node types and their natural (constrained-unique) key:
  - `(:Control {uid})`             — uid = "<framework>:<control_id>"
  - `(:Weakness {weakness_id})`    — e.g. "CWE-79"
  - `(:AttackTechnique {technique_id})` — e.g. "T1055.011"
  - `(:Vulnerability {cve_id})`    — e.g. "CVE-2021-3156"

Edge types, each loaded in its own node-existence-safe MATCH+MERGE pass so
loading order across the four ingesters never matters:
  - `(:Control)-[:RELATES_TO]->(:Control)`             — same-framework related controls
  - `(:Control)-[:ENHANCES]->(:Control)`                — enhancement -> base control
  - `(:Weakness)-[:RELATES_TO]->(:Weakness)`            — CWE View-1000 hierarchy
  - `(:Vulnerability)-[:MAPS_TO]->(:Weakness)`          — CVE's associated CWE(s)
  - `(:AttackTechnique)-[:MAPS_TO]->(:Control)`         — CTID mitigates mapping

Every "load nodes then load edges" pass follows the same two-phase shape:
  1. UNWIND-batched MERGE of every node.
  2. UNWIND-batched MATCH+MERGE of edges between nodes that already exist
     (from this batch or a prior loader run) — a MATCH that doesn't resolve
     (e.g. a CVE's CWE not yet ingested) simply produces no edge, rather than
     failing the whole batch.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, TypeVar
from uuid import uuid4

import structlog
from neo4j import Driver
from pydantic import BaseModel

from grc_agent.config.settings import get_settings
from grc_agent.schemas import (
    AttackControlMapping,
    IngestionResult,
    UnifiedAttackTechnique,
    UnifiedControl,
    UnifiedVulnerability,
    UnifiedWeakness,
)
from grc_agent.tools.neo4j_tools import get_driver

logger = structlog.get_logger(__name__)

DEFAULT_INPUT_PATH = Path("data/sp800_53.jsonl")
DEFAULT_BATCH_SIZE = 500

_T = TypeVar("_T", bound=BaseModel)

#: Neo4j Community Edition only supports single-property uniqueness constraints
#: (composite NODE KEY constraints require Enterprise Edition — see spec §11
#: assumptions: "Neo4j Community Edition is sufficient"). `uid` is a derived
#: "<framework>:<control_id>" key so a control_id is only unique per framework.
_CONTROL_CONSTRAINT_QUERY = """
CREATE CONSTRAINT control_unique_uid IF NOT EXISTS
FOR (c:Control) REQUIRE c.uid IS UNIQUE
"""

_CONTROL_NODE_UPSERT_QUERY = """
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

_CONTROL_RELATES_TO_QUERY = """
UNWIND $pairs AS pair
MATCH (a:Control {uid: pair.from_uid})
MATCH (b:Control {uid: pair.to_uid})
MERGE (a)-[r:RELATES_TO]->(b)
SET r.loader_run_id = $loader_run_id
"""

_CONTROL_ENHANCES_QUERY = """
UNWIND $pairs AS pair
MATCH (child:Control {uid: pair.child_uid})
MATCH (parent:Control {uid: pair.parent_uid})
MERGE (child)-[r:ENHANCES]->(parent)
SET r.loader_run_id = $loader_run_id
"""

_WEAKNESS_CONSTRAINT_QUERY = """
CREATE CONSTRAINT weakness_unique_id IF NOT EXISTS
FOR (w:Weakness) REQUIRE w.weakness_id IS UNIQUE
"""

_WEAKNESS_NODE_UPSERT_QUERY = """
UNWIND $records AS rec
MERGE (w:Weakness {weakness_id: rec.weakness_id})
SET w.name = rec.name,
    w.description = rec.description,
    w.extended_description = rec.extended_description,
    w.abstraction = rec.abstraction,
    w.status = rec.status,
    w.related_weakness_ids = rec.related_weakness_ids,
    w.ingester_run_id = rec.ingester_run_id,
    w.ingested_at = rec.ingested_at,
    w.raw_source_json = rec.raw_source_json,
    w.loader_run_id = $loader_run_id
"""

_WEAKNESS_RELATES_TO_QUERY = """
UNWIND $pairs AS pair
MATCH (a:Weakness {weakness_id: pair.from_id})
MATCH (b:Weakness {weakness_id: pair.to_id})
MERGE (a)-[r:RELATES_TO]->(b)
SET r.loader_run_id = $loader_run_id
"""

_ATTACK_TECHNIQUE_CONSTRAINT_QUERY = """
CREATE CONSTRAINT attack_technique_unique_id IF NOT EXISTS
FOR (t:AttackTechnique) REQUIRE t.technique_id IS UNIQUE
"""

_ATTACK_TECHNIQUE_NODE_UPSERT_QUERY = """
UNWIND $records AS rec
MERGE (t:AttackTechnique {technique_id: rec.technique_id})
SET t.name = rec.name,
    t.description = rec.description,
    t.tactics = rec.tactics,
    t.is_subtechnique = rec.is_subtechnique,
    t.parent_technique_id = rec.parent_technique_id,
    t.platforms = rec.platforms,
    t.ingester_run_id = rec.ingester_run_id,
    t.ingested_at = rec.ingested_at,
    t.raw_source_json = rec.raw_source_json,
    t.loader_run_id = $loader_run_id
"""

_VULNERABILITY_CONSTRAINT_QUERY = """
CREATE CONSTRAINT vulnerability_unique_cve_id IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE
"""

_VULNERABILITY_NODE_UPSERT_QUERY = """
UNWIND $records AS rec
MERGE (v:Vulnerability {cve_id: rec.cve_id})
SET v.description = rec.description,
    v.cvss_v3_score = rec.cvss_v3_score,
    v.cvss_v3_severity = rec.cvss_v3_severity,
    v.cvss_v2_score = rec.cvss_v2_score,
    v.cwes = rec.cwes,
    v.cpes = rec.cpes,
    v.published_date = rec.published_date,
    v.last_modified_date = rec.last_modified_date,
    v.references = rec.references,
    v.in_kev = rec.in_kev,
    v.epss_score = rec.epss_score,
    v.ingester_run_id = rec.ingester_run_id,
    v.ingested_at = rec.ingested_at,
    v.raw_source_json = rec.raw_source_json,
    v.loader_run_id = $loader_run_id
"""

_VULNERABILITY_MAPS_TO_WEAKNESS_QUERY = """
UNWIND $pairs AS pair
MATCH (v:Vulnerability {cve_id: pair.cve_id})
MATCH (w:Weakness {weakness_id: pair.weakness_id})
MERGE (v)-[r:MAPS_TO]->(w)
SET r.loader_run_id = $loader_run_id
"""

_ATTACK_CONTROL_MAPS_TO_QUERY = """
UNWIND $pairs AS pair
MATCH (t:AttackTechnique {technique_id: pair.technique_id})
MATCH (c:Control {uid: pair.control_uid})
MERGE (t)-[r:MAPS_TO]->(c)
SET r.mapping_type = pair.mapping_type,
    r.comments = pair.comments,
    r.loader_run_id = $loader_run_id
"""


def _uid(framework: str, control_id: str) -> str:
    return f"{framework}:{control_id}"


def read_jsonl(path: Path, model: type[_T]) -> Iterator[_T]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield model.model_validate_json(line)


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


def _weakness_to_node_params(weakness: UnifiedWeakness) -> dict[str, Any]:
    return {
        "weakness_id": weakness.weakness_id,
        "name": weakness.name,
        "description": weakness.description,
        "extended_description": weakness.extended_description,
        "abstraction": weakness.abstraction,
        "status": weakness.status,
        "related_weakness_ids": weakness.related_weakness_ids,
        "ingester_run_id": weakness.ingester_run_id,
        "ingested_at": weakness.ingested_at.isoformat(),
        "raw_source_json": json.dumps(weakness.raw_source, default=str),
    }


def _attack_technique_to_node_params(technique: UnifiedAttackTechnique) -> dict[str, Any]:
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "description": technique.description,
        "tactics": technique.tactics,
        "is_subtechnique": technique.is_subtechnique,
        "parent_technique_id": technique.parent_technique_id,
        "platforms": technique.platforms,
        "ingester_run_id": technique.ingester_run_id,
        "ingested_at": technique.ingested_at.isoformat(),
        "raw_source_json": json.dumps(technique.raw_source, default=str),
    }


def _vulnerability_to_node_params(vuln: UnifiedVulnerability) -> dict[str, Any]:
    return {
        "cve_id": vuln.cve_id,
        "description": vuln.description,
        "cvss_v3_score": vuln.cvss_v3_score,
        "cvss_v3_severity": vuln.cvss_v3_severity.value if vuln.cvss_v3_severity else None,
        "cvss_v2_score": vuln.cvss_v2_score,
        "cwes": vuln.cwes,
        "cpes": vuln.cpes,
        "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
        "last_modified_date": (
            vuln.last_modified_date.isoformat() if vuln.last_modified_date else None
        ),
        "references": vuln.references,
        "in_kev": vuln.in_kev,
        "epss_score": vuln.epss_score,
        "ingester_run_id": vuln.ingester_run_id,
        "ingested_at": vuln.ingested_at.isoformat(),
        "raw_source_json": json.dumps(vuln.raw_source, default=str),
    }


def _mapping_to_edge_params(mapping: AttackControlMapping) -> dict[str, Any]:
    return {
        "technique_id": mapping.technique_id,
        "control_uid": _uid(mapping.control_framework.value, mapping.control_id),
        "mapping_type": mapping.mapping_type,
        "comments": mapping.comments,
    }


def ensure_constraints(driver: Driver, database: str) -> None:
    driver.execute_query(_CONTROL_CONSTRAINT_QUERY, database_=database)


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
            _CONTROL_NODE_UPSERT_QUERY,
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
            _CONTROL_RELATES_TO_QUERY, pairs=batch, loader_run_id=loader_run_id, database_=database
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
            _CONTROL_ENHANCES_QUERY, pairs=batch, loader_run_id=loader_run_id, database_=database
        )
        relationships_created += summary.counters.relationships_created

    result.finish()
    logger.info(
        "neo4j_load_complete",
        record_type="control",
        run_id=result.run_id,
        nodes_written=result.records_written,
        relationships_created=relationships_created,
        duration_seconds=result.duration_seconds,
    )
    return result


def load_weaknesses(
    weaknesses: Iterable[UnifiedWeakness],
    *,
    driver: Driver,
    database: str,
    loader_run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestionResult:
    """Upsert every CWE weakness as a node, then wire up View-1000 RELATES_TO edges."""
    result = IngestionResult(source_name="neo4j_loader:mitre_cwe", run_id=loader_run_id)
    driver.execute_query(_WEAKNESS_CONSTRAINT_QUERY, database_=database)

    all_weaknesses = list(weaknesses)
    node_params = [_weakness_to_node_params(w) for w in all_weaknesses]

    for batch in _chunks(node_params, batch_size):
        driver.execute_query(
            _WEAKNESS_NODE_UPSERT_QUERY,
            records=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        result.record_success(count=len(batch))

    relates_pairs = [
        {"from_id": w.weakness_id, "to_id": related}
        for w in all_weaknesses
        for related in w.related_weakness_ids
    ]
    relationships_created = 0
    for batch in _chunks(relates_pairs, batch_size):
        _, summary, _ = driver.execute_query(
            _WEAKNESS_RELATES_TO_QUERY, pairs=batch, loader_run_id=loader_run_id, database_=database
        )
        relationships_created += summary.counters.relationships_created

    result.finish()
    logger.info(
        "neo4j_load_complete",
        record_type="weakness",
        run_id=result.run_id,
        nodes_written=result.records_written,
        relationships_created=relationships_created,
        duration_seconds=result.duration_seconds,
    )
    return result


def load_attack_techniques(
    techniques: Iterable[UnifiedAttackTechnique],
    *,
    driver: Driver,
    database: str,
    loader_run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestionResult:
    """Upsert every ATT&CK technique/sub-technique as a node.

    No edges are created here: sub-technique/parent linkage is kept as a
    plain `parent_technique_id` property (there's no dedicated relationship
    type for it in the spec's FR-403/FR-404 vocabulary), and the
    technique->control edge is loaded separately by
    `load_attack_control_mappings`.
    """
    result = IngestionResult(source_name="neo4j_loader:mitre_attack", run_id=loader_run_id)
    driver.execute_query(_ATTACK_TECHNIQUE_CONSTRAINT_QUERY, database_=database)

    node_params = [_attack_technique_to_node_params(t) for t in techniques]
    for batch in _chunks(node_params, batch_size):
        driver.execute_query(
            _ATTACK_TECHNIQUE_NODE_UPSERT_QUERY,
            records=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        result.record_success(count=len(batch))

    result.finish()
    logger.info(
        "neo4j_load_complete",
        record_type="attack_technique",
        run_id=result.run_id,
        nodes_written=result.records_written,
        duration_seconds=result.duration_seconds,
    )
    return result


def load_vulnerabilities(
    vulnerabilities: Iterable[UnifiedVulnerability],
    *,
    driver: Driver,
    database: str,
    loader_run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestionResult:
    """Upsert every CVE as a node, then wire up MAPS_TO edges to its CWE(s)."""
    result = IngestionResult(source_name="neo4j_loader:nist_nvd", run_id=loader_run_id)
    driver.execute_query(_VULNERABILITY_CONSTRAINT_QUERY, database_=database)

    all_vulnerabilities = list(vulnerabilities)
    node_params = [_vulnerability_to_node_params(v) for v in all_vulnerabilities]

    for batch in _chunks(node_params, batch_size):
        driver.execute_query(
            _VULNERABILITY_NODE_UPSERT_QUERY,
            records=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        result.record_success(count=len(batch))

    maps_to_pairs = [
        {"cve_id": v.cve_id, "weakness_id": cwe} for v in all_vulnerabilities for cwe in v.cwes
    ]
    relationships_created = 0
    for batch in _chunks(maps_to_pairs, batch_size):
        _, summary, _ = driver.execute_query(
            _VULNERABILITY_MAPS_TO_WEAKNESS_QUERY,
            pairs=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        relationships_created += summary.counters.relationships_created

    result.finish()
    logger.info(
        "neo4j_load_complete",
        record_type="vulnerability",
        run_id=result.run_id,
        nodes_written=result.records_written,
        relationships_created=relationships_created,
        duration_seconds=result.duration_seconds,
    )
    return result


def load_attack_control_mappings(
    mappings: Iterable[AttackControlMapping],
    *,
    driver: Driver,
    database: str,
    loader_run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestionResult:
    """Wire up AttackTechnique->Control MAPS_TO edges. Creates no nodes of its own —
    both endpoints must already exist from `load_attack_techniques`/`load_controls`.
    """
    result = IngestionResult(
        source_name="neo4j_loader:ctid_attack_control_mappings", run_id=loader_run_id
    )

    edge_params = [_mapping_to_edge_params(m) for m in mappings]
    relationships_created = 0
    for batch in _chunks(edge_params, batch_size):
        _, summary, _ = driver.execute_query(
            _ATTACK_CONTROL_MAPS_TO_QUERY,
            pairs=batch,
            loader_run_id=loader_run_id,
            database_=database,
        )
        relationships_created += summary.counters.relationships_created
        result.record_success(count=len(batch))

    result.finish()
    logger.info(
        "neo4j_load_complete",
        record_type="attack_control_mapping",
        run_id=result.run_id,
        mappings_attempted=result.records_written,
        relationships_created=relationships_created,
        duration_seconds=result.duration_seconds,
    )
    return result


#: One entry per `--record-type`: which schema to parse the input file as,
#: which loader function to hand the parsed records to, and the noun used in
#: the CLI's success message.
_RECORD_TYPE_REGISTRY: dict[str, tuple[type[BaseModel], Any, str]] = {
    "control": (UnifiedControl, load_controls, "controls"),
    "weakness": (UnifiedWeakness, load_weaknesses, "weaknesses"),
    "attack_technique": (UnifiedAttackTechnique, load_attack_techniques, "techniques"),
    "vulnerability": (UnifiedVulnerability, load_vulnerabilities, "CVEs"),
    "attack_control_mapping": (AttackControlMapping, load_attack_control_mappings, "mappings"),
}


def run(input_path: Path, record_type: str = "control") -> IngestionResult:
    settings = get_settings()
    model, loader_fn, _ = _RECORD_TYPE_REGISTRY[record_type]
    records = list(read_jsonl(input_path, model))
    with get_driver() as driver:
        result: IngestionResult = loader_fn(
            records,
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=str(uuid4()),
        )
        return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Load Unified* JSON-Lines records into Neo4j as graph nodes/edges."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Input JSON-Lines path (default: {DEFAULT_INPUT_PATH}).",
    )
    parser.add_argument(
        "--record-type",
        choices=list(_RECORD_TYPE_REGISTRY.keys()),
        default="control",
        help="Which Unified* schema the input file holds (default: control).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("neo4j_loader_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run(args.input, args.record_type)
    except Exception as exc:  # noqa: BLE001 - surface any driver/connection failure cleanly
        logger.error("neo4j_loader_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error("neo4j_loader_had_failures", errors=result.errors)
        return 1

    noun = _RECORD_TYPE_REGISTRY[args.record_type][2]
    print(f"Loaded {result.records_written} {noun} from {args.input} into Neo4j.")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
