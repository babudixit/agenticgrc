"""Thin wrapper around the Neo4j Bolt driver.

Deliverable 3's loader and Deliverable 5's mapping agent both need a Neo4j
connection; this module centralizes driver construction and a couple of
smoke-test helpers so neither has to duplicate connection handling.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

import structlog
from neo4j import Driver, GraphDatabase, RoutingControl
from neo4j.exceptions import Neo4jError, ServiceUnavailable

from grc_agent.config.settings import get_settings

logger = structlog.get_logger(__name__)

# Word-boundary match on every Cypher clause/procedure that can mutate the
# graph or its schema. Deliberately broad (better to reject a legitimate
# read than to execute an unintended write) since queries reaching this
# guard are LLM-generated (Deliverable 5's mapping agent).
_WRITE_CLAUSE_PATTERN = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV"
    r"|CALL\s*\{|CALL\s+apoc\.(?:create|merge|refactor|periodic|schema)"
    r"|CALL\s+db\.(?:createIndex|createProperty|index)"
    r"|CALL\s+dbms\.)",
    re.IGNORECASE,
)


class UnsafeCypherQueryError(ValueError):
    """Raised when a Cypher query text looks like it would mutate the graph or schema."""


def _assert_read_only(cypher: str) -> None:
    match = _WRITE_CLAUSE_PATTERN.search(cypher)
    if match:
        raise UnsafeCypherQueryError(
            f"Refusing to execute Cypher containing a write clause/procedure "
            f"({match.group(0)!r}). Only read (MATCH/RETURN/WHERE/...) queries are allowed."
        )


def get_driver() -> Driver:
    """Build a Neo4j driver from the current settings.

    The caller owns the returned driver's lifecycle and should close it (or
    use it as a context manager) when done.
    """
    settings = get_settings()
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
    )


def verify_connectivity() -> dict[str, str]:
    """Verify the Neo4j connection is reachable and return basic server info.

    Raises `neo4j.exceptions.ServiceUnavailable` if the server can't be
    reached at all, or `neo4j.exceptions.Neo4jError` for auth/other failures.
    """
    settings = get_settings()
    with get_driver() as driver:
        driver.verify_connectivity()
        records, _, _ = driver.execute_query(
            "CALL dbms.components() YIELD name, versions, edition "
            "RETURN name, versions[0] AS version, edition",
            database_=settings.neo4j_database,
        )
    info = dict(records[0]) if records else {}
    logger.info("neo4j_connectivity_verified", uri=settings.neo4j_uri, **info)
    return info


def run_read_query(
    cypher: str,
    parameters: dict[str, Any] | None = None,
    *,
    driver: Driver,
    database: str | None = None,
    row_limit: int = 50,
) -> list[dict[str, Any]]:
    """Execute a read-only Cypher query and return rows as plain JSON-serializable dicts.

    This is the tool the mapping agent (Deliverable 5) exposes to Claude for graph
    traversal (CVE -> Weakness -> AttackTechnique -> Control). The query text is
    LLM-generated, so it's treated as untrusted input: `_assert_read_only` rejects
    any write clause/procedure as defense-in-depth, on top of requesting Neo4j's
    own READ routing mode. `row_limit` caps how many rows are returned to keep the
    agent's context window bounded regardless of what the query itself requests.
    """
    _assert_read_only(cypher)
    settings = get_settings()
    records, _, _ = driver.execute_query(
        cypher,
        parameters_=parameters or {},
        database_=database or settings.neo4j_database,
        routing_=RoutingControl.READ,
    )
    return [dict(record) for record in records[:row_limit]]


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify connectivity to the configured Neo4j instance."
    )
    parser.parse_args(argv)

    try:
        info = verify_connectivity()
    except ServiceUnavailable:
        logger.error(
            "neo4j_unreachable",
            hint="Is the container running? Try: docker-compose up -d neo4j",
        )
        return 1
    except Neo4jError as exc:
        logger.error("neo4j_error", code=exc.code, message=exc.message)
        return 1

    print(f"Connected to {info.get('name')} {info.get('version')} ({info.get('edition')} edition)")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
