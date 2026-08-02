"""Thin wrapper around the Neo4j Bolt driver.

Deliverable 3's loader and Deliverable 5's mapping agent both need a Neo4j
connection; this module centralizes driver construction and a couple of
smoke-test helpers so neither has to duplicate connection handling.
"""

from __future__ import annotations

import argparse
import sys

import structlog
from neo4j import Driver, GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

from grc_agent.config.settings import get_settings

logger = structlog.get_logger(__name__)


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
