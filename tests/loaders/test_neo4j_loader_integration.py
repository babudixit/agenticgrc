"""Integration tests that exercise the loader against a real, running Neo4j
instance (started via `docker-compose up -d neo4j`).

These are automatically skipped if Neo4j isn't reachable, so the main test
suite stays green in environments without Docker running (e.g. a fresh clone
before `docker-compose up`). Every node/edge this test creates is tagged with
a unique per-test run ID and cleaned up in a fixture teardown, so it never
pollutes real ingested data sitting in the same database.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from grc_agent.config.settings import get_settings
from grc_agent.loaders.neo4j_loader import load_controls
from grc_agent.schemas import Framework, UnifiedControl
from grc_agent.tools.neo4j_tools import get_driver, verify_connectivity


def _neo4j_available() -> bool:
    try:
        verify_connectivity()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _neo4j_available(), reason="Neo4j is not reachable")


@pytest.fixture
def loader_run_id() -> str:
    """A unique tag so this test's nodes can be identified and cleaned up."""
    return f"pytest-integration-{uuid4()}"


@pytest.fixture(autouse=True)
def _cleanup(loader_run_id: str):
    yield
    settings = get_settings()
    with get_driver() as driver:
        driver.execute_query(
            "MATCH (c:Control) WHERE c.loader_run_id = $run_id DETACH DELETE c",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )


def test_load_controls_creates_nodes_and_relates_to_edge(loader_run_id: str) -> None:
    settings = get_settings()
    framework = Framework.NIST_SP_800_53_R5
    base = UnifiedControl(
        control_id=f"TEST-{loader_run_id[:8]}-1",
        framework=framework,
        version="test",
        title="Fixture Control One",
        statement="Statement one.",
        raw_source={},
    )
    related = UnifiedControl(
        control_id=f"TEST-{loader_run_id[:8]}-2",
        framework=framework,
        version="test",
        title="Fixture Control Two",
        statement="Statement two.",
        related_controls=[base.control_id],
        raw_source={},
    )

    with get_driver() as driver:
        result = load_controls(
            [base, related],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )

        assert result.success is True
        assert result.records_written == 2

        records, _, _ = driver.execute_query(
            "MATCH (c:Control {loader_run_id: $run_id}) RETURN c.control_id AS control_id "
            "ORDER BY control_id",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )
        assert [r["control_id"] for r in records] == sorted([base.control_id, related.control_id])

        rel_records, _, _ = driver.execute_query(
            "MATCH (a:Control {loader_run_id: $run_id})-[:RELATES_TO]->(b:Control) "
            "RETURN a.control_id AS from_id, b.control_id AS to_id",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )
        assert len(rel_records) == 1
        assert rel_records[0]["from_id"] == related.control_id
        assert rel_records[0]["to_id"] == base.control_id


def test_load_controls_is_idempotent_on_reload(loader_run_id: str) -> None:
    settings = get_settings()
    control = UnifiedControl(
        control_id=f"TEST-{loader_run_id[:8]}-idempotent",
        framework=Framework.NIST_SP_800_53_R5,
        version="test",
        title="Idempotency Fixture",
        statement="Statement.",
        raw_source={},
    )

    with get_driver() as driver:
        load_controls(
            [control], driver=driver, database=settings.neo4j_database, loader_run_id=loader_run_id
        )
        load_controls(
            [control], driver=driver, database=settings.neo4j_database, loader_run_id=loader_run_id
        )

        records, _, _ = driver.execute_query(
            "MATCH (c:Control {loader_run_id: $run_id}) RETURN count(c) AS n",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )
        assert records[0]["n"] == 1  # not 2 — the second load must not duplicate the node
