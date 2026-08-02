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
from grc_agent.loaders.neo4j_loader import (
    load_attack_control_mappings,
    load_attack_techniques,
    load_controls,
    load_vulnerabilities,
    load_weaknesses,
)
from grc_agent.schemas import (
    AttackControlMapping,
    Framework,
    UnifiedAttackTechnique,
    UnifiedControl,
    UnifiedVulnerability,
    UnifiedWeakness,
)
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
        for label in ("Control", "Weakness", "AttackTechnique", "Vulnerability"):
            driver.execute_query(
                f"MATCH (n:{label}) WHERE n.loader_run_id = $run_id DETACH DELETE n",
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


def test_load_weaknesses_creates_nodes_and_relates_to_edge(loader_run_id: str) -> None:
    settings = get_settings()
    numeric_suffix = abs(hash(loader_run_id)) % 10000
    child = UnifiedWeakness(
        weakness_id=f"CWE-9{numeric_suffix:04d}",
        name="Fixture Child Weakness",
        description="Child weakness description.",
        raw_source={},
    )
    parent = UnifiedWeakness(
        weakness_id=f"CWE-8{numeric_suffix:04d}",
        name="Fixture Parent Weakness",
        description="Parent weakness description.",
        raw_source={},
    )
    child = child.model_copy(update={"related_weakness_ids": [parent.weakness_id]})

    with get_driver() as driver:
        result = load_weaknesses(
            [child, parent],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )
        assert result.success is True
        assert result.records_written == 2

        rel_records, _, _ = driver.execute_query(
            "MATCH (a:Weakness {loader_run_id: $run_id})-[:RELATES_TO]->(b:Weakness) "
            "RETURN a.weakness_id AS from_id, b.weakness_id AS to_id",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )
        assert len(rel_records) == 1
        assert rel_records[0]["from_id"] == child.weakness_id
        assert rel_records[0]["to_id"] == parent.weakness_id


def test_load_attack_techniques_creates_nodes(loader_run_id: str) -> None:
    settings = get_settings()
    numeric_suffix = 9000 + abs(hash(loader_run_id)) % 1000
    technique = UnifiedAttackTechnique(
        technique_id=f"T{numeric_suffix}",
        name="Fixture Technique",
        description="Fixture description.",
        tactics=["discovery"],
        raw_source={},
    )

    with get_driver() as driver:
        result = load_attack_techniques(
            [technique],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )
        assert result.success is True

        records, _, _ = driver.execute_query(
            "MATCH (t:AttackTechnique {loader_run_id: $run_id}) RETURN t.technique_id AS id",
            run_id=loader_run_id,
            database_=settings.neo4j_database,
        )
        assert [r["id"] for r in records] == [technique.technique_id]


def test_full_traversal_vulnerability_to_control(loader_run_id: str) -> None:
    """End-to-end proof of the CVE->CWE->ATT&CK->Controls chain the mapping
    agent (Deliverable 5) will query: load one node of each type plus their
    connecting edges, then traverse from a CVE all the way to a control.
    """
    settings = get_settings()
    suffix = abs(hash(loader_run_id)) % 10000
    weakness = UnifiedWeakness(
        weakness_id=f"CWE-7{suffix:04d}",
        name="Fixture Weakness",
        description="Fixture description.",
        raw_source={},
    )
    vulnerability = UnifiedVulnerability(
        cve_id=f"CVE-2024-{suffix:04d}",
        description="Fixture vulnerability.",
        cwes=[weakness.weakness_id],
        raw_source={},
    )
    technique_numeric_id = 8000 + suffix % 1000
    technique = UnifiedAttackTechnique(
        technique_id=f"T{technique_numeric_id}",
        name="Fixture Technique",
        description="Fixture description.",
        raw_source={},
    )
    control = UnifiedControl(
        control_id=f"TEST-{suffix}",
        framework=Framework.NIST_SP_800_53_R5,
        version="test",
        title="Fixture Control",
        statement="Fixture statement.",
        raw_source={},
    )
    mapping = AttackControlMapping(
        technique_id=technique.technique_id,
        control_id=control.control_id,
        control_framework=Framework.NIST_SP_800_53_R5,
        mapping_type="mitigates",
        raw_source={},
    )

    with get_driver() as driver:
        load_weaknesses(
            [weakness], driver=driver, database=settings.neo4j_database, loader_run_id=loader_run_id
        )
        load_controls(
            [control], driver=driver, database=settings.neo4j_database, loader_run_id=loader_run_id
        )
        load_attack_techniques(
            [technique],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )
        load_vulnerabilities(
            [vulnerability],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )
        load_attack_control_mappings(
            [mapping],
            driver=driver,
            database=settings.neo4j_database,
            loader_run_id=loader_run_id,
        )

        vuln_to_weakness, _, _ = driver.execute_query(
            "MATCH (v:Vulnerability {cve_id: $cve_id})-[:MAPS_TO]->(w:Weakness) "
            "RETURN w.weakness_id AS weakness_id",
            cve_id=vulnerability.cve_id,
            database_=settings.neo4j_database,
        )
        assert len(vuln_to_weakness) == 1
        assert vuln_to_weakness[0]["weakness_id"] == weakness.weakness_id

        full_chain, _, _ = driver.execute_query(
            "MATCH (v:Vulnerability {cve_id: $cve_id})-[:MAPS_TO]->(w:Weakness) "
            "MATCH (t:AttackTechnique {technique_id: $technique_id})-[:MAPS_TO]->(c:Control) "
            "RETURN v.cve_id AS cve_id, w.weakness_id AS weakness_id, "
            "t.technique_id AS technique_id, c.control_id AS control_id",
            cve_id=vulnerability.cve_id,
            technique_id=technique.technique_id,
            database_=settings.neo4j_database,
        )
        assert len(full_chain) == 1
        assert full_chain[0]["cve_id"] == vulnerability.cve_id
        assert full_chain[0]["weakness_id"] == weakness.weakness_id
        assert full_chain[0]["technique_id"] == technique.technique_id
        assert full_chain[0]["control_id"] == control.control_id


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
