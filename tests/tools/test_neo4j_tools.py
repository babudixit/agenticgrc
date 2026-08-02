"""Unit tests for grc_agent.tools.neo4j_tools.

No live Neo4j connection is used — the driver is mocked so these tests run
anywhere, including CI with no database available.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from neo4j.exceptions import ServiceUnavailable

from grc_agent.tools.neo4j_tools import (
    UnsafeCypherQueryError,
    _run_cli,
    run_read_query,
    verify_connectivity,
)


def _mock_driver_returning(records: list[dict[str, object]]) -> MagicMock:
    driver = MagicMock()
    driver.__enter__.return_value = driver
    driver.__exit__.return_value = False
    driver.execute_query.return_value = (records, MagicMock(), MagicMock())
    return driver


def test_verify_connectivity_returns_server_info() -> None:
    record = {"name": "Neo4j Kernel", "version": "5.26.28", "edition": "community"}
    driver = _mock_driver_returning([record])

    with patch("grc_agent.tools.neo4j_tools.get_driver", return_value=driver):
        info = verify_connectivity()

    driver.verify_connectivity.assert_called_once()
    driver.execute_query.assert_called_once()
    assert info == record


def test_verify_connectivity_handles_empty_result() -> None:
    driver = _mock_driver_returning([])

    with patch("grc_agent.tools.neo4j_tools.get_driver", return_value=driver):
        info = verify_connectivity()

    assert info == {}


def test_cli_returns_nonzero_when_server_unreachable() -> None:
    with patch(
        "grc_agent.tools.neo4j_tools.verify_connectivity",
        side_effect=ServiceUnavailable("no connection"),
    ):
        exit_code = _run_cli([])

    assert exit_code == 1


def test_cli_returns_zero_on_success(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "grc_agent.tools.neo4j_tools.verify_connectivity",
        return_value={"name": "Neo4j Kernel", "version": "5.26.28", "edition": "community"},
    ):
        exit_code = _run_cli([])

    assert exit_code == 0
    assert "Neo4j Kernel 5.26.28" in capsys.readouterr().out


def test_run_read_query_returns_rows_as_dicts() -> None:
    rows = [{"cwe_id": "CWE-787"}, {"cwe_id": "CWE-193"}]
    driver = _mock_driver_returning(rows)

    result = run_read_query(
        "MATCH (v:Vulnerability {cve_id: $cve_id})-[:MAPS_TO]->(w:Weakness) RETURN w.weakness_id AS cwe_id",
        {"cve_id": "CVE-2021-3156"},
        driver=driver,
    )

    assert result == rows
    driver.execute_query.assert_called_once()
    _, kwargs = driver.execute_query.call_args
    assert kwargs["parameters_"] == {"cve_id": "CVE-2021-3156"}


def test_run_read_query_respects_row_limit() -> None:
    driver = _mock_driver_returning([{"n": i} for i in range(10)])

    result = run_read_query("MATCH (n) RETURN n", driver=driver, row_limit=3)

    assert len(result) == 3


@pytest.mark.parametrize(
    "cypher",
    [
        "MATCH (n) DETACH DELETE n",
        "CREATE (n:Evil) RETURN n",
        "MERGE (n:Control {control_id: 'AC-2'}) RETURN n",
        "MATCH (n) SET n.pwned = true RETURN n",
        "MATCH (n) REMOVE n.pwned RETURN n",
        "DROP CONSTRAINT foo",
        "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {})",
        "CALL dbms.shutdown()",
    ],
)
def test_run_read_query_rejects_write_clauses(cypher: str) -> None:
    driver = _mock_driver_returning([])

    with pytest.raises(UnsafeCypherQueryError):
        run_read_query(cypher, driver=driver)

    driver.execute_query.assert_not_called()


def test_run_read_query_allows_ordinary_reads() -> None:
    driver = _mock_driver_returning([{"name": "AC-2"}])

    result = run_read_query(
        "MATCH (c:Control) WHERE c.control_id = $id RETURN c.title AS name",
        {"id": "AC-2"},
        driver=driver,
    )

    assert result == [{"name": "AC-2"}]
