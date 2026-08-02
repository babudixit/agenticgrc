"""Unit tests for grc_agent.tools.neo4j_tools.

No live Neo4j connection is used — the driver is mocked so these tests run
anywhere, including CI with no database available.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from neo4j.exceptions import ServiceUnavailable

from grc_agent.tools.neo4j_tools import _run_cli, verify_connectivity


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
