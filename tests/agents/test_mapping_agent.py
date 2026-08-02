"""Unit tests for the mapping agent's LangGraph state machine.

No live Anthropic/Neo4j/ChromaDB access is used: the Anthropic client's
`messages.create` is scripted with `side_effect`, and the Neo4j driver /
Chroma collection are `MagicMock`s configured to return fixture data — this
exercises the full agent-tool-agent loop and the final MappedFinding
assembly deterministically and offline.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from grc_agent.agents.mapping_agent import (
    CYPHER_TOOL_NAME,
    SEMANTIC_SEARCH_TOOL_NAME,
    SUBMIT_TOOL_NAME,
    ToolContext,
    map_finding,
)
from grc_agent.schemas import MatchMethod, UnifiedFinding


class _FakeBlock:
    """Stands in for an Anthropic SDK content block (TextBlock/ToolUseBlock)."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def model_dump(self) -> dict[str, Any]:
        return self._data


class _FakeResponse:
    def __init__(self, content: list[dict[str, Any]]) -> None:
        self.content = [_FakeBlock(block) for block in content]


def _tool_use_block(tool_use_id: str, name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": tool_use_id, "name": name, "input": tool_input}


def _mock_neo4j_driver(records: list[dict[str, Any]]) -> MagicMock:
    driver = MagicMock()
    driver.execute_query.return_value = (records, MagicMock(), MagicMock())
    return driver


def _mock_chroma_collection(matches: list[dict[str, Any]]) -> MagicMock:
    collection = MagicMock()
    collection.count.return_value = max(len(matches), 1)
    collection.query.return_value = {
        "ids": [[m["technique_id"] for m in matches]],
        "distances": [[m["distance"] for m in matches]],
        "metadatas": [[{"name": m["name"], "tactics": ",".join(m["tactics"])} for m in matches]],
    }
    return collection


@pytest.fixture
def finding() -> UnifiedFinding:
    return UnifiedFinding(
        finding_id="tenable:144982:prod-web-01",
        source_system="Tenable.io",
        source_class="vulnerability_scanner",
        source_finding_id="144982",
        timestamp="2024-05-18T02:11:00Z",
        severity="High",
        vendor_severity="high",
        title="OpenSSH 8.2 < 8.5 Multiple Vulnerabilities",
        description="OpenSSH version 8.2 is installed on the remote host.",
        affected_assets=["prod-web-01"],
        cves=["CVE-2021-3156"],
        cwes=[],
        cpes=["cpe:2.3:a:openbsd:openssh:8.2"],
        mitre_techniques=[],
        raw_source={"plugin": {"id": 144982}},
    )


def test_map_finding_full_tool_loop(finding: UnifiedFinding) -> None:
    """Simulates: agent runs Cypher -> agent runs semantic search -> agent submits."""
    anthropic_client = MagicMock()
    anthropic_client.messages.create.side_effect = [
        _FakeResponse(
            [
                _tool_use_block(
                    "call_1",
                    CYPHER_TOOL_NAME,
                    {
                        "query": "MATCH (v:Vulnerability {cve_id: $cve_id})-[:MAPS_TO]->(w:Weakness) "
                        "RETURN w.weakness_id AS cwe_id",
                        "parameters": {"cve_id": "CVE-2021-3156"},
                    },
                )
            ]
        ),
        _FakeResponse(
            [
                _tool_use_block(
                    "call_2",
                    SEMANTIC_SEARCH_TOOL_NAME,
                    {"query_text": "out-of-bounds write buffer overflow", "top_k": 3},
                )
            ]
        ),
        _FakeResponse(
            [
                _tool_use_block(
                    "call_3",
                    SUBMIT_TOOL_NAME,
                    {
                        "matched_weaknesses": ["CWE-787"],
                        "matched_techniques": [
                            {
                                "technique_id": "T1068",
                                "name": "Exploitation for Privilege Escalation",
                                "match_method": "semantic_search",
                                "confidence": 0.75,
                                "rationale": "Semantic match on memory-corruption description.",
                            }
                        ],
                        "matched_controls": [
                            {
                                "control_id": "SI-2",
                                "framework": "NIST_SP_800-53_r5",
                                "title": "Flaw Remediation",
                                "via_technique_ids": ["T1068"],
                                "confidence": 0.75,
                            }
                        ],
                        "reasoning": "CVE-2021-3156 maps to CWE-787; semantic search found T1068 as "
                        "the closest ATT&CK technique, mitigated by SI-2.",
                        "overall_confidence": 0.75,
                    },
                )
            ]
        ),
    ]

    driver = _mock_neo4j_driver([{"cwe_id": "CWE-787"}])
    collection = _mock_chroma_collection(
        [
            {
                "technique_id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "tactics": ["privilege-escalation"],
                "distance": 0.5,
            }
        ]
    )

    mapped = map_finding(
        finding,
        anthropic_client=anthropic_client,
        neo4j_driver=driver,
        chroma_collection=collection,
        model="claude-sonnet-4-5",
        agent_run_id="run-test-1",
    )

    assert anthropic_client.messages.create.call_count == 3
    assert mapped.finding_id == "tenable:144982:prod-web-01"
    assert mapped.agent_run_id == "run-test-1"
    assert mapped.model_used == "claude-sonnet-4-5"
    assert mapped.matched_cves == ["CVE-2021-3156"]
    assert mapped.matched_weaknesses == ["CWE-787"]
    assert len(mapped.matched_techniques) == 1
    assert mapped.matched_techniques[0].match_method is MatchMethod.SEMANTIC_SEARCH
    assert mapped.matched_controls[0].control_id == "SI-2"
    assert mapped.overall_confidence == pytest.approx(0.75)

    # The Cypher tool actually reached the mocked driver.
    driver.execute_query.assert_called_once()
    # The semantic search tool actually reached the mocked collection.
    collection.query.assert_called_once()


def test_map_finding_submits_immediately_with_no_tool_calls(finding: UnifiedFinding) -> None:
    anthropic_client = MagicMock()
    anthropic_client.messages.create.side_effect = [
        _FakeResponse(
            [
                _tool_use_block(
                    "call_1",
                    SUBMIT_TOOL_NAME,
                    {"reasoning": "No CVEs/CWEs could be resolved.", "overall_confidence": 0.0},
                )
            ]
        ),
    ]

    driver = _mock_neo4j_driver([])
    collection = _mock_chroma_collection([])

    mapped = map_finding(
        finding,
        anthropic_client=anthropic_client,
        neo4j_driver=driver,
        chroma_collection=collection,
    )

    assert anthropic_client.messages.create.call_count == 1
    assert mapped.matched_techniques == []
    assert mapped.matched_controls == []
    assert mapped.overall_confidence == 0.0
    driver.execute_query.assert_not_called()


def test_map_finding_forces_finish_when_agent_never_submits(finding: UnifiedFinding) -> None:
    """If the model just keeps calling Cypher and never submits, the agent must
    still terminate (bounded by max_tool_iterations) instead of looping forever."""
    anthropic_client = MagicMock()
    anthropic_client.messages.create.side_effect = [
        _FakeResponse(
            [_tool_use_block(f"call_{i}", CYPHER_TOOL_NAME, {"query": "MATCH (n) RETURN n"})]
        )
        for i in range(10)
    ]
    driver = _mock_neo4j_driver([{"n": 1}])
    collection = _mock_chroma_collection([])

    mapped = map_finding(
        finding,
        anthropic_client=anthropic_client,
        neo4j_driver=driver,
        chroma_collection=collection,
        max_tool_iterations=3,
    )

    assert anthropic_client.messages.create.call_count == 3
    assert mapped.overall_confidence == 0.0
    assert mapped.matched_techniques == []
    assert "did not submit" in mapped.reasoning


def test_map_finding_rejects_unsafe_cypher_and_continues(finding: UnifiedFinding) -> None:
    """An unsafe (write) Cypher query is fed back to the model as a tool error
    instead of ever reaching the database, and the agent can still recover."""
    anthropic_client = MagicMock()
    anthropic_client.messages.create.side_effect = [
        _FakeResponse(
            [_tool_use_block("call_1", CYPHER_TOOL_NAME, {"query": "MATCH (n) DETACH DELETE n"})]
        ),
        _FakeResponse(
            [
                _tool_use_block(
                    "call_2",
                    SUBMIT_TOOL_NAME,
                    {
                        "reasoning": "Query rejected; nothing further to report.",
                        "overall_confidence": 0.0,
                    },
                )
            ]
        ),
    ]
    driver = _mock_neo4j_driver([])
    collection = _mock_chroma_collection([])

    mapped = map_finding(
        finding,
        anthropic_client=anthropic_client,
        neo4j_driver=driver,
        chroma_collection=collection,
    )

    driver.execute_query.assert_not_called()
    assert mapped.overall_confidence == 0.0

    # The rejected-query error was fed back to the model as a tool_result.
    second_call_kwargs = anthropic_client.messages.create.call_args_list[1].kwargs
    tool_result_messages = [m for m in second_call_kwargs["messages"] if m["role"] == "user"]
    last_tool_result = tool_result_messages[-1]["content"][0]
    assert "Refusing to execute" in last_tool_result["content"]


def test_tool_context_dispatch_rejects_unknown_tool() -> None:
    context = ToolContext(driver=MagicMock(), database=None, chroma_collection=MagicMock())

    with pytest.raises(ValueError, match="Unknown tool"):
        context.dispatch("not_a_real_tool", {})
