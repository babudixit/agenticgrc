"""Mapping agent (Deliverable 5) — a LangGraph state machine that maps a single
UnifiedFinding to candidate ATT&CK techniques and mitigating controls.

Architecture (spec's "deterministic modules for data movement, LLM agents only
for reasoning", carried through every prior deliverable):

- Graph traversal (Neo4j, via `neo4j_tools.run_read_query`) and semantic
  search (ChromaDB, via `chroma_tools.semantic_search_attack_techniques`) are
  the deterministic data-movement tools. This module wires them up and
  exposes them to Claude as tool-use tools, but never itself decides which
  CVE/CWE/technique/control belongs in the final answer — that reasoning is
  entirely Claude's.
- Claude drives the loop via the raw Anthropic Python SDK (not a LangChain
  chat-model wrapper — the project's chosen LLM client is the SDK directly).
  It may call `run_cypher_query` and/or `semantic_search_attack_techniques`
  any number of times, then must finish by calling `submit_mapped_finding`
  with its structured final answer. Forcing the final answer through a tool
  call (rather than asking for raw JSON in text) is the reliable way to get
  structured output from Claude's tool-use API.
- LangGraph only orchestrates the loop (agent -> tools -> agent -> ... -> END
  or a hard `force_finish` once `max_tool_iterations` is exhausted); it holds
  no reasoning logic of its own.

There is deliberately no direct (:Weakness)-[:MAPS_TO]->(:AttackTechnique) edge
in the graph (see README's ingestion notes: CWE and ATT&CK are independently
maintained taxonomies and MITRE's CAPEC bridge was explicitly skipped for
Phase 1). Step 3 of the system prompt below is what tells Claude to reach for
semantic search instead of hunting for a graph edge that doesn't exist.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

import anthropic
import structlog
from anthropic.types import MessageParam, ToolParam
from chromadb.api.models.Collection import Collection
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from neo4j import Driver

from grc_agent.config.settings import get_settings
from grc_agent.schemas import (
    Framework,
    IngestionResult,
    MappedControl,
    MappedFinding,
    MappedTechnique,
    UnifiedFinding,
)
from grc_agent.tools.chroma_tools import (
    get_attack_technique_collection,
    get_chroma_client,
    semantic_search_attack_techniques,
)
from grc_agent.tools.neo4j_tools import get_driver, run_read_query

logger = structlog.get_logger(__name__)

DEFAULT_MAX_TOOL_ITERATIONS = 15
DEFAULT_MAX_TOKENS = 4096

CYPHER_TOOL_NAME = "run_cypher_query"
SEMANTIC_SEARCH_TOOL_NAME = "semantic_search_attack_techniques"
SUBMIT_TOOL_NAME = "submit_mapped_finding"

_GRAPH_SCHEMA_DESCRIPTION = """
Node labels and key properties:
  (:Vulnerability {cve_id, description, cvss_v3_score, cvss_v3_severity, in_kev, epss_score})
  (:Weakness {weakness_id, name, description, abstraction})
  (:AttackTechnique {technique_id, name, description, tactics, is_subtechnique, parent_technique_id})
  (:Control {uid, control_id, framework, title, statement, control_family})

Relationships:
  (:Vulnerability)-[:MAPS_TO]->(:Weakness)
  (:Weakness)-[:RELATES_TO]->(:Weakness)               (CWE hierarchy)
  (:AttackTechnique)-[:MAPS_TO {mapping_type}]->(:Control)
  (:Control)-[:RELATES_TO]->(:Control)
  (:Control)-[:ENHANCES]->(:Control)

There is deliberately NO edge directly from (:Weakness) to (:AttackTechnique) —
CWE and ATT&CK are independently maintained taxonomies with no official
crosswalk loaded in Phase 1. To bridge a CWE to an ATT&CK technique, use the
semantic_search_attack_techniques tool instead of looking for a graph edge.
""".strip()

_SUBMIT_TOOL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "matched_weaknesses": {
            "type": "array",
            "items": {"type": "string"},
            "description": "CWE IDs you confirmed are relevant to this finding.",
        },
        "matched_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "name": {"type": "string"},
                    "match_method": {
                        "type": "string",
                        "enum": ["direct", "graph_traversal", "semantic_search"],
                    },
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "rationale": {"type": "string"},
                },
                "required": ["technique_id", "match_method", "confidence"],
            },
        },
        "matched_controls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "control_id": {"type": "string"},
                    "framework": {"type": "string", "enum": [f.value for f in Framework]},
                    "title": {"type": "string"},
                    "via_technique_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                },
                "required": ["control_id", "framework", "confidence"],
            },
        },
        "reasoning": {
            "type": "string",
            "description": "Concise justification for the mapping, citing the evidence used.",
        },
        "overall_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
    "required": ["reasoning", "overall_confidence"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": CYPHER_TOOL_NAME,
        "description": (
            "Run a read-only Cypher query against the compliance knowledge graph to look "
            "up vulnerabilities, weaknesses, ATT&CK techniques, controls, and the "
            "relationships between them. Only MATCH/RETURN/WHERE-style read queries are "
            "allowed; any write clause is rejected.\n\n" + _GRAPH_SCHEMA_DESCRIPTION
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The Cypher query to run."},
                "parameters": {
                    "type": "object",
                    "description": "Optional query parameters, referenced in `query` as $name.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": SEMANTIC_SEARCH_TOOL_NAME,
        "description": (
            "Semantically search ATT&CK technique names/descriptions for the closest "
            "matches to a piece of free text (typically a CWE's name + description). Use "
            "this whenever graph traversal from a CWE doesn't reach an AttackTechnique "
            "node, since no such edge exists in the graph."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query_text": {"type": "string"},
                "top_k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
            },
            "required": ["query_text"],
        },
    },
    {
        "name": SUBMIT_TOOL_NAME,
        "description": (
            "Submit your final mapping for this finding. Call this exactly once, after "
            "you've explored the graph and/or run semantic search as needed — this ends "
            "the mapping process."
        ),
        "input_schema": _SUBMIT_TOOL_INPUT_SCHEMA,
    },
]

_SYSTEM_PROMPT = (
    "You are a cybersecurity compliance-mapping analyst. Given one normalized security "
    "finding, determine which MITRE ATT&CK techniques it relates to and which compliance "
    "controls mitigate those techniques, citing concrete evidence from the knowledge "
    "graph and/or semantic search — never guess a technique or control ID from memory.\n\n"
    "Process:\n"
    "1. Start from the finding's own CVEs/CWEs/ATT&CK-technique IDs.\n"
    "2. Use run_cypher_query to traverse Vulnerability -> Weakness, and "
    "AttackTechnique -> Control, gathering deterministic ('graph_traversal') evidence. "
    "If the finding names ATT&CK techniques directly, treat those as 'direct' matches "
    "(still verify their controls via the graph).\n"
    "3. If a CWE has no path to an AttackTechnique, call "
    "semantic_search_attack_techniques with the CWE's name + description as the query "
    "text, and label any resulting matches 'semantic_search' with confidence taken from "
    "the tool's similarity score.\n"
    "4. Once you've gathered enough evidence (or exhausted reasonable options), call "
    "submit_mapped_finding exactly once with your final answer, concise reasoning, and "
    "honest confidence scores. Do not call it more than once, and do not answer in plain "
    "text instead of calling it.\n\n" + _GRAPH_SCHEMA_DESCRIPTION
)


def _finding_summary(finding: UnifiedFinding) -> str:
    payload = finding.model_dump(
        mode="json",
        include={
            "finding_id",
            "title",
            "description",
            "severity",
            "cves",
            "cwes",
            "cpes",
            "mitre_techniques",
        },
    )
    return "Map this finding:\n\n" + json.dumps(payload, indent=2)


class MappingState(TypedDict):
    """LangGraph state. Plain dicts/lists throughout (no LangChain message
    types) to stay directly on the Anthropic SDK's native message format.
    """

    messages: list[dict[str, Any]]
    iterations: int
    final_output: dict[str, Any] | None


class ToolContext:
    """Bundles the live tool dependencies the `tools` node dispatches to.

    Kept separate from `MappingState` because it's process-local
    infrastructure (a driver, a collection handle), not JSON-serializable
    graph state, and is injected once per agent run.
    """

    def __init__(
        self, *, driver: Driver, database: str | None, chroma_collection: Collection
    ) -> None:
        self.driver = driver
        self.database = database
        self.chroma_collection = chroma_collection

    def dispatch(self, tool_name: str, tool_input: dict[str, Any]) -> Any:
        if tool_name == CYPHER_TOOL_NAME:
            return run_read_query(
                tool_input["query"],
                tool_input.get("parameters"),
                driver=self.driver,
                database=self.database,
            )
        if tool_name == SEMANTIC_SEARCH_TOOL_NAME:
            return semantic_search_attack_techniques(
                tool_input["query_text"],
                collection=self.chroma_collection,
                top_k=tool_input.get("top_k", 5),
            )
        raise ValueError(f"Unknown tool: {tool_name!r}")


def build_graph(
    *,
    anthropic_client: anthropic.Anthropic,
    tool_context: ToolContext,
    model: str,
    max_tool_iterations: int = DEFAULT_MAX_TOOL_ITERATIONS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> CompiledStateGraph:
    """Build and compile the mapping agent's LangGraph state machine.

    Exposed as its own function (rather than inlined in `map_finding`) so
    tests can compile a graph against a mocked Anthropic client/tool context
    and drive it directly.
    """

    def call_model(state: MappingState) -> dict[str, Any]:
        # TOOLS/messages are plain JSON-shaped dicts by design (see module
        # docstring: no LangChain message types, direct Anthropic SDK use) —
        # they conform to ToolParam/MessageParam at runtime, so cast rather
        # than duplicate the state as typed-dict instances just to satisfy mypy.
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=_SYSTEM_PROMPT,
            tools=cast(list[ToolParam], TOOLS),
            messages=cast(list[MessageParam], state["messages"]),
        )
        assistant_content = [_content_block_to_dict(block) for block in response.content]
        messages = [*state["messages"], {"role": "assistant", "content": assistant_content}]

        submit_block = next(
            (
                b
                for b in assistant_content
                if b.get("type") == "tool_use" and b["name"] == SUBMIT_TOOL_NAME
            ),
            None,
        )
        if submit_block is not None:
            return {"messages": messages, "final_output": submit_block["input"]}
        return {"messages": messages, "iterations": state["iterations"] + 1}

    def run_tools(state: MappingState) -> dict[str, Any]:
        last_message = state["messages"][-1]
        tool_use_blocks = [b for b in last_message["content"] if b.get("type") == "tool_use"]

        tool_results = []
        for block in tool_use_blocks:
            try:
                output = tool_context.dispatch(block["name"], block["input"])
            except (
                Exception
            ) as exc:  # noqa: BLE001 — surface any tool failure to the model, not the caller
                logger.warning("mapping_agent_tool_error", tool=block["name"], error=str(exc))
                output = {"error": str(exc)}
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block["id"],
                    "content": json.dumps(output, default=str),
                }
            )
        return {"messages": [*state["messages"], {"role": "user", "content": tool_results}]}

    def force_finish(state: MappingState) -> dict[str, Any]:
        logger.warning("mapping_agent_forced_finish", iterations=state["iterations"])
        return {
            "final_output": {
                "matched_weaknesses": [],
                "matched_techniques": [],
                "matched_controls": [],
                "reasoning": "The agent did not submit a structured mapping within its "
                f"{max_tool_iterations}-turn budget; returning an empty, zero-confidence result.",
                "overall_confidence": 0.0,
            }
        }

    def route(state: MappingState) -> Literal["tools", "force_finish", "end"]:
        if state["final_output"] is not None:
            return "end"
        if state["iterations"] >= max_tool_iterations:
            return "force_finish"
        last_message = state["messages"][-1]
        has_tool_use = any(b.get("type") == "tool_use" for b in last_message["content"])
        return "tools" if has_tool_use else "force_finish"

    graph = StateGraph(MappingState)
    graph.add_node("agent", call_model)
    graph.add_node("tools", run_tools)
    graph.add_node("force_finish", force_finish)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges(
        "agent", route, {"tools": "tools", "force_finish": "force_finish", "end": END}
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("force_finish", END)
    return graph.compile()


def _content_block_to_dict(block: Any) -> dict[str, Any]:
    if hasattr(block, "model_dump"):
        return dict(block.model_dump())
    return dict(block)


def map_finding(
    finding: UnifiedFinding,
    *,
    anthropic_client: anthropic.Anthropic,
    neo4j_driver: Driver,
    chroma_collection: Collection,
    database: str | None = None,
    model: str | None = None,
    max_tool_iterations: int = DEFAULT_MAX_TOOL_ITERATIONS,
    agent_run_id: str | None = None,
) -> MappedFinding:
    """Run the mapping agent end-to-end on a single finding and return a MappedFinding.

    All external dependencies (Anthropic client, Neo4j driver, Chroma
    collection) are injected so this — and everything it calls — can be
    unit-tested with no live network/database access (matching the "no live
    API calls in tests" convention).
    """
    settings = get_settings()
    resolved_model = model or settings.llm_model_mapping
    run_id = agent_run_id or f"mapping-{uuid.uuid4().hex[:12]}"

    tool_context = ToolContext(
        driver=neo4j_driver, database=database, chroma_collection=chroma_collection
    )
    compiled_graph = build_graph(
        anthropic_client=anthropic_client,
        tool_context=tool_context,
        model=resolved_model,
        max_tool_iterations=max_tool_iterations,
    )

    initial_state: MappingState = {
        "messages": [{"role": "user", "content": _finding_summary(finding)}],
        "iterations": 0,
        "final_output": None,
    }
    final_state = compiled_graph.invoke(
        initial_state, config={"recursion_limit": max_tool_iterations * 2 + 10}
    )

    output: dict[str, Any] = final_state["final_output"] or {}
    matched_techniques = [MappedTechnique(**t) for t in output.get("matched_techniques") or []]
    matched_controls = [MappedControl(**c) for c in output.get("matched_controls") or []]

    mapped = MappedFinding(
        finding_id=finding.finding_id,
        agent_run_id=run_id,
        model_used=resolved_model,
        matched_cves=finding.cves,
        matched_weaknesses=output.get("matched_weaknesses") or finding.cwes,
        matched_techniques=matched_techniques,
        matched_controls=matched_controls,
        reasoning=output.get("reasoning", ""),
        overall_confidence=output.get("overall_confidence", 0.0),
    )
    logger.info(
        "finding_mapped",
        finding_id=finding.finding_id,
        agent_run_id=run_id,
        techniques=len(matched_techniques),
        controls=len(matched_controls),
        confidence=mapped.overall_confidence,
    )
    return mapped


def run_batch(input_path: Path, output_path: Path) -> IngestionResult:
    """Map every UnifiedFinding in a JSON-Lines file, writing one MappedFinding
    per line. Builds real Anthropic/Neo4j/ChromaDB clients from settings —
    intended for CLI/production use, not for unit tests (use `map_finding`
    with injected fakes for those).
    """
    settings = get_settings()
    result = IngestionResult(source_name="mapping_agent")

    findings: list[UnifiedFinding] = []
    with input_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(UnifiedFinding.model_validate_json(line))

    if settings.anthropic_api_key is None:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not configured; set it in .env before running the agent."
        )

    anthropic_client = anthropic.Anthropic(api_key=settings.anthropic_api_key.get_secret_value())
    chroma_client = get_chroma_client()
    chroma_collection = get_attack_technique_collection(chroma_client)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with get_driver() as driver, output_path.open("w", encoding="utf-8") as out:
        for finding in findings:
            try:
                mapped = map_finding(
                    finding,
                    anthropic_client=anthropic_client,
                    neo4j_driver=driver,
                    chroma_collection=chroma_collection,
                    agent_run_id=result.run_id,
                )
            except Exception as exc:  # noqa: BLE001 — one bad finding shouldn't abort the batch
                result.record_error(f"{finding.finding_id}: {exc}")
                continue
            out.write(mapped.model_dump_json() + "\n")
            result.record_success()

    result.output_path = str(output_path)
    result.finish()
    logger.info(
        "mapping_batch_complete",
        run_id=result.run_id,
        records_written=result.records_written,
        records_failed=result.records_failed,
        duration_seconds=result.duration_seconds,
    )
    return result


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Map UnifiedFinding JSON-Lines to MappedFinding JSON-Lines via the "
        "LangGraph mapping agent."
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to findings JSON-Lines.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/mapped_findings.jsonl"),
        help="Output JSON-Lines path (default: data/mapped_findings.jsonl).",
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("mapping_agent_input_not_found", input_path=str(args.input))
        return 1

    try:
        result = run_batch(args.input, args.output)
    except (OSError, ValueError, RuntimeError) as exc:
        logger.error("mapping_agent_failed", error=str(exc))
        return 1

    if not result.success:
        logger.error(
            "mapping_agent_had_failures", records_failed=result.records_failed, errors=result.errors
        )
        return 1

    print(f"Mapped {result.records_written} findings to {result.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
