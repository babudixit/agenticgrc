# Cybersecurity Agentic GRC Tool

An autonomous system that ingests **structured** security findings from an
organization's existing vulnerability scanners, cloud security tools (CSPM),
and SIEMs, correlates them against authoritative compliance reference data
(NIST, CIS, MITRE ATT&CK), and produces audit-defensible findings and Plans of
Action and Milestones (POA&Ms).

This is not a detection engine — it performs **compliance interpretation**:
taking findings that already exist and translating them into the language of
NIST controls, CIS safeguards, ATT&CK techniques, and executive-ready risk
narratives. See `Cybersecurity Agentic GRC Tool.docx` (Requirements
Specification v2.0) for the full spec.

## Architecture at a glance

- **Deterministic modules for data movement.** Every reference-data ingester,
  vendor normalizer, and graph loader is a plain, unit-tested Python module.
  LLM calls are confined to the compliance-mapping and finding-synthesis
  agents.
- **Unified Pydantic schemas as the internal contract.** `UnifiedControl`,
  `UnifiedVulnerability`, `UnifiedAsset`, `UnifiedFinding`, `UnifiedWeakness`
  (CWE), `UnifiedAttackTechnique` (MITRE ATT&CK), `AttackControlMapping`
  (technique→control edges), `MappedFinding` (the mapping agent's output).
  Vendor-specific field names never leak past a normalizer boundary.
- **JSON-Lines as the interchange format** between ingesters/normalizers and
  loaders, keeping ingestion and storage independently testable.
- **LangGraph** for agent orchestration; read-only Neo4j Cypher and ChromaDB
  semantic search are exposed to the mapping agent as tools (KEV/EPSS lookups
  planned for the synthesis agent).
- **Claude (Anthropic SDK)** as the LLM reasoning engine — `claude-sonnet-4-5`
  by default, with headroom to upgrade the synthesis agent to Opus.

## Project layout

```
Dev/
├── pyproject.toml          # Packaging, ruff, black, mypy, pytest config
├── docker-compose.yml      # Neo4j Community Edition (+ optional Chroma server)
├── .env.example            # Template for all environment variables
├── conftest.py             # Repo-wide pytest hooks
├── grc_agent/               # The installable package
│   ├── schemas/             # Pydantic models — UnifiedControl, UnifiedFinding, etc.
│   ├── ingesters/           # One module per reference-data source (NIST, MITRE CWE/ATT&CK, NVD, CTID...)
│   ├── normalizers/         # One module per scanner/CSPM/SIEM vendor (Tenable first)
│   ├── loaders/             # JSON-Lines → Neo4j / ChromaDB
│   ├── agents/               # LangGraph state machines (mapping, then synthesis)
│   ├── tools/                # Tool wrappers for agent use (Neo4j, Chroma, KEV/EPSS)
│   ├── api/                  # FastAPI endpoints (built after agents work)
│   └── config/                # pydantic-settings configuration
└── tests/
    ├── schemas/
    ├── tools/
    ├── ingesters/
    ├── loaders/
    ├── normalizers/
    └── agents/
```

`grc_agent` is both the pip distribution name (`grc-agent`) and the Python
import name (`grc_agent`), installed in editable mode so every module doubles
as a CLI entry point, e.g. `python -m grc_agent.ingesters.nist_sp800_53`.

## Prerequisites

- Python 3.11+
- Docker Desktop (or another Docker Engine) for Neo4j
- An Anthropic API key (`ANTHROPIC_API_KEY` in `.env`) to run the mapping
  agent, and read-only API credentials for the vendors you're integrating
  (Tenable to start)

## Setup

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. Install the package in editable mode with dev tooling
pip install -e ".[dev]"

# 3. Copy the environment template and adjust as needed
copy .env.example .env

# 4. Start Neo4j (Community Edition)
docker-compose up -d neo4j

# 5. Verify the toolchain
pytest
ruff check .
black --check .
mypy
```

Neo4j's browser UI is then available at http://localhost:7474 (default
credentials `neo4j` / whatever you set `NEO4J_PASSWORD` to in `.env`, default
`changeme123`). Bolt is on `bolt://localhost:7687`.

ChromaDB runs **embedded** (persistent, SQLite-backed, in-process via the
`chromadb` Python client) — no separate container is required. A `chromadb`
service is defined in `docker-compose.yml` under the `server` profile for
teams that later prefer a standalone Chroma server (`docker-compose --profile
server up -d`), but it is not started by default.

## Configuration

All configuration is environment-variable driven via `pydantic-settings`
(`grc_agent/config/settings.py`). See `.env.example` for the full list —
Neo4j connection details, ChromaDB persistence directory, LLM model names,
vendor API credentials, and reference-data refresh cadences. No secrets are
ever hard-coded; secret-typed fields (`SecretStr`) are automatically redacted
when settings are logged.

Inspect the resolved (secret-redacted) configuration at any time:

```powershell
python -m grc_agent.config.settings
```

## Conventions

- Python 3.11+, all functions fully typed (`mypy` enforced).
- `ruff` for linting, `black` for formatting.
- `pytest` with fixtures for all external data — no live API calls in tests.
- Every ingester/normalizer module has a `__main__` entry point and accepts
  `--output` to write JSON-Lines; every loader accepts `--input` to read it.
- Structured logging via `structlog` — no `print()` statements in library
  code (CLI-facing summaries are the exception).
- No secrets in code; `.env` is git-ignored, `.env.example` is the template.

## Ingesting & loading NIST SP 800-53 (Deliverable 3)

```powershell
# 1. Fetch the OSCAL catalog from NIST's GitHub-hosted source and parse it
#    into UnifiedControl JSON-Lines (defaults shown; --source also accepts a
#    local file path, e.g. for air-gapped/offline use per NFR-06).
python -m grc_agent.ingesters.nist_sp800_53 --output data/sp800_53.jsonl

# 2. Load those records into Neo4j as (:Control) nodes, wired up with
#    RELATES_TO edges (cross-references) and ENHANCES edges (control
#    enhancements, e.g. AC-2(1) -[:ENHANCES]-> AC-2). Idempotent — safe to
#    re-run after every refresh.
python -m grc_agent.loaders.neo4j_loader --input data/sp800_53.jsonl
```

Both commands emit a structured `IngestionResult` summary (records
processed/written/failed, duration, run ID) via `structlog`. The full
Rev 5 catalog (~1,200 controls including enhancements) loads in a couple of
seconds.

## Normalizing Tenable findings (Deliverable 4)

```powershell
python -m grc_agent.normalizers.tenable --input path\to\tenable_export.json --output data\tenable_findings.jsonl
```

Accepts either a Tenable export shaped as `{"findings": [...]}` or a bare
JSON array of finding objects. Each finding is normalized into a
`UnifiedFinding` — severity is mapped onto the canonical scale while the
vendor's own rating is preserved verbatim (`vendor_severity`), CVEs/CPEs are
validated and normalized, and the per-host scan `output` text is folded into
`description` alongside Tenable's generic plugin description. Malformed
records are skipped (and reported in the run's `IngestionResult.errors`)
rather than aborting the whole run.

## Ingesting the CVE/CWE/ATT&CK reference graph (Deliverable 5 prep)

Before the mapping agent can traverse CVE→CWE→ATT&CK→Controls, that whole
chain needs to exist in Neo4j. Four ingesters build it, each independently
runnable and idempotent:

```powershell
# CWE catalog -> UnifiedWeakness (~970 weaknesses, a few seconds)
python -m grc_agent.ingesters.mitre_cwe --output data/cwe.jsonl

# ATT&CK Enterprise techniques/sub-techniques/tactics -> UnifiedAttackTechnique
# (~700 objects; revoked/deprecated techniques are excluded)
python -m grc_agent.ingesters.mitre_attack --output data/attack_techniques.jsonl

# CTID's ATT&CK-to-NIST-800-53-Rev5 "mitigates" mappings -> AttackControlMapping
# (~5,300 mappings; closes the ATT&CK->Controls hop)
python -m grc_agent.ingesters.ctid_attack_control_mappings --output data/attack_control_mappings.jsonl

# NVD CVEs, bulk by publication date range -> UnifiedVulnerability
# (chunks the range into NVD's 120-day API windows automatically; an
# NVD_API_KEY in .env raises the rate limit from 5 to 50 requests/30s)
python -m grc_agent.ingesters.nist_nvd --start-date 2024-08-02 --end-date 2026-08-02 --output data/nvd_cves.jsonl
```

Then load each JSON-Lines file with `neo4j_loader.py`'s `--record-type` flag
(the loader was extended in Deliverable 5 from Control-only to every node
type below; loading order doesn't matter — edges are created with a
node-existence-checking `MATCH`, so a CVE ingested before its CWE, or a
mapping loaded before its technique, simply creates the node now and the
edge on the next reload):

```powershell
python -m grc_agent.loaders.neo4j_loader --input data/cwe.jsonl --record-type weakness
python -m grc_agent.loaders.neo4j_loader --input data/attack_techniques.jsonl --record-type attack_technique
python -m grc_agent.loaders.neo4j_loader --input data/attack_control_mappings.jsonl --record-type attack_control_mapping
python -m grc_agent.loaders.neo4j_loader --input data/nvd_cves.jsonl --record-type vulnerability
```

Verified end-to-end against real data in a live Neo4j container:

| Label / relationship | Count |
| --- | --- |
| `(:Vulnerability)` (CVEs, last 2 years) | 113,648 |
| `(:Control)` | 1,196 |
| `(:Weakness)` (CWEs) | 969 |
| `(:AttackTechnique)` | 697 |
| `[:MAPS_TO]` (Vulnerability→Weakness, AttackTechnique→Control) | 127,273 |
| `[:RELATES_TO]` | 4,870 |
| `[:ENHANCES]` | 872 |

A sample traversal confirms the chain works end-to-end, e.g.
`CVE-2026-48760 -[:MAPS_TO]-> CWE-1007`, and separately
`T1055.011 (Extra Window Memory Injection) -[:MAPS_TO {mapping_type:
"mitigates"}]-> SC-7 (Boundary Protection)`. Note there is intentionally no
direct `(:Weakness)-->(:AttackTechnique)` edge — per an explicit scope
decision, that hop has no reliable public mapping (CWE and ATT&CK are
maintained independently) and is left to the mapping agent's ChromaDB
semantic-search fallback rather than an unreliable CAPEC bridge.

## The mapping agent (Deliverable 5)

`agents/mapping_agent.py` is a **LangGraph** state machine that maps a single
`UnifiedFinding` to candidate ATT&CK techniques and mitigating controls,
returning a `MappedFinding` (`schemas/mapped_finding.py`: `matched_cves`,
`matched_weaknesses`, `matched_techniques`/`matched_controls` — each with a
`match_method` and per-match confidence — plus an LLM-written `reasoning`
narrative and `overall_confidence`).

**Architecture — same "deterministic modules, LLM only reasons" rule as
every other deliverable:**

- Graph traversal and semantic search are the deterministic tools; they never
  decide what belongs in the final answer.
- `tools/neo4j_tools.run_read_query` exposes **read-only Cypher** as a tool:
  the query text is LLM-generated, so it's guarded as untrusted input — a
  regex rejects any write clause/procedure (`CREATE`, `MERGE`, `DELETE`,
  `SET`, `DROP`, `CALL apoc.periodic...`, `CALL dbms...`, etc.) *before* the
  query reaches Neo4j, on top of requesting the driver's own `READ` routing
  mode.
- `tools/chroma_tools.py` builds/queries the `attack_techniques` Chroma
  collection (one document per technique: `"{name}: {description}"`) for the
  CWE→ATT&CK semantic fallback. Embeddings use ChromaDB's bundled
  `DefaultEmbeddingFunction` — a local ONNX build of `all-MiniLM-L6-v2` (the
  same model named in `Settings.chroma_embedding_model`) — so there's no
  torch/sentence-transformers dependency, no GPU, and no external API calls
  or per-query cost for embedding.
- Claude drives the loop via the **raw Anthropic Python SDK** (not a
  LangChain chat-model wrapper, per the project's original LLM-client
  decision). It may call `run_cypher_query` and/or
  `semantic_search_attack_techniques` any number of times, then must finish
  by calling a terminal `submit_mapped_finding` tool with its structured
  answer — forcing the final answer through a tool call (rather than parsing
  free-form JSON from text) is what makes the structured output reliable.
  LangGraph only orchestrates `agent -> tools -> agent -> ... -> END`, plus a
  hard `force_finish` fallback if `max_tool_iterations` (default 15) is
  exhausted without a submission, so the agent can never loop forever or run
  away on API cost.
- Every external dependency (Anthropic client, Neo4j driver, Chroma
  collection) is injected, so `map_finding()` — and the whole LangGraph state
  machine — is fully unit-testable with `unittest.mock` and a fake,
  network-free embedding function; no live API/DB access happens in tests.

```powershell
# One-time: embed all ingested ATT&CK techniques into the Chroma collection
# the semantic-search tool queries (re-run after every ATT&CK refresh).
python -m grc_agent.tools.chroma_tools --input data/attack_techniques.jsonl

# Map every finding in a JSON-Lines file to a MappedFinding.
python -m grc_agent.agents.mapping_agent --input data/tenable_findings.jsonl --output data/mapped_findings.jsonl
```

**Verified live** against a real Neo4j graph (113K+ CVEs, 969 CWEs, 697 ATT&CK
techniques), a real ChromaDB collection, and real Claude (`claude-sonnet-4-5`)
calls, on a CVE with a real graph-loaded CWE mapping (CVE-2025-27223 → static
cookie-encryption key): the agent traversed `Vulnerability -[:MAPS_TO]->
Weakness (CWE-1004)`, explored the CWE hierarchy for closer matches
(landing on CWE-321/CWE-565/CWE-798), semantically matched those against
ATT&CK (`T1606.001` "Web Cookies" at 83.5% similarity, `T1550.004` "Web
Session Cookie", `T1539` "Steal Web Session Cookie"), traversed each
technique's `[:MAPS_TO]-> Control` edges, and submitted a mapping citing
8 NIST SP 800-53 controls (`SC-12`, `SC-23`, `IA-5`, `SI-2`, `AC-3`, `SC-8`,
`AC-6`, `AC-2`) with an overall confidence of 0.92 and a reasoning narrative
citing the specific graph/semantic evidence used at each step.

## Delivery roadmap (Phase 1)

Built incrementally, each deliverable working end-to-end before the next
begins:

1. **Foundation** ✅ — project skeleton, tooling config, Docker Compose for
   Neo4j, environment handling.
2. **Schemas** ✅ — `UnifiedControl`, `UnifiedVulnerability`, `UnifiedAsset`,
   `UnifiedFinding`, `SourceSystem`, `IngestionResult`, with full validation
   and round-trip test coverage.
3. **First ingester + loader** ✅ *(this deliverable)* —
   `ingesters/nist_sp800_53.py` (OSCAL JSON → `UnifiedControl` →
   `sp800_53.jsonl`) and `loaders/neo4j_loader.py` (JSON-Lines →
   `(:Control)` nodes with `RELATES_TO`/`ENHANCES` edges). Verified
   end-to-end against NIST's real Rev 5 catalog (1,196 controls, 4,383
   relationships) loaded into a live Neo4j container, including a
   reload-is-idempotent check.
4. **First vendor normalizer** ✅ *(this deliverable)* — `normalizers/tenable.py`
   (Tenable finding → `UnifiedFinding`). Verified against a real Tenable.io
   export (6 findings spanning single-CVE, multi-CVE, and zero-CVE/
   compliance-check patterns across critical/high/medium severities).
5. **First agent** ✅ *(this deliverable)* — `agents/mapping_agent.py`, a
   LangGraph state machine that maps a `UnifiedFinding` to `MappedFinding`
   (candidate ATT&CK techniques + mitigating controls, each with a
   `match_method`/confidence, plus an LLM reasoning narrative) via Neo4j
   graph traversal (exposed as a read-only, write-clause-guarded Cypher
   tool) with a ChromaDB semantic-search fallback for the CWE→ATT&CK hop.
   Claude drives the tool-use loop through the raw Anthropic SDK and finishes
   via a terminal `submit_mapped_finding` tool call for reliable structured
   output. Verified live end-to-end (see above) against the real Neo4j graph,
   a real 697-technique Chroma collection, and real Claude calls.

Deferred beyond these five: the synthesis agent, additional vendor
normalizers, the FastAPI layer, and the frontend/UI (Phase 3+).
