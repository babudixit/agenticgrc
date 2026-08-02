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
  `UnifiedVulnerability`, `UnifiedAsset`, `UnifiedFinding`. Vendor-specific
  field names never leak past a normalizer boundary.
- **JSON-Lines as the interchange format** between ingesters/normalizers and
  loaders, keeping ingestion and storage independently testable.
- **LangGraph** for agent orchestration; Neo4j Cypher, ChromaDB retrieval, KEV
  lookups, and EPSS lookups are exposed to agents as tools.
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
│   ├── ingesters/           # One module per reference-data source (NIST, MITRE, CISA, EPSS...)
│   ├── normalizers/         # One module per scanner/CSPM/SIEM vendor (Tenable first)
│   ├── loaders/             # JSON-Lines → Neo4j / ChromaDB
│   ├── agents/               # LangGraph state machines (mapping, then synthesis)
│   ├── tools/                # Tool wrappers for agent use (Neo4j, Chroma, KEV/EPSS)
│   ├── api/                  # FastAPI endpoints (built after agents work)
│   └── config/                # pydantic-settings configuration
└── tests/
    ├── ingesters/
    ├── normalizers/
    └── agents/
```

`grc_agent` is both the pip distribution name (`grc-agent`) and the Python
import name (`grc_agent`), installed in editable mode so every module doubles
as a CLI entry point, e.g. `python -m grc_agent.ingesters.nist_sp800_53`.

## Prerequisites

- Python 3.11+
- Docker Desktop (or another Docker Engine) for Neo4j
- (Later deliverables) an Anthropic API key, and read-only API credentials for
  the vendors you're integrating (Tenable to start)

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

## Delivery roadmap (Phase 1)

Built incrementally, each deliverable working end-to-end before the next
begins:

1. **Foundation** *(this deliverable)* — project skeleton, tooling config,
   Docker Compose for Neo4j, environment handling.
2. **Schemas** — `UnifiedControl`, `UnifiedVulnerability`, `UnifiedAsset`,
   `UnifiedFinding`, `SourceSystem`, `IngestionResult`, with full validation
   and round-trip test coverage.
3. **First ingester + loader** — `ingesters/nist_sp800_53.py` (OSCAL JSON →
   `UnifiedControl` → `sp800_53.jsonl`) and `loaders/neo4j_loader.py`
   (JSON-Lines → `(:Control)` nodes and edges).
4. **First vendor normalizer** — `normalizers/tenable.py` (Tenable finding →
   `UnifiedFinding`).
5. **First agent** — `agents/mapping_agent.py`, a LangGraph state machine that
   maps a `UnifiedFinding` to controls, ATT&CK techniques, and confidence
   scores via Neo4j traversal with ChromaDB semantic fallback.

Deferred beyond these five: the synthesis agent, additional vendor
normalizers, the FastAPI layer, and the frontend/UI (Phase 3+).
