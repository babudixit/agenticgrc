"""Centralized application settings, loaded from environment variables and/or
a local .env file (see .env.example for the full template).

Fields are grouped by subsystem (core, Neo4j, ChromaDB, LLM, reference-data
refresh cadences, vendor credentials). Every field maps to an environment
variable of the same name, upper-cased (e.g. `neo4j_uri` <- `NEO4J_URI`).

No secrets are hard-coded here or anywhere else in the codebase; values marked
`SecretStr` are redacted automatically when the settings object is logged or
serialized.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core / runtime -----------------------------------------------
    environment: str = Field(
        default="development",
        description="Deployment environment name (development, staging, production).",
    )
    log_level: str = Field(default="INFO", description="structlog / stdlib logging level.")
    data_dir: Path = Field(
        default=Path("./data"),
        description="Root directory for locally cached reference data and JSON-Lines output.",
    )

    # --- Neo4j (knowledge graph) ----------------------------------------
    neo4j_uri: str = Field(default="bolt://localhost:7687", description="Neo4j Bolt URI.")
    neo4j_user: str = Field(default="neo4j", description="Neo4j username.")
    neo4j_password: SecretStr = Field(
        default=SecretStr("changeme123"),
        description="Neo4j password. Override in .env; never commit a real value.",
    )
    neo4j_database: str = Field(default="neo4j", description="Neo4j database name.")

    # --- ChromaDB (vector store) -----------------------------------------
    chroma_persist_dir: Path = Field(
        default=Path("./data/chroma"),
        description="Local directory for ChromaDB's persistent (SQLite-backed) store.",
    )
    chroma_embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Embedding model used for ChromaDB collections.",
    )

    # --- LLM (Anthropic Claude) -------------------------------------------
    anthropic_api_key: SecretStr | None = Field(
        default=None, description="Anthropic API key. Required once agents are implemented."
    )
    llm_model_mapping: str = Field(
        default="claude-sonnet-4-5",
        description="Claude model used by the compliance-mapping agent.",
    )
    llm_model_synthesis: str = Field(
        default="claude-sonnet-4-5",
        description="Claude model used by the finding-synthesis agent (may upgrade to Opus).",
    )

    # --- Reference-data source credentials ---------------------------------
    nvd_api_key: SecretStr | None = Field(
        default=None,
        description="Optional NVD API key; raises the NVD REST API rate limit.",
    )

    # --- Vendor normalizer credentials (read-only API tokens only, per NFR-07) --
    tenable_access_key: SecretStr | None = Field(
        default=None, description="Tenable.io read-only API access key."
    )
    tenable_secret_key: SecretStr | None = Field(
        default=None, description="Tenable.io read-only API secret key."
    )

    # --- Scheduled refresh cadences (cron expressions) ----------------------
    refresh_cron_frameworks: str = Field(
        default="0 0 1 */3 *",
        description="Cron expression for quarterly framework refreshes (SP 800-53, CSF, CIS).",
    )
    refresh_cron_daily: str = Field(
        default="0 6 * * *",
        description="Cron expression for daily refreshes (NVD, CISA KEV, EPSS).",
    )

    def masked_dict(self) -> dict[str, object]:
        """Return settings as a dict with `SecretStr` fields redacted, safe to log."""
        return self.model_dump(mode="json")


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance."""
    return Settings()


if __name__ == "__main__":
    import json

    print(json.dumps(get_settings().masked_dict(), indent=2, default=str))
