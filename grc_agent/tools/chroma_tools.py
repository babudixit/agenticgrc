"""ChromaDB vector-store helpers for the mapping agent's CWE -> ATT&CK semantic
fallback (Deliverable 5, spec §7.4/§9 Step 4).

There's no graph edge from a Weakness to an AttackTechnique by design (see
README's "What's deliberately NOT ingested" note): CWE and ATT&CK are
maintained independently and MITRE's own CAPEC bridge was explicitly skipped
for Phase 1. When graph traversal from a finding's CVEs/CWEs dead-ends before
reaching a technique, the mapping agent falls back to embedding the CWE's
name+description and finding the nearest ATT&CK techniques by vector
similarity instead.

Embedding model: ChromaDB's bundled `DefaultEmbeddingFunction` runs
all-MiniLM-L6-v2 (the same model named in `Settings.chroma_embedding_model`)
as a local ONNX model — no GPU, no torch/sentence-transformers dependency, no
external API calls or per-query cost. Good enough for nearest-neighbor
technique lookup without pulling a multi-GB ML stack into what's meant to be
a lightweight, deterministic data-movement tool.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import chromadb
import structlog
from chromadb.api import ClientAPI
from chromadb.api.models.Collection import Collection
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

from grc_agent.config.settings import get_settings
from grc_agent.schemas import UnifiedAttackTechnique

logger = structlog.get_logger(__name__)

ATTACK_TECHNIQUE_COLLECTION = "attack_techniques"
DEFAULT_TOP_K = 5


def get_chroma_client(persist_directory: Path | None = None) -> ClientAPI:
    """Build a persistent (SQLite-backed) ChromaDB client from settings."""
    settings = get_settings()
    directory = persist_directory or settings.chroma_persist_dir
    directory.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(directory))


def get_attack_technique_collection(
    client: ClientAPI,
    *,
    embedding_function: Any | None = None,
) -> Collection:
    """Get or create the ATT&CK technique collection used for the CWE -> technique
    semantic fallback.

    `embedding_function` is overridable so tests can inject a deterministic,
    network-free stand-in instead of downloading the real ONNX model. Typed
    as `Any` rather than chromadb's `EmbeddingFunction[...]` generic — its
    input-type parameter is unions of numpy dtypes not worth fighting mypy over
    for what's a duck-typed callable at runtime.
    """
    return client.get_or_create_collection(
        name=ATTACK_TECHNIQUE_COLLECTION,
        embedding_function=cast(Any, embedding_function or DefaultEmbeddingFunction()),
        metadata={"hnsw:space": "cosine"},
    )


def _technique_document(technique: UnifiedAttackTechnique) -> str:
    return f"{technique.name}: {technique.description}"


def index_attack_techniques(
    techniques: Iterable[UnifiedAttackTechnique],
    *,
    collection: Collection,
    batch_size: int = 100,
) -> int:
    """Upsert ATT&CK techniques into the collection, keyed by `technique_id` so
    re-running this is idempotent. Returns the number of techniques indexed.
    """
    all_techniques = list(techniques)
    indexed = 0
    for start in range(0, len(all_techniques), batch_size):
        batch = all_techniques[start : start + batch_size]
        collection.upsert(
            ids=[t.technique_id for t in batch],
            documents=[_technique_document(t) for t in batch],
            metadatas=[
                {
                    "name": t.name,
                    "tactics": ",".join(t.tactics),
                    "is_subtechnique": t.is_subtechnique,
                    "parent_technique_id": t.parent_technique_id or "",
                }
                for t in batch
            ],
        )
        indexed += len(batch)
    logger.info("attack_techniques_indexed", count=indexed)
    return indexed


def semantic_search_attack_techniques(
    query_text: str,
    *,
    collection: Collection,
    top_k: int = DEFAULT_TOP_K,
) -> list[dict[str, Any]]:
    """Semantic nearest-neighbor search for ATT&CK techniques given free text
    (typically a CWE's name + description).

    Returns results ordered most-similar first. `similarity` normalizes
    ChromaDB's cosine *distance* (range [0, 2], 0 = identical) into a [0, 1]
    confidence-like score suitable for `MappedTechnique.confidence`.
    """
    collection_size = collection.count()
    if collection_size == 0:
        logger.warning("attack_technique_collection_empty")
        return []

    results = collection.query(query_texts=[query_text], n_results=min(top_k, collection_size))
    ids = results["ids"][0]
    distances = (results.get("distances") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]

    matches: list[dict[str, Any]] = []
    for technique_id, distance, metadata in zip(ids, distances, metadatas, strict=True):
        metadata = metadata or {}
        tactics_raw = str(metadata.get("tactics") or "")
        matches.append(
            {
                "technique_id": technique_id,
                "name": metadata.get("name"),
                "tactics": [t for t in tactics_raw.split(",") if t],
                "distance": distance,
                "similarity": max(0.0, min(1.0, 1.0 - distance / 2.0)),
            }
        )
    return matches


def _run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="(Re)index ATT&CK techniques from JSON-Lines into the ChromaDB "
        f"'{ATTACK_TECHNIQUE_COLLECTION}' collection used for the mapping agent's "
        "CWE -> ATT&CK semantic fallback."
    )
    parser.add_argument(
        "--input", type=Path, required=True, help="Path to attack_techniques.jsonl."
    )
    args = parser.parse_args(argv)

    if not args.input.exists():
        logger.error("chroma_index_input_not_found", input_path=str(args.input))
        return 1

    techniques = []
    with args.input.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            techniques.append(UnifiedAttackTechnique.model_validate_json(line))

    client = get_chroma_client()
    collection = get_attack_technique_collection(client)
    indexed = index_attack_techniques(techniques, collection=collection)

    print(
        f"Indexed {indexed} ATT&CK techniques into '{ATTACK_TECHNIQUE_COLLECTION}' "
        f"({collection.count()} total in collection)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())
