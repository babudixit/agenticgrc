"""Unit tests for grc_agent.tools.chroma_tools.

Uses ChromaDB's in-memory `EphemeralClient` (no persistence, no network) with a
deterministic, hash-based fake embedding function so these tests never
download the real ONNX model or depend on network access.
"""

from __future__ import annotations

import hashlib
import math

import chromadb
import pytest
from chromadb.api.models.Collection import Collection

from grc_agent.schemas import UnifiedAttackTechnique
from grc_agent.tools.chroma_tools import (
    ATTACK_TECHNIQUE_COLLECTION,
    get_attack_technique_collection,
    index_attack_techniques,
    semantic_search_attack_techniques,
)

_DIMS = 32


def _hash_embed(text: str) -> list[float]:
    """Deterministic bag-of-words hash embedding — related vocabulary lands in
    the same buckets, so semantically similar fixture text still scores as
    "closer" without needing a real model.
    """
    vector = [0.0] * _DIMS
    for word in text.lower().split():
        bucket = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16) % _DIMS
        vector[bucket] += 1.0
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [v / norm for v in vector]


class _FakeEmbeddingFunction:
    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return [_hash_embed(text) for text in input]

    def embed_query(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)

    def name(self) -> str:
        return "fake-hash-embedding"


@pytest.fixture
def collection() -> Collection:
    # chromadb.EphemeralClient() caches the underlying System per identical
    # Settings within a process, so a fresh client alone doesn't guarantee a
    # fresh collection; reset() forces a clean, isolated store per test.
    client = chromadb.EphemeralClient(settings=chromadb.Settings(allow_reset=True))
    client.reset()
    return get_attack_technique_collection(client, embedding_function=_FakeEmbeddingFunction())


@pytest.fixture
def sample_techniques() -> list[UnifiedAttackTechnique]:
    return [
        UnifiedAttackTechnique(
            technique_id="T1068",
            name="Exploitation for Privilege Escalation",
            description="Adversaries may exploit software vulnerabilities in an attempt to "
            "collect information or gain access to a system by taking advantage of a "
            "memory corruption or buffer overflow flaw.",
            tactics=["privilege-escalation"],
            is_subtechnique=False,
            raw_source={"id": "attack-pattern--t1068"},
        ),
        UnifiedAttackTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            description="Adversaries may abuse PowerShell commands and scripts for execution.",
            tactics=["execution"],
            is_subtechnique=True,
            parent_technique_id="T1059",
            raw_source={"id": "attack-pattern--t1059-001"},
        ),
    ]


def test_get_attack_technique_collection_uses_expected_name(collection: Collection) -> None:
    assert collection.name == ATTACK_TECHNIQUE_COLLECTION


def test_index_attack_techniques_returns_count(
    collection: Collection, sample_techniques: list[UnifiedAttackTechnique]
) -> None:
    indexed = index_attack_techniques(sample_techniques, collection=collection)

    assert indexed == 2
    assert collection.count() == 2


def test_index_is_idempotent_on_rerun(
    collection: Collection, sample_techniques: list[UnifiedAttackTechnique]
) -> None:
    index_attack_techniques(sample_techniques, collection=collection)
    index_attack_techniques(sample_techniques, collection=collection)

    assert collection.count() == 2


def test_semantic_search_returns_closest_technique(
    collection: Collection, sample_techniques: list[UnifiedAttackTechnique]
) -> None:
    index_attack_techniques(sample_techniques, collection=collection)

    results = semantic_search_attack_techniques(
        "buffer overflow memory corruption vulnerability exploit", collection=collection, top_k=2
    )

    assert len(results) == 2
    assert results[0]["technique_id"] == "T1068"
    assert results[0]["name"] == "Exploitation for Privilege Escalation"
    assert results[0]["tactics"] == ["privilege-escalation"]
    assert 0.0 <= results[0]["similarity"] <= 1.0
    # Closest match should score at least as high as the more distant one.
    assert results[0]["similarity"] >= results[1]["similarity"]


def test_semantic_search_respects_top_k(
    collection: Collection, sample_techniques: list[UnifiedAttackTechnique]
) -> None:
    index_attack_techniques(sample_techniques, collection=collection)

    results = semantic_search_attack_techniques("script execution", collection=collection, top_k=1)

    assert len(results) == 1


def test_semantic_search_on_empty_collection_returns_empty_list(collection: Collection) -> None:
    results = semantic_search_attack_techniques("anything", collection=collection)
    assert results == []
