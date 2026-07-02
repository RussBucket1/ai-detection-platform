"""Tests for VectorStore and ContextRetriever."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from triage_assistant.models.alert import AlertSeverity, AlertSource, RawAlert
from triage_assistant.retrieval.retriever import ContextRetriever
from triage_assistant.retrieval.vector_store import (
    COLLECTION_IOCS,
    COLLECTION_MITRE,
    COLLECTION_SIGMA,
    VectorStore,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_chroma_result(doc_id: str, doc: str, meta: dict, distance: float) -> dict:
    return {
        "ids": [[doc_id]],
        "documents": [[doc]],
        "metadatas": [[meta]],
        "distances": [[distance]],
    }


def _make_mock_vector_store() -> MagicMock:
    store = MagicMock(spec=VectorStore)
    return store


def _sample_alert(**kwargs) -> RawAlert:
    defaults = dict(
        title="Suspicious PowerShell Execution",
        description="PowerShell launched with encoded command",
        source=AlertSource.manual,
        severity=AlertSeverity.high,
        source_ip="10.0.0.5",
        process="powershell.exe",
        command_line="powershell -enc JABQ...",
        event_id="4688",
    )
    defaults.update(kwargs)
    return RawAlert(**defaults)


# ---------------------------------------------------------------------------
# TestVectorStore (unit — mocks chromadb internals)
# ---------------------------------------------------------------------------


class TestVectorStore:
    def _make_store_with_mock_client(self) -> tuple[VectorStore, MagicMock]:
        """Return a VectorStore and its underlying chromadb.PersistentClient mock."""
        mock_client = MagicMock()
        mock_collection = MagicMock()
        mock_collection.count.return_value = 0
        mock_client.get_or_create_collection.return_value = mock_collection

        with patch("chromadb.PersistentClient", return_value=mock_client), \
             patch("chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction"):
            store = VectorStore(persist_directory="./test_chroma")

        return store, mock_client

    def test_add_documents_returns_count(self) -> None:
        store, _ = self._make_store_with_mock_client()
        col = store._collections[COLLECTION_IOCS]
        col.add.return_value = None

        count = store.add_documents(
            COLLECTION_IOCS,
            ["doc1", "doc2", "doc3"],
            [{}, {}, {}],
            ["id1", "id2", "id3"],
        )
        assert count == 3

    def test_query_returns_relevance_scores(self) -> None:
        store, _ = self._make_store_with_mock_client()
        col = store._collections[COLLECTION_SIGMA]
        col.count.return_value = 1
        col.query.return_value = _make_chroma_result(
            "rule-1", "SIGMA Rule: Mimikatz", {"title": "Mimikatz"}, 0.2
        )

        results = store.query(COLLECTION_SIGMA, "mimikatz credential dump")
        assert len(results) == 1
        assert abs(results[0]["relevance_score"] - 0.8) < 0.001

    def test_query_returns_empty_on_error(self) -> None:
        store, _ = self._make_store_with_mock_client()
        col = store._collections[COLLECTION_MITRE]
        col.count.return_value = 5
        col.query.side_effect = RuntimeError("chromadb blew up")

        results = store.query(COLLECTION_MITRE, "lateral movement")
        assert results == []

    def test_get_collection_stats_all_collections(self) -> None:
        store, _ = self._make_store_with_mock_client()
        for col in store._collections.values():
            col.count.return_value = 10

        stats = store.get_collection_stats()
        assert COLLECTION_IOCS in stats
        assert COLLECTION_SIGMA in stats
        assert COLLECTION_MITRE in stats

    def test_duplicate_id_handled_gracefully(self) -> None:
        store, _ = self._make_store_with_mock_client()
        col = store._collections[COLLECTION_IOCS]
        col.add.side_effect = Exception("uniqueness constraint violation — duplicate ID")

        # Should not raise; duplicate is logged and skipped
        count = store.add_documents(COLLECTION_IOCS, ["doc"], [{}], ["dup-id"])
        assert count == 0


# ---------------------------------------------------------------------------
# TestContextRetriever
# ---------------------------------------------------------------------------


def _make_vector_result(doc_id: str, doc: str, meta: dict, relevance: float) -> dict:
    return {
        "id": doc_id,
        "document": doc,
        "metadata": meta,
        "distance": 1.0 - relevance,
        "relevance_score": relevance,
    }


class TestContextRetriever:
    def test_retrieve_context_queries_all_collections(self) -> None:
        store = _make_mock_vector_store()
        store.query.return_value = []

        retriever = ContextRetriever(store, n_results_per_collection=3)
        alert = _sample_alert()
        retriever.retrieve_context(alert)

        assert store.query.call_count == 3
        call_collections = {call.args[0] for call in store.query.call_args_list}
        assert call_collections == {COLLECTION_IOCS, COLLECTION_SIGMA, COLLECTION_MITRE}

    def test_ioc_query_includes_ip_fields(self) -> None:
        store = _make_mock_vector_store()
        retriever = ContextRetriever(store)
        alert = _sample_alert(source_ip="10.0.0.5")
        query = retriever._build_ioc_query(alert)
        assert "10.0.0.5" in query

    def test_sigma_query_includes_process(self) -> None:
        store = _make_mock_vector_store()
        retriever = ContextRetriever(store)
        alert = _sample_alert(process="mimikatz.exe")
        query = retriever._build_sigma_query(alert)
        assert "mimikatz.exe" in query

    def test_mitre_query_includes_description(self) -> None:
        store = _make_mock_vector_store()
        retriever = ContextRetriever(store)
        alert = _sample_alert(description="Credential dumping via lsass memory access")
        query = retriever._build_mitre_query(alert)
        assert "Credential dumping" in query

    def test_retrieval_summary_format(self) -> None:
        store = _make_mock_vector_store()
        retriever = ContextRetriever(store)

        ioc_r = [_make_vector_result("i1", "ioc doc", {"ioc_value": "1.2.3.4"}, 0.9)]
        sigma_r = [_make_vector_result("s1", "sigma doc", {"title": "Mimikatz"}, 0.8)]
        mitre_r = [_make_vector_result("T1003", "mitre doc", {"technique_name": "LSASS"}, 0.7)]

        summary = retriever._build_retrieval_summary(ioc_r, sigma_r, mitre_r)

        assert "1" in summary  # counts
        assert "0.90" in summary or "0.9" in summary

    def test_context_matches_built_correctly(self) -> None:
        store = _make_mock_vector_store()

        ioc_result = _make_vector_result("ioc-1", "Malicious IP", {"ioc_value": "1.2.3.4"}, 0.95)
        sigma_result = _make_vector_result("sig-1", "SIGMA Rule", {"title": "Mimikatz"}, 0.80)
        mitre_result = _make_vector_result("T1059", "PowerShell", {"technique_name": "PowerShell"}, 0.70)

        def _query_side_effect(collection, query_text, n_results):
            if collection == COLLECTION_IOCS:
                return [ioc_result]
            if collection == COLLECTION_SIGMA:
                return [sigma_result]
            return [mitre_result]

        store.query.side_effect = _query_side_effect

        retriever = ContextRetriever(store)
        alert = _sample_alert()
        all_matches, ioc_ctx, sigma_ctx, mitre_ctx, summary = retriever.retrieve_context(alert)

        sources = {m.source for m in all_matches}
        assert "ioc_database" in sources
        assert "sigma_rules" in sources
        assert "mitre_attack" in sources
        assert len(all_matches) == 3
