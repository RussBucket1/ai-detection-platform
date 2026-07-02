"""ChromaDB-backed vector store with three named knowledge base collections."""
from __future__ import annotations

import chromadb
from chromadb.utils import embedding_functions

from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)

COLLECTION_IOCS = "ioc_enrichment"
COLLECTION_SIGMA = "sigma_rules"
COLLECTION_MITRE = "mitre_attack"

_ALL_COLLECTIONS = (COLLECTION_IOCS, COLLECTION_SIGMA, COLLECTION_MITRE)


class VectorStore:
    """ChromaDB persistent vector store managing three knowledge base collections.

    Uses the SentenceTransformer ``all-MiniLM-L6-v2`` embedding function by default,
    which runs locally and requires no API key — suitable for portfolio/lab use.

    To swap to OpenAI embeddings for production:
        from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
        ef = OpenAIEmbeddingFunction(api_key=os.environ["OPENAI_API_KEY"],
                                     model_name="text-embedding-3-small")
    Then pass ``ef`` to each get_or_create_collection call instead of the
    SentenceTransformerEmbeddingFunction below.
    """

    def __init__(
        self,
        persist_directory: str,
        embedding_model: str = "all-MiniLM-L6-v2",
    ) -> None:
        """Initialise ChromaDB client and all three named collections.

        Args:
            persist_directory: Filesystem path where ChromaDB persists its data.
            embedding_model: SentenceTransformer model name for local embeddings.
        """
        self._persist_directory = persist_directory
        self._embedding_model = embedding_model

        self._client = chromadb.PersistentClient(path=persist_directory)

        self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=embedding_model
        )

        self._collections: dict[str, chromadb.Collection] = {}
        for name in _ALL_COLLECTIONS:
            self._collections[name] = self._client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
                embedding_function=self._embedding_fn,
            )

        logger.info(
            "vector_store_initialised",
            persist_directory=persist_directory,
            embedding_model=embedding_model,
        )

    def get_collection(self, name: str) -> chromadb.Collection:
        """Return a named collection by its constant name.

        Args:
            name: One of COLLECTION_IOCS, COLLECTION_SIGMA, or COLLECTION_MITRE.

        Returns:
            The ChromaDB Collection object.
        """
        if name not in self._collections:
            raise ValueError(f"Unknown collection '{name}'. Valid: {list(self._collections)}")
        return self._collections[name]

    def add_documents(
        self,
        collection_name: str,
        documents: list[str],
        metadatas: list[dict],
        ids: list[str],
    ) -> int:
        """Add documents to the named collection, skipping duplicate IDs.

        Args:
            collection_name: Target collection constant.
            documents: Raw text documents to embed and store.
            metadatas: Parallel list of metadata dicts for each document.
            ids: Stable unique IDs for each document.

        Returns:
            Count of documents successfully added (duplicates are skipped).
        """
        collection = self.get_collection(collection_name)
        added = 0

        for doc, meta, doc_id in zip(documents, metadatas, ids):
            try:
                collection.add(documents=[doc], metadatas=[meta], ids=[doc_id])
                added += 1
            except Exception as exc:
                exc_str = str(exc).lower()
                if "duplicate" in exc_str or "already exists" in exc_str or "uniqueness" in exc_str:
                    logger.debug(
                        "duplicate_document_skipped",
                        collection=collection_name,
                        doc_id=doc_id,
                    )
                else:
                    logger.warning(
                        "document_add_error",
                        collection=collection_name,
                        doc_id=doc_id,
                        error=str(exc),
                    )

        return added

    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 5,
    ) -> list[dict]:
        """Query the collection for semantically similar documents.

        Args:
            collection_name: Collection to query.
            query_text: Natural language query string.
            n_results: Maximum number of results to return.

        Returns:
            List of dicts with keys: id, document, metadata, distance, relevance_score.
            relevance_score = 1 - cosine_distance (higher is more relevant).
            Returns an empty list on any error.
        """
        try:
            collection = self.get_collection(collection_name)
            count = collection.count()
            if count == 0:
                return []

            actual_n = min(n_results, count)
            results = collection.query(query_texts=[query_text], n_results=actual_n)

            output: list[dict] = []
            ids = results.get("ids", [[]])[0]
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for doc_id, doc, meta, dist in zip(ids, docs, metas, distances):
                output.append(
                    {
                        "id": doc_id,
                        "document": doc,
                        "metadata": meta or {},
                        "distance": dist,
                        "relevance_score": max(0.0, 1.0 - dist),
                    }
                )
            return output

        except Exception as exc:
            logger.error(
                "vector_store_query_error",
                collection=collection_name,
                error=str(exc),
            )
            return []

    def get_collection_stats(self) -> dict[str, int]:
        """Return document counts for all three collections.

        Returns:
            Mapping of collection name → document count.
        """
        return {name: col.count() for name, col in self._collections.items()}

    def clear_collection(self, name: str) -> None:
        """Delete and recreate a collection, removing all its documents.

        Used to force a full re-ingestion of a knowledge base.

        Args:
            name: Collection constant to reset.
        """
        self._client.delete_collection(name)
        self._collections[name] = self._client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
            embedding_function=self._embedding_fn,
        )
        logger.info("collection_cleared", collection=name)
