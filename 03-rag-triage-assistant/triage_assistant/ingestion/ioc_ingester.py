"""Ingests enriched IOC JSON output from module 01 into the IOC ChromaDB collection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from triage_assistant.retrieval.vector_store import COLLECTION_IOCS, VectorStore
from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)


class IOCIngester:
    """Loads module-01 enriched IOC files and upserts them into the IOC vector collection."""

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialise with a shared VectorStore instance.

        Args:
            vector_store: Initialised VectorStore to write IOC documents into.
        """
        self._store = vector_store

    def ingest_file(self, path: str | Path) -> int:
        """Ingest enriched IOC data from a JSON or NDJSON file.

        Handles:
          - A single EnrichedIOC dict (JSON object at root).
          - A list of EnrichedIOC dicts (JSON array at root).
          - NDJSON files where each line is one EnrichedIOC JSON object.

        Args:
            path: Path to the .json or .ndjson file.

        Returns:
            Count of documents successfully ingested. Returns 0 on file errors.
        """
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("ioc_file_not_found", path=str(file_path))
            return 0

        try:
            if file_path.suffix == ".ndjson":
                return self._ingest_ndjson(file_path)
            return self._ingest_json(file_path)
        except Exception as exc:
            logger.error("ioc_ingest_file_error", path=str(file_path), error=str(exc))
            return 0

    def ingest_directory(self, directory: str | Path) -> int:
        """Process all .json and .ndjson files in a directory.

        Args:
            directory: Path to directory containing IOC files.

        Returns:
            Total count of ingested documents across all files.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning("ioc_directory_not_found", path=str(dir_path))
            return 0

        total = 0
        for file_path in sorted(dir_path.iterdir()):
            if file_path.suffix in {".json", ".ndjson"}:
                count = self.ingest_file(file_path)
                total += count
                logger.info("ioc_file_ingested", path=str(file_path), count=count)

        logger.info("ioc_directory_ingested", directory=str(dir_path), total=total)
        return total

    def _ingest_json(self, file_path: Path) -> int:
        """Ingest a standard JSON file (single dict or list of dicts)."""
        with open(file_path, encoding="utf-8") as fh:
            data = json.load(fh)

        records: list[dict] = data if isinstance(data, list) else [data]
        return self._ingest_records(records)

    def _ingest_ndjson(self, file_path: Path) -> int:
        """Ingest a newline-delimited JSON file (one JSON object per line)."""
        records: list[dict] = []
        with open(file_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "ndjson_line_parse_error",
                            path=str(file_path),
                            error=str(exc),
                        )
        return self._ingest_records(records)

    def _ingest_records(self, records: list[dict]) -> int:
        """Convert and add a list of IOC dicts to the vector store."""
        documents: list[str] = []
        metadatas: list[dict] = []
        ids: list[str] = []

        for record in records:
            try:
                doc_text, meta, doc_id = self._ioc_to_document(record)
                documents.append(doc_text)
                metadatas.append(meta)
                ids.append(doc_id)
            except Exception as exc:
                logger.warning("ioc_record_conversion_error", error=str(exc), record=str(record)[:100])

        if not documents:
            return 0

        return self._store.add_documents(COLLECTION_IOCS, documents, metadatas, ids)

    def _ioc_to_document(self, ioc_data: dict) -> tuple[str, dict, str]:
        """Convert an enriched IOC dict to (document_text, metadata, id) for embedding.

        Builds a rich textual representation combining IOC value, risk context,
        tags, MITRE techniques, and provider verdicts to maximise retrieval quality.

        Args:
            ioc_data: EnrichedIOC dict produced by module 01.

        Returns:
            Tuple of (document_text, metadata_dict, stable_id).
        """
        ioc_value = str(ioc_data.get("ioc_value", ioc_data.get("value", "")))
        ioc_type = str(ioc_data.get("ioc_type", ioc_data.get("type", "unknown")))
        risk_score = ioc_data.get("risk_score", 0)
        risk_band = str(ioc_data.get("risk_band", ioc_data.get("risk_level", "UNKNOWN")))

        tags: list[str] = ioc_data.get("tags", [])
        tags_str = ", ".join(str(t) for t in tags) if tags else ""

        mitre_techniques: list[str] = ioc_data.get("mitre_techniques", [])
        mitre_str = ", ".join(str(m) for m in mitre_techniques) if mitre_techniques else ""

        # Flatten provider enrichment data into a readable summary
        provider_parts: list[str] = []
        enrichments = ioc_data.get("enrichments", ioc_data.get("providers", {}))
        if isinstance(enrichments, dict):
            for provider, data in enrichments.items():
                if isinstance(data, dict):
                    confidence = data.get("confidence_score", data.get("confidence", ""))
                    verdict = data.get("verdict", data.get("malicious", ""))
                    if confidence or verdict:
                        provider_parts.append(f"{provider}: {verdict} ({confidence})")
        providers_str = " | ".join(provider_parts) if provider_parts else ""

        document_text = (
            f"Malicious {ioc_type} {ioc_value} | Risk: {risk_band} (score: {risk_score})"
        )
        if tags_str:
            document_text += f" | Tags: {tags_str}"
        if mitre_str:
            document_text += f" | MITRE: {mitre_str}"
        if providers_str:
            document_text += f" | Providers: {providers_str}"

        description = ioc_data.get("description", "")
        if description:
            document_text += f" | {description[:200]}"

        metadata = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "risk_score": int(risk_score) if str(risk_score).isdigit() else 0,
            "risk_band": risk_band,
            "tags": tags_str,
            "mitre_techniques": mitre_str,
            "source": str(ioc_data.get("source", "")),
            "enriched_at": str(ioc_data.get("enriched_at", ioc_data.get("created_at", ""))),
        }

        fingerprint = ioc_data.get("fingerprint", "")
        if fingerprint:
            doc_id = str(fingerprint)
        else:
            doc_id = hashlib.sha256(ioc_value.encode()).hexdigest()[:16]

        return document_text, metadata, doc_id
