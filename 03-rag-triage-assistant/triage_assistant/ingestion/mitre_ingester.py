"""Downloads and ingests MITRE ATT&CK Enterprise technique data into the mitre_attack collection."""
from __future__ import annotations

import json
from pathlib import Path

import requests

from triage_assistant.retrieval.vector_store import COLLECTION_MITRE, VectorStore
from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)

MITRE_ENTERPRISE_URL: str = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class MitreIngester:
    """Downloads MITRE ATT&CK Enterprise STIX data and ingests technique objects."""

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialise with a shared VectorStore instance.

        Args:
            vector_store: Initialised VectorStore to write MITRE documents into.
        """
        self._store = vector_store

    def download_mitre_data(self, cache_path: str | Path | None = None) -> dict:
        """Download the MITRE ATT&CK Enterprise STIX bundle, optionally using a local cache.

        Args:
            cache_path: If provided and the file exists, load from cache instead of
                        downloading. If provided and the file does not exist, save the
                        downloaded data to this path for future use.

        Returns:
            Parsed STIX bundle as a Python dict.
        """
        if cache_path is not None:
            cache_file = Path(cache_path)
            if cache_file.exists():
                logger.info("mitre_loading_from_cache", path=str(cache_file))
                with open(cache_file, encoding="utf-8") as fh:
                    return json.load(fh)

        logger.info("mitre_downloading", url=MITRE_ENTERPRISE_URL)
        response = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
        response.raise_for_status()
        data: dict = response.json()

        if cache_path is not None:
            cache_file = Path(cache_path)
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            logger.info("mitre_cached", path=str(cache_file))

        return data

    def ingest(self, cache_path: str | Path | None = None) -> int:
        """Download and ingest all non-deprecated MITRE ATT&CK Enterprise techniques.

        Args:
            cache_path: Optional filesystem path for caching the downloaded STIX bundle.

        Returns:
            Count of techniques successfully ingested into the vector store.
        """
        try:
            bundle = self.download_mitre_data(cache_path=cache_path)
        except Exception as exc:
            logger.error("mitre_download_error", error=str(exc))
            return 0

        objects = bundle.get("objects", [])
        techniques = [
            obj
            for obj in objects
            if obj.get("type") == "attack-pattern"
            and not obj.get("revoked", False)
            and not obj.get("x_mitre_deprecated", False)
        ]

        logger.info("mitre_techniques_found", count=len(techniques))

        documents: list[str] = []
        metadatas: list[dict] = []
        ids: list[str] = []

        for technique in techniques:
            try:
                doc_text, meta, doc_id = self._technique_to_document(technique)
                documents.append(doc_text)
                metadatas.append(meta)
                ids.append(doc_id)
            except Exception as exc:
                logger.warning(
                    "mitre_technique_conversion_error",
                    technique_id=technique.get("id", "?"),
                    error=str(exc),
                )

        if not documents:
            return 0

        # Batch in chunks of 100 to avoid memory pressure on large ingestion
        total = 0
        chunk_size = 100
        for i in range(0, len(documents), chunk_size):
            total += self._store.add_documents(
                COLLECTION_MITRE,
                documents[i : i + chunk_size],
                metadatas[i : i + chunk_size],
                ids[i : i + chunk_size],
            )

        logger.info("mitre_ingestion_complete", ingested=total)
        return total

    def _technique_to_document(self, technique: dict) -> tuple[str, dict, str]:
        """Convert a MITRE ATT&CK STIX attack-pattern object to (document_text, metadata, id).

        Extracts: name, description, external_references (for technique ID),
        kill_chain_phases (for tactic), x_mitre_platforms, x_mitre_data_sources,
        and x_mitre_detection (detection guidance).

        Args:
            technique: STIX attack-pattern object dict.

        Returns:
            Tuple of (document_text, metadata_dict, technique_id_string).
        """
        name = str(technique.get("name", ""))
        description = str(technique.get("description", ""))
        detection_guidance = str(technique.get("x_mitre_detection", ""))

        # Extract the ATT&CK technique ID (e.g. T1059.001) from external_references
        technique_id = ""
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = str(ref.get("external_id", ""))
                break

        # Extract primary tactic from kill chain phases
        tactic = ""
        for phase in technique.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = str(phase.get("phase_name", "")).replace("-", " ").title()
                break

        platforms: list[str] = list(technique.get("x_mitre_platforms", []) or [])
        platforms_str = ", ".join(platforms)

        data_sources: list[str] = list(technique.get("x_mitre_data_sources", []) or [])
        data_sources_str = ", ".join(data_sources[:10])

        is_subtechnique: bool = technique.get("x_mitre_is_subtechnique", False)

        document_text = f"MITRE ATT&CK {technique_id}: {name} | Tactic: {tactic}"
        if platforms_str:
            document_text += f" | Platforms: {platforms_str}"
        if description:
            document_text += f" | Description: {description[:500]}"
        if detection_guidance:
            document_text += f" | Detection: {detection_guidance[:300]}"
        if data_sources_str:
            document_text += f" | Data Sources: {data_sources_str}"

        metadata = {
            "technique_id": technique_id,
            "technique_name": name,
            "tactic": tactic,
            "platforms": platforms_str,
            "data_sources": data_sources_str,
            "is_subtechnique": is_subtechnique,
        }

        doc_id = technique_id if technique_id else technique.get("id", name)
        return document_text, metadata, doc_id
