"""Ingests SIGMA rule YAML files from module 02 output into the sigma_rules collection."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from triage_assistant.retrieval.vector_store import COLLECTION_SIGMA, VectorStore
from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)

_yaml = YAML()
_yaml.preserve_quotes = True


class SigmaIngester:
    """Loads SIGMA rule YAML files and upserts them into the sigma_rules vector collection."""

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialise with a shared VectorStore instance.

        Args:
            vector_store: Initialised VectorStore to write SIGMA documents into.
        """
        self._store = vector_store

    def ingest_file(self, path: str | Path) -> int:
        """Load and ingest a single SIGMA rule YAML file.

        Args:
            path: Path to a .yml or .yaml SIGMA rule file.

        Returns:
            1 on success, 0 on any failure (file not found, parse error, etc.).
        """
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("sigma_file_not_found", path=str(file_path))
            return 0

        try:
            with open(file_path, encoding="utf-8") as fh:
                rule_dict = _yaml.load(fh)

            if not isinstance(rule_dict, dict):
                logger.warning("sigma_file_invalid_structure", path=str(file_path))
                return 0

            doc_text, meta, doc_id = self._rule_to_document(rule_dict)
            return self._store.add_documents(COLLECTION_SIGMA, [doc_text], [meta], [doc_id])

        except Exception as exc:
            logger.error("sigma_ingest_file_error", path=str(file_path), error=str(exc))
            return 0

    def ingest_directory(self, directory: str | Path) -> int:
        """Process all .yml and .yaml files in a directory.

        Args:
            directory: Path to directory containing SIGMA rule files.

        Returns:
            Total count of successfully ingested rules across all files.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning("sigma_directory_not_found", path=str(dir_path))
            return 0

        total = 0
        for file_path in sorted(dir_path.rglob("*.yml")):
            count = self.ingest_file(file_path)
            total += count

        for file_path in sorted(dir_path.rglob("*.yaml")):
            count = self.ingest_file(file_path)
            total += count

        logger.info("sigma_directory_ingested", directory=str(dir_path), total=total)
        return total

    def _rule_to_document(self, rule_dict: dict[str, Any]) -> tuple[str, dict, str]:
        """Convert a parsed SIGMA rule dict to (document_text, metadata, id).

        Builds a rich text representation combining the rule title, description,
        detection logic keywords, logsource, ATT&CK tags, and false positive notes
        to maximise semantic retrieval accuracy at query time.

        Args:
            rule_dict: Parsed SIGMA rule as a Python dict.

        Returns:
            Tuple of (document_text, metadata_dict, stable_id).
        """
        title = str(rule_dict.get("title", ""))
        description = str(rule_dict.get("description", ""))
        status = str(rule_dict.get("status", "experimental"))
        level = str(rule_dict.get("level", "medium"))
        author = str(rule_dict.get("author", ""))
        date_val = rule_dict.get("date", "")

        logsource = rule_dict.get("logsource", {}) or {}
        logsource_category = str(logsource.get("category", ""))
        logsource_product = str(logsource.get("product", ""))
        logsource_service = str(logsource.get("service", ""))

        tags: list[str] = list(rule_dict.get("tags", []) or [])
        tags_str = ", ".join(str(t) for t in tags)

        falsepositives: list[str] = list(rule_dict.get("falsepositives", []) or [])
        fp_str = ", ".join(str(f) for f in falsepositives)

        # Extract detection field values — used as keywords for semantic matching
        detection_keywords: list[str] = []
        detection = rule_dict.get("detection", {}) or {}
        self._extract_detection_keywords(detection, detection_keywords)
        detection_str = " | ".join(detection_keywords[:20])

        document_text = f"SIGMA Rule: {title}"
        if logsource_product or logsource_category:
            document_text += (
                f" | Logsource: {logsource_product} {logsource_category} {logsource_service}".strip()
            )
        if description:
            document_text += f" | Detects: {description[:200]}"
        if detection_str:
            document_text += f" | Keywords: {detection_str}"
        if tags_str:
            document_text += f" | Tags: {tags_str}"
        if fp_str:
            document_text += f" | False positives: {fp_str}"

        metadata = {
            "title": title,
            "status": status,
            "level": level,
            "author": author,
            "date": str(date_val),
            "logsource_category": logsource_category,
            "logsource_product": logsource_product,
            "logsource_service": logsource_service,
            "tags": tags_str,
        }

        rule_id = rule_dict.get("id", "")
        if rule_id:
            doc_id = str(rule_id)
        else:
            doc_id = hashlib.sha256(f"{title}{date_val}".encode()).hexdigest()[:16]

        return document_text, metadata, doc_id

    def _extract_detection_keywords(
        self, obj: Any, out: list[str], depth: int = 0
    ) -> None:
        """Recursively extract string values from detection conditions for keyword indexing."""
        if depth > 5:
            return
        if isinstance(obj, str) and obj not in ("all", "any", "contains", "startswith", "endswith"):
            out.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_detection_keywords(item, out, depth + 1)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                if key not in ("condition",):
                    self._extract_detection_keywords(val, out, depth + 1)
