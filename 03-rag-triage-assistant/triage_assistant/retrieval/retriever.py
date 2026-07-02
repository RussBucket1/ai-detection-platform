"""High-level retrieval coordinator that assembles RAG context from all three knowledge bases."""
from __future__ import annotations

from triage_assistant.models.alert import RawAlert
from triage_assistant.models.triage import ContextMatch
from triage_assistant.retrieval.vector_store import (
    COLLECTION_IOCS,
    COLLECTION_MITRE,
    COLLECTION_SIGMA,
    VectorStore,
)
from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)


class ContextRetriever:
    """Queries all three ChromaDB collections and formats results for LLM context injection."""

    def __init__(
        self,
        vector_store: VectorStore,
        n_results_per_collection: int = 5,
    ) -> None:
        """Initialise with a shared VectorStore and result count cap.

        Args:
            vector_store: Initialised VectorStore instance.
            n_results_per_collection: Maximum results retrieved from each collection.
        """
        self._store = vector_store
        self._n = n_results_per_collection

    def retrieve_context(
        self,
        alert: RawAlert,
    ) -> tuple[list[ContextMatch], str, str, str, str]:
        """Query all three knowledge bases and assemble LLM-ready context strings.

        Builds collection-optimised query strings from the alert's fields so that
        each retrieval call targets the vocabulary most relevant to that corpus.

        Args:
            alert: Normalised SIEM alert to retrieve context for.

        Returns:
            Tuple of:
              - all_context_matches: Combined ContextMatch list from all three collections.
              - ioc_context_str: Formatted IOC context block for the LLM prompt.
              - sigma_context_str: Formatted SIGMA rule context block.
              - mitre_context_str: Formatted MITRE technique context block.
              - retrieval_summary: One-paragraph summary of retrieval results.
        """
        ioc_query = self._build_ioc_query(alert)
        sigma_query = self._build_sigma_query(alert)
        mitre_query = self._build_mitre_query(alert)

        ioc_results = self._store.query(COLLECTION_IOCS, ioc_query, self._n)
        sigma_results = self._store.query(COLLECTION_SIGMA, sigma_query, self._n)
        mitre_results = self._store.query(COLLECTION_MITRE, mitre_query, self._n)

        logger.debug(
            "retrieval_complete",
            ioc_count=len(ioc_results),
            sigma_count=len(sigma_results),
            mitre_count=len(mitre_results),
        )

        all_matches: list[ContextMatch] = []

        for r in ioc_results:
            meta = r["metadata"]
            all_matches.append(
                ContextMatch(
                    source="ioc_database",
                    document_id=r["id"],
                    title=str(meta.get("ioc_value", r["id"])),
                    relevance_score=round(r["relevance_score"], 4),
                    excerpt=r["document"][:500],
                )
            )

        for r in sigma_results:
            meta = r["metadata"]
            all_matches.append(
                ContextMatch(
                    source="sigma_rules",
                    document_id=r["id"],
                    title=str(meta.get("title", r["id"])),
                    relevance_score=round(r["relevance_score"], 4),
                    excerpt=r["document"][:500],
                )
            )

        for r in mitre_results:
            meta = r["metadata"]
            all_matches.append(
                ContextMatch(
                    source="mitre_attack",
                    document_id=r["id"],
                    title=str(meta.get("technique_name", r["id"])),
                    relevance_score=round(r["relevance_score"], 4),
                    excerpt=r["document"][:500],
                )
            )

        ioc_ctx = self._format_ioc_context(ioc_results)
        sigma_ctx = self._format_sigma_context(sigma_results)
        mitre_ctx = self._format_mitre_context(mitre_results)
        summary = self._build_retrieval_summary(ioc_results, sigma_results, mitre_results)

        return all_matches, ioc_ctx, sigma_ctx, mitre_ctx, summary

    # -------------------------------------------------------------------------
    # Query builders — each targets vocabulary optimised for its corpus
    # -------------------------------------------------------------------------

    def _build_ioc_query(self, alert: RawAlert) -> str:
        """Build query targeting IOC-relevant fields: IPs, hashes, file paths, domains."""
        parts: list[str] = []
        if alert.source_ip:
            parts.append(f"IP address {alert.source_ip}")
        if alert.dest_ip:
            parts.append(f"destination IP {alert.dest_ip}")
        if alert.file_hash:
            parts.append(f"file hash {alert.file_hash}")
        if alert.file_path:
            domain_hint = alert.file_path.split("/")[-1] if "/" in alert.file_path else alert.file_path
            parts.append(f"file {domain_hint}")
        if not parts:
            parts.append(alert.title)
            parts.append(alert.description[:200])
        return " | ".join(parts)

    def _build_sigma_query(self, alert: RawAlert) -> str:
        """Build query targeting detection-relevant fields: processes, command lines, event IDs."""
        parts: list[str] = []
        if alert.process:
            parts.append(f"process {alert.process}")
        if alert.command_line:
            parts.append(f"command line {alert.command_line[:200]}")
        if alert.event_id:
            parts.append(f"event ID {alert.event_id}")
        parts.append(alert.title)
        if alert.description:
            parts.append(alert.description[:200])
        return " ".join(parts)

    def _build_mitre_query(self, alert: RawAlert) -> str:
        """Build query targeting behavioral fields for technique matching."""
        parts: list[str] = [alert.title, alert.description[:300]]
        if alert.command_line:
            parts.append(alert.command_line[:150])
        return " ".join(parts)

    # -------------------------------------------------------------------------
    # Context formatters — produce readable blocks for LLM prompt injection
    # -------------------------------------------------------------------------

    def _format_ioc_context(self, results: list[dict]) -> str:
        """Format IOC retrieval results into a readable context block."""
        if not results:
            return "No IOC matches found in the threat intelligence database."

        lines = [f"Found {len(results)} IOC match(es):"]
        for i, r in enumerate(results, 1):
            meta = r["metadata"]
            lines.append(
                f"\n[IOC {i}] (relevance: {r['relevance_score']:.2f})\n"
                f"  Value: {meta.get('ioc_value', 'N/A')}\n"
                f"  Type: {meta.get('ioc_type', 'N/A')}\n"
                f"  Risk Band: {meta.get('risk_band', 'N/A')} "
                f"(score: {meta.get('risk_score', 'N/A')})\n"
                f"  Tags: {meta.get('tags', 'N/A')}\n"
                f"  MITRE: {meta.get('mitre_techniques', 'N/A')}\n"
                f"  Context: {r['document'][:300]}"
            )
        return "\n".join(lines)

    def _format_sigma_context(self, results: list[dict]) -> str:
        """Format SIGMA rule results including title, logsource, detection logic, and score."""
        if not results:
            return "No matching SIGMA detection rules found."

        lines = [f"Found {len(results)} SIGMA rule match(es):"]
        for i, r in enumerate(results, 1):
            meta = r["metadata"]
            lines.append(
                f"\n[SIGMA Rule {i}] (relevance: {r['relevance_score']:.2f})\n"
                f"  Title: {meta.get('title', 'N/A')}\n"
                f"  Level: {meta.get('level', 'N/A')}\n"
                f"  Logsource: {meta.get('logsource_product', 'N/A')} / "
                f"{meta.get('logsource_category', 'N/A')}\n"
                f"  Tags: {meta.get('tags', 'N/A')}\n"
                f"  Detection excerpt: {r['document'][:350]}"
            )
        return "\n".join(lines)

    def _format_mitre_context(self, results: list[dict]) -> str:
        """Format MITRE technique results including ID, name, tactic, and detection guidance."""
        if not results:
            return "No matching MITRE ATT&CK techniques found."

        lines = [f"Found {len(results)} MITRE ATT&CK technique match(es):"]
        for i, r in enumerate(results, 1):
            meta = r["metadata"]
            lines.append(
                f"\n[MITRE {i}] (relevance: {r['relevance_score']:.2f})\n"
                f"  Technique: {meta.get('technique_id', 'N/A')} — "
                f"{meta.get('technique_name', 'N/A')}\n"
                f"  Tactic: {meta.get('tactic', 'N/A')}\n"
                f"  Platforms: {meta.get('platforms', 'N/A')}\n"
                f"  Description: {r['document'][:350]}"
            )
        return "\n".join(lines)

    def _build_retrieval_summary(
        self,
        ioc_results: list[dict],
        sigma_results: list[dict],
        mitre_results: list[dict],
    ) -> str:
        """Build a one-paragraph summary of what was retrieved from each knowledge base."""
        ioc_top = ioc_results[0]["relevance_score"] if ioc_results else 0.0
        sigma_top = sigma_results[0]["relevance_score"] if sigma_results else 0.0
        mitre_top = mitre_results[0]["relevance_score"] if mitre_results else 0.0

        return (
            f"Retrieved {len(ioc_results)} IOC match(es) from the threat intelligence database "
            f"(highest relevance: {ioc_top:.2f}), "
            f"{len(sigma_results)} SIGMA detection rule(s) "
            f"(highest relevance: {sigma_top:.2f}), and "
            f"{len(mitre_results)} MITRE ATT&CK technique(s) "
            f"(highest relevance: {mitre_top:.2f}). "
            f"Total context documents: {len(ioc_results) + len(sigma_results) + len(mitre_results)}."
        )
