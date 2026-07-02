"""Core triage orchestration engine — retrieves context, calls Claude, returns TriageResult."""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

import anthropic
from jinja2 import Environment, BaseLoader

from triage_assistant.ingestion.ioc_ingester import IOCIngester
from triage_assistant.ingestion.mitre_ingester import MitreIngester
from triage_assistant.ingestion.sigma_ingester import SigmaIngester
from triage_assistant.models.alert import AlertSeverity, RawAlert
from triage_assistant.models.triage import (
    ContextMatch,
    MitreTechnique,
    RecommendedAction,
    TriageResult,
    TriageVerdict,
)
from triage_assistant.prompts.triage import TRIAGE_SYSTEM_PROMPT, TRIAGE_USER_TEMPLATE
from triage_assistant.retrieval.retriever import ContextRetriever
from triage_assistant.retrieval.vector_store import VectorStore
from triage_assistant.utils.config import AppConfig
from triage_assistant.utils.logger import get_logger

logger = get_logger(__name__)

_JINJA_ENV = Environment(loader=BaseLoader(), autoescape=False)  # noqa: S701 — not rendering HTML


class TriageAssistant:
    """Orchestrates the full RAG triage pipeline from alert ingestion to TriageResult."""

    def __init__(self, config: AppConfig) -> None:
        """Initialise all pipeline components from configuration.

        Args:
            config: Fully populated AppConfig instance.
        """
        self._config = config
        self._client = anthropic.Anthropic(api_key=config.llm.api_key)
        self._vector_store = VectorStore(
            persist_directory=config.vector_store.persist_directory,
            embedding_model=config.vector_store.embedding_model,
        )
        self._retriever = ContextRetriever(
            vector_store=self._vector_store,
            n_results_per_collection=config.vector_store.n_results_per_collection,
        )
        self._ioc_ingester = IOCIngester(self._vector_store)
        self._sigma_ingester = SigmaIngester(self._vector_store)
        self._mitre_ingester = MitreIngester(self._vector_store)
        self._triage_template = _JINJA_ENV.from_string(TRIAGE_USER_TEMPLATE)

    # -------------------------------------------------------------------------
    # Primary triage pipeline
    # -------------------------------------------------------------------------

    async def triage(self, alert: RawAlert) -> TriageResult:
        """Execute the full RAG triage pipeline for a single alert.

        Steps:
          1. Retrieve context from all three vector collections.
          2. Build the triage prompt via Jinja2 template.
          3. Call Claude (temperature=0, max_tokens=2048).
          4. Parse JSON response into a fully populated TriageResult.

        Never raises — any exception returns a safe TriageResult with
        ``verdict=needs_investigation`` and the error detail in analyst_notes.

        Args:
            alert: Normalised SIEM alert to triage.

        Returns:
            Structured TriageResult.
        """
        start_ms = time.monotonic() * 1000

        try:
            context_matches, ioc_ctx, sigma_ctx, mitre_ctx, retrieval_summary = (
                self._retriever.retrieve_context(alert)
            )

            user_message = self._triage_template.render(
                alert_context=alert.to_context_string(),
                ioc_context=ioc_ctx,
                sigma_context=sigma_ctx,
                mitre_context=mitre_ctx,
                retrieval_summary=retrieval_summary,
            )

            logger.info(
                "triage_llm_call",
                alert_id=alert.alert_id,
                context_docs=len(context_matches),
                model=self._config.llm.model,
            )

            response = self._client.messages.create(
                model=self._config.llm.model,
                max_tokens=self._config.llm.max_tokens,
                temperature=self._config.llm.temperature,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )

            response_text = response.content[0].text if response.content else ""
            duration_ms = time.monotonic() * 1000 - start_ms

            result = self._parse_triage_response(
                response_text=response_text,
                alert=alert,
                context_matches=context_matches,
                duration_ms=duration_ms,
            )

            logger.info(
                "triage_complete",
                alert_id=alert.alert_id,
                verdict=result.verdict.value,
                confidence=result.confidence,
                duration_ms=round(duration_ms, 1),
            )
            return result

        except anthropic.AuthenticationError as exc:
            logger.error("triage_auth_error", alert_id=alert.alert_id, error=str(exc))
            return self._safe_default(alert, f"Authentication error: {exc}", time.monotonic() * 1000 - start_ms)

        except anthropic.APIError as exc:
            logger.error("triage_api_error", alert_id=alert.alert_id, error=str(exc))
            return self._safe_default(alert, f"API error: {exc}", time.monotonic() * 1000 - start_ms)

        except Exception as exc:
            logger.exception("triage_unexpected_error", alert_id=alert.alert_id, error=str(exc))
            return self._safe_default(alert, f"Unexpected error: {exc}", time.monotonic() * 1000 - start_ms)

    def triage_sync(self, alert: RawAlert) -> TriageResult:
        """Synchronous wrapper around :meth:`triage` for CLI and non-async callers."""
        return asyncio.run(self.triage(alert))

    # -------------------------------------------------------------------------
    # Ingestion delegation
    # -------------------------------------------------------------------------

    def _validate_ingestion_path(self, path: str | Path) -> Path:
        """Resolve and validate ingestion paths to stay within the configured safe root."""
        safe_root = Path(self._config.vector_store.persist_directory).resolve()
        candidate = Path(path)
        resolved = (safe_root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

        try:
            resolved.relative_to(safe_root)
        except ValueError as exc:
            raise ValueError(f"Path '{path}' is outside allowed ingestion root '{safe_root}'") from exc

        return resolved

    async def ingest_iocs(self, path: str | Path) -> int:
        """Ingest IOC files from a file or directory path."""
        p = self._validate_ingestion_path(path)
        if p.is_dir():
            return self._ioc_ingester.ingest_directory(p)
        return self._ioc_ingester.ingest_file(p)

    async def ingest_sigma_rules(self, path: str | Path) -> int:
        """Ingest SIGMA rule YAML files from a file or directory path."""
        p = self._validate_ingestion_path(path)
        if p.is_dir():
            return self._sigma_ingester.ingest_directory(p)
        return self._sigma_ingester.ingest_file(p)

    async def ingest_mitre(self, cache_path: str | Path | None = None) -> int:
        """Download and ingest MITRE ATT&CK Enterprise techniques."""
        return self._mitre_ingester.ingest(cache_path=cache_path)

    # -------------------------------------------------------------------------
    # Knowledge base status
    # -------------------------------------------------------------------------

    def get_knowledge_base_stats(self) -> dict:
        """Return vector store collection counts and configuration metadata."""
        stats = self._vector_store.get_collection_stats()
        return {
            "collections": stats,
            "persist_directory": self._config.vector_store.persist_directory,
            "embedding_model": self._config.vector_store.embedding_model,
        }

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _parse_triage_response(
        self,
        response_text: str,
        alert: RawAlert,
        context_matches: list[ContextMatch],
        duration_ms: float,
    ) -> TriageResult:
        """Parse the LLM JSON response into a fully populated TriageResult.

        Handles JSON wrapped in markdown code fences (```json...```).
        On parse failure, returns a safe default with needs_investigation verdict.

        Args:
            response_text: Raw text from the LLM response.
            alert: Source alert for field back-population.
            context_matches: RAG matches retrieved for this alert.
            duration_ms: Elapsed pipeline time in milliseconds.

        Returns:
            Populated TriageResult.
        """
        # Strip markdown code fences if the LLM wrapped the JSON
        cleaned = response_text.strip()
        fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?", "", cleaned).rstrip("`").strip()

        try:
            data: dict = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.warning(
                "triage_json_parse_failure",
                alert_id=alert.alert_id,
                error=str(exc),
                response_preview=response_text[:200],
            )
            return self._safe_default(
                alert,
                f"LLM response could not be parsed as JSON: {exc}\n\nRaw response:\n{response_text[:500]}",
                duration_ms,
            )

        try:
            verdict = TriageVerdict(data.get("verdict", "needs_investigation"))
        except ValueError:
            verdict = TriageVerdict.needs_investigation

        try:
            action = RecommendedAction(data.get("recommended_action", "investigate"))
        except ValueError:
            action = RecommendedAction.investigate

        try:
            severity = AlertSeverity(data.get("severity_assessment", alert.severity.value))
        except ValueError:
            severity = alert.severity

        mitre_techniques: list[MitreTechnique] = []
        for t in data.get("mitre_techniques", []):
            try:
                mitre_techniques.append(
                    MitreTechnique(
                        technique_id=str(t.get("technique_id", "")),
                        technique_name=str(t.get("technique_name", "")),
                        tactic=str(t.get("tactic", "")),
                        confidence=float(t.get("confidence", 0.5)),
                    )
                )
            except Exception:
                pass

        ioc_matches = [
            m.title for m in context_matches if m.source == "ioc_database" and m.relevance_score > 0.3
        ]
        sigma_rule_matches = [
            m.title for m in context_matches if m.source == "sigma_rules" and m.relevance_score > 0.3
        ]

        return TriageResult(
            alert_id=alert.alert_id,
            verdict=verdict,
            recommended_action=action,
            severity_assessment=severity,
            confidence=float(data.get("confidence", 0.5)),
            confidence_rationale=str(data.get("confidence_rationale", "")),
            summary=str(data.get("summary", "")),
            analyst_notes=str(data.get("analyst_notes", "")),
            mitre_techniques=mitre_techniques,
            context_matches=context_matches,
            ioc_matches=ioc_matches,
            sigma_rule_matches=sigma_rule_matches,
            recommended_searches=list(data.get("recommended_searches", [])),
            false_positive_indicators=list(data.get("false_positive_indicators", [])),
            escalation_path=data.get("escalation_path"),
            triage_duration_ms=round(duration_ms, 2),
            model_used=self._config.llm.model,
            context_documents_used=len(context_matches),
        )

    def _safe_default(
        self, alert: RawAlert, error_detail: str, duration_ms: float
    ) -> TriageResult:
        """Return a safe fallback TriageResult when the pipeline encounters an unrecoverable error."""
        return TriageResult(
            alert_id=alert.alert_id,
            verdict=TriageVerdict.needs_investigation,
            recommended_action=RecommendedAction.investigate,
            severity_assessment=alert.severity,
            confidence=0.0,
            confidence_rationale="Triage pipeline error — manual review required.",
            summary="Automated triage could not be completed. Manual analyst review is required.",
            analyst_notes=f"Pipeline error:\n\n{error_detail}",
            triage_duration_ms=round(duration_ms, 2),
            model_used=self._config.llm.model,
        )
