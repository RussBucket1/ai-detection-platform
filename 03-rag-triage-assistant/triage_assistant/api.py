"""FastAPI REST API for receiving SIEM webhook alerts and exposing the triage pipeline."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from triage_assistant.assistant import TriageAssistant
from triage_assistant.models.alert import ElasticAlert, RawAlert, SplunkAlert
from triage_assistant.models.triage import TriageResult
from triage_assistant.utils.config import load_config
from triage_assistant.utils.logger import configure_logging, get_logger

logger = get_logger(__name__)

# Module-level singleton — populated by the lifespan startup handler
_assistant: TriageAssistant | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialise the TriageAssistant on startup and release resources on shutdown."""
    global _assistant
    config = load_config()
    configure_logging(config.triage.log_level)
    _assistant = TriageAssistant(config)
    logger.info(
        "triage_api_started",
        model=config.llm.model,
        chroma_dir=config.vector_store.persist_directory,
    )
    yield
    _assistant = None
    logger.info("triage_api_shutdown")


app = FastAPI(
    title="AI Alert Triage Assistant",
    version="1.0.0",
    description=(
        "RAG-based SIEM alert triage using IOC intelligence, SIGMA rules, and MITRE ATT&CK"
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _log_requests(request: Request, call_next: Any) -> Any:
    """Log method, path, status code, and duration for every request."""
    t0 = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - t0) * 1000, 1)
    logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    return response


def _get_assistant() -> TriageAssistant:
    """Return the global TriageAssistant, raising 503 if it is not yet initialised."""
    if _assistant is None:
        raise HTTPException(status_code=503, detail="Triage assistant not initialised")
    return _assistant


# -------------------------------------------------------------------------
# Triage endpoints
# -------------------------------------------------------------------------


@app.post(
    "/triage",
    response_model=TriageResult,
    tags=["triage"],
    summary="Triage a SIEM alert",
)
async def triage_alert(alert: RawAlert) -> TriageResult:
    """Triage a normalised RawAlert through the full RAG pipeline.

    Accepts a RawAlert JSON body, retrieves context from all three knowledge
    bases, calls Claude, and returns a structured TriageResult.
    """
    assistant = _get_assistant()
    try:
        return await assistant.triage(alert)
    except Exception as exc:
        logger.exception("triage_endpoint_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post(
    "/triage/splunk",
    response_model=TriageResult,
    tags=["triage"],
    summary="Triage a Splunk webhook alert",
)
async def triage_splunk(alert: SplunkAlert) -> TriageResult:
    """Convert a Splunk webhook payload to a RawAlert and triage it.

    Configure Splunk to POST its alert webhook to this endpoint. The payload
    must follow Splunk's standard webhook format with a ``result`` dict and
    a ``search_name`` field.
    """
    assistant = _get_assistant()
    try:
        raw_alert = alert.to_raw_alert()
        return await assistant.triage(raw_alert)
    except Exception as exc:
        logger.exception("splunk_triage_endpoint_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post(
    "/triage/elastic",
    response_model=TriageResult,
    tags=["triage"],
    summary="Triage an Elastic webhook alert",
)
async def triage_elastic(alert: ElasticAlert) -> TriageResult:
    """Convert an Elastic alerting webhook payload to a RawAlert and triage it.

    Configure Elastic to POST its alert action webhook to this endpoint. The
    payload must include a ``rule`` dict with at minimum a ``name`` field.
    """
    assistant = _get_assistant()
    try:
        raw_alert = alert.to_raw_alert()
        return await assistant.triage(raw_alert)
    except Exception as exc:
        logger.exception("elastic_triage_endpoint_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# -------------------------------------------------------------------------
# Ingestion endpoints
# -------------------------------------------------------------------------


@app.post(
    "/ingest/iocs",
    tags=["ingestion"],
    summary="Ingest IOC files into the knowledge base",
)
async def ingest_iocs(body: dict[str, str]) -> dict[str, Any]:
    """Ingest enriched IOC JSON files from module 01 into the IOC vector collection.

    Body: ``{"path": "/path/to/ioc/files"}``
    """
    assistant = _get_assistant()
    raw_path = body.get("path", "")
    if not isinstance(raw_path, str):
        raise HTTPException(status_code=422, detail="'path' field must be a string")
    path = raw_path.strip()
    if not path:
        raise HTTPException(status_code=422, detail="'path' field is required")
    try:
        count = await assistant.ingest_iocs(path)
        return {"ingested": count, "message": f"Successfully ingested {count} IOC document(s)"}
    except Exception as exc:
        logger.exception("ingest_iocs_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post(
    "/ingest/sigma",
    tags=["ingestion"],
    summary="Ingest SIGMA rule YAML files into the knowledge base",
)
async def ingest_sigma(body: dict[str, str]) -> dict[str, Any]:
    """Ingest SIGMA rule YAML files from module 02 into the sigma_rules vector collection.

    Body: ``{"path": "/path/to/sigma/rules"}``
    """
    assistant = _get_assistant()
    raw_path = body.get("path", "")
    if not isinstance(raw_path, str):
        raise HTTPException(status_code=422, detail="'path' field must be a string")
    path = raw_path.strip()
    if not path:
        raise HTTPException(status_code=422, detail="'path' field is required")
    try:
        count = await assistant.ingest_sigma_rules(path)
        return {"ingested": count, "message": f"Successfully ingested {count} SIGMA rule(s)"}
    except Exception as exc:
        logger.exception("ingest_sigma_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post(
    "/ingest/mitre",
    tags=["ingestion"],
    summary="Download and ingest MITRE ATT&CK Enterprise techniques",
)
async def ingest_mitre(body: dict[str, str | None] | None = None) -> dict[str, Any]:
    """Download the MITRE ATT&CK Enterprise STIX bundle and ingest all techniques.

    Body (optional): ``{"cache_path": "/path/to/cache.json"}``
    """
    assistant = _get_assistant()
    cache_path = (body or {}).get("cache_path")
    try:
        count = await assistant.ingest_mitre(cache_path=cache_path)
        return {
            "ingested": count,
            "message": f"Successfully ingested {count} MITRE ATT&CK technique(s)",
        }
    except Exception as exc:
        logger.exception("ingest_mitre_error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# -------------------------------------------------------------------------
# Knowledge base and system endpoints
# -------------------------------------------------------------------------


@app.get(
    "/knowledge-base/stats",
    tags=["knowledge-base"],
    summary="Get knowledge base collection statistics",
)
async def knowledge_base_stats() -> dict[str, Any]:
    """Return document counts for all three vector collections plus configuration metadata."""
    assistant = _get_assistant()
    return assistant.get_knowledge_base_stats()


@app.get(
    "/health",
    tags=["system"],
    summary="API health check",
)
async def health() -> dict[str, Any]:
    """Return API health status, knowledge base collection sizes, model name, and version."""
    from triage_assistant import __version__

    assistant = _get_assistant()
    stats = assistant.get_knowledge_base_stats()
    return {
        "status": "healthy",
        "knowledge_base": stats,
        "model": assistant._config.llm.model,
        "version": __version__,
    }
