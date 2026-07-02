"""Tests for the FastAPI REST API endpoints."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from triage_assistant.models.alert import AlertSeverity
from triage_assistant.models.triage import (
    RecommendedAction,
    TriageResult,
    TriageVerdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_triage_result(alert_id: str = "test-alert-123") -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        verdict=TriageVerdict.likely_true_positive,
        recommended_action=RecommendedAction.investigate,
        severity_assessment=AlertSeverity.high,
        confidence=0.82,
        confidence_rationale="IOC match confirmed",
        summary="Alert is a likely true positive based on IOC and SIGMA matches.",
        analyst_notes="Source IP matched known C2. Investigate further.",
        triage_duration_ms=350.5,
        model_used="claude-sonnet-4-20250514",
        context_documents_used=8,
    )


@pytest.fixture()
def mock_assistant() -> MagicMock:
    assistant = MagicMock()
    assistant.triage = AsyncMock(return_value=_make_triage_result())
    assistant._config = MagicMock()
    assistant._config.llm.model = "claude-sonnet-4-20250514"
    assistant.get_knowledge_base_stats.return_value = {
        "collections": {
            "ioc_enrichment": 150,
            "sigma_rules": 42,
            "mitre_attack": 600,
        },
        "persist_directory": "./data/chroma",
        "embedding_model": "all-MiniLM-L6-v2",
    }
    assistant.ingest_iocs = AsyncMock(return_value=10)
    assistant.ingest_sigma_rules = AsyncMock(return_value=5)
    assistant.ingest_mitre = AsyncMock(return_value=620)
    return assistant


@pytest.fixture()
def test_client(mock_assistant: MagicMock) -> TestClient:
    """TestClient with the TriageAssistant singleton replaced by mock_assistant."""
    import triage_assistant.api as api_module

    # Inject the mock assistant into the module-level singleton before creating the client
    api_module._assistant = mock_assistant

    with TestClient(api_module.app, raise_server_exceptions=True) as client:
        yield client

    # Clean up
    api_module._assistant = None


# ---------------------------------------------------------------------------
# TestHealthEndpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_200(self, test_client: TestClient) -> None:
        response = test_client.get("/health")
        assert response.status_code == 200

    def test_health_has_status_healthy(self, test_client: TestClient) -> None:
        response = test_client.get("/health")
        assert response.json()["status"] == "healthy"

    def test_health_includes_model(self, test_client: TestClient) -> None:
        response = test_client.get("/health")
        assert "model" in response.json()
        assert "claude" in response.json()["model"].lower()


# ---------------------------------------------------------------------------
# TestTriageEndpoint
# ---------------------------------------------------------------------------


class TestTriageEndpoint:
    _RAW_ALERT = {
        "title": "Suspicious Network Connection",
        "description": "Outbound connection to known C2 IP detected",
        "source_ip": "10.0.0.5",
        "severity": "high",
    }

    def test_triage_raw_alert_returns_200(self, test_client: TestClient) -> None:
        response = test_client.post("/triage", json=self._RAW_ALERT)
        assert response.status_code == 200

    def test_triage_splunk_alert_returns_200(self, test_client: TestClient) -> None:
        payload = {
            "search_name": "Mimikatz Detected",
            "result": {
                "src_ip": "10.0.0.5",
                "host": "WIN-HOST",
                "CommandLine": "sekurlsa::logonpasswords",
            },
        }
        response = test_client.post("/triage/splunk", json=payload)
        assert response.status_code == 200

    def test_triage_elastic_alert_returns_200(self, test_client: TestClient) -> None:
        payload = {
            "rule": {
                "name": "PowerShell Execution Policy Bypass",
                "description": "Detects bypass flag",
                "severity": "high",
            }
        }
        response = test_client.post("/triage/elastic", json=payload)
        assert response.status_code == 200

    def test_triage_invalid_body_returns_422(self, test_client: TestClient) -> None:
        response = test_client.post("/triage", json={"bad_field": "garbage"})
        assert response.status_code == 422

    def test_triage_response_has_verdict(self, test_client: TestClient) -> None:
        response = test_client.post("/triage", json=self._RAW_ALERT)
        assert "verdict" in response.json()

    def test_triage_response_has_confidence(self, test_client: TestClient) -> None:
        response = test_client.post("/triage", json=self._RAW_ALERT)
        data = response.json()
        assert "confidence" in data
        assert isinstance(data["confidence"], float)


# ---------------------------------------------------------------------------
# TestIngestionEndpoints
# ---------------------------------------------------------------------------


class TestIngestionEndpoints:
    def test_ingest_iocs_returns_count(self, test_client: TestClient) -> None:
        response = test_client.post("/ingest/iocs", json={"path": "./data/iocs"})
        assert response.status_code == 200
        data = response.json()
        assert "ingested" in data
        assert data["ingested"] >= 0

    def test_ingest_sigma_returns_count(self, test_client: TestClient) -> None:
        response = test_client.post("/ingest/sigma", json={"path": "./data/sigma_rules"})
        assert response.status_code == 200
        data = response.json()
        assert "ingested" in data
        assert data["ingested"] >= 0

    def test_ingest_mitre_returns_200(self, test_client: TestClient) -> None:
        response = test_client.post("/ingest/mitre", json={})
        assert response.status_code == 200
        data = response.json()
        assert "ingested" in data
        assert data["ingested"] >= 600


# ---------------------------------------------------------------------------
# TestKnowledgeBaseStats
# ---------------------------------------------------------------------------


class TestKnowledgeBaseStats:
    def test_stats_returns_all_collections(self, test_client: TestClient) -> None:
        response = test_client.get("/knowledge-base/stats")
        assert response.status_code == 200
        data = response.json()
        collections = data.get("collections", {})
        assert "ioc_enrichment" in collections
        assert "sigma_rules" in collections
        assert "mitre_attack" in collections
