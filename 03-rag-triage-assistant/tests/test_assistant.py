"""Tests for TriageAssistant orchestration engine."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from triage_assistant.models.alert import AlertSeverity, AlertSource, RawAlert
from triage_assistant.models.triage import ContextMatch, TriageResult, TriageVerdict
from triage_assistant.utils.config import AppConfig, LLMConfig, TriageConfig, VectorStoreConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_triage_response() -> str:
    """Realistic LLM JSON response matching the triage schema."""
    return json.dumps(
        {
            "verdict": "likely_true_positive",
            "recommended_action": "investigate",
            "severity_assessment": "high",
            "confidence": 0.82,
            "confidence_rationale": "Source IP matched known C2 IOC, SIGMA rule for encoded PowerShell also triggered.",
            "summary": "A PowerShell process launched with an encoded command string from a source IP matching a known Cobalt Strike C2 indicator. This is likely a true positive requiring investigation.",
            "analyst_notes": "The source IP 10.0.0.5 appears in the IOC database as a known C2 endpoint. The command line matches the Encoded PowerShell SIGMA rule. Recommend isolating the host and reviewing lateral movement.",
            "mitre_techniques": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactic": "Execution",
                    "confidence": 0.9,
                }
            ],
            "recommended_searches": [
                "index=windows EventCode=4688 source_ip=10.0.0.5 | stats count by host, user",
                "index=windows process=powershell CommandLine=*-enc* earliest=-1h | table host, user, CommandLine",
                "index=network dest_ip=10.0.0.5 | stats sum(bytes) by src_ip",
            ],
            "false_positive_indicators": [
                "PowerShell encoded commands are used by some legitimate admin scripts"
            ],
            "escalation_path": "Tier-3 IR team via ServiceNow P1 ticket",
        }
    )


@pytest.fixture()
def sample_alert() -> RawAlert:
    return RawAlert(
        title="Suspicious PowerShell Execution",
        description="PowerShell launched with encoded command",
        source=AlertSource.manual,
        severity=AlertSeverity.high,
        source_ip="10.0.0.5",
        process="powershell.exe",
        command_line="powershell -enc JABQ...",
    )


@pytest.fixture()
def mock_config() -> AppConfig:
    return AppConfig(
        llm=LLMConfig(api_key="test-key", model="claude-sonnet-4-20250514"),
        vector_store=VectorStoreConfig(persist_directory="./test_chroma"),
        triage=TriageConfig(),
    )


@pytest.fixture()
def mock_assistant(mock_config: AppConfig):
    """TriageAssistant with mocked Anthropic client and VectorStore."""
    with patch("triage_assistant.assistant.anthropic.Anthropic"), \
         patch("triage_assistant.assistant.VectorStore"), \
         patch("triage_assistant.assistant.ContextRetriever"), \
         patch("triage_assistant.assistant.IOCIngester"), \
         patch("triage_assistant.assistant.SigmaIngester"), \
         patch("triage_assistant.assistant.MitreIngester"):
        from triage_assistant.assistant import TriageAssistant
        assistant = TriageAssistant(mock_config)
    return assistant


# ---------------------------------------------------------------------------
# TestTriageAssistant
# ---------------------------------------------------------------------------


class TestTriageAssistant:
    def _set_llm_response(self, assistant, text: str) -> None:
        """Configure the mock Anthropic client to return a given text."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=text)]
        assistant._client.messages.create.return_value = mock_message

    def _set_retriever_response(self, assistant, matches=None) -> None:
        if matches is None:
            matches = []
        assistant._retriever.retrieve_context.return_value = (
            matches,
            "No IOC matches.",
            "No SIGMA matches.",
            "No MITRE matches.",
            "Retrieved 0 results total.",
        )

    async def test_triage_returns_triage_result(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert isinstance(result, TriageResult)

    async def test_triage_sets_alert_id(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert result.alert_id == sample_alert.alert_id

    async def test_triage_tracks_duration(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert result.triage_duration_ms >= 0

    async def test_triage_sets_model_used(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert "claude" in result.model_used.lower()

    async def test_triage_handles_auth_error(
        self, mock_assistant, sample_alert: RawAlert
    ) -> None:
        import anthropic

        mock_assistant._client.messages.create.side_effect = anthropic.AuthenticationError(
            message="Invalid API key",
            response=MagicMock(status_code=401, headers={}),
            body={},
        )
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert isinstance(result, TriageResult)
        assert result.verdict == TriageVerdict.needs_investigation

    async def test_triage_handles_api_error(
        self, mock_assistant, sample_alert: RawAlert
    ) -> None:
        import anthropic

        mock_assistant._client.messages.create.side_effect = anthropic.APIStatusError(
            message="Rate limit exceeded",
            response=MagicMock(status_code=429, headers={}),
            body={},
        )
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert isinstance(result, TriageResult)

    async def test_triage_never_raises(
        self, mock_assistant, sample_alert: RawAlert
    ) -> None:
        mock_assistant._client.messages.create.side_effect = RuntimeError("Totally unexpected")
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert isinstance(result, TriageResult)

    async def test_context_matches_populated(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        matches = [
            ContextMatch(
                source="ioc_database",
                document_id="ioc-1",
                title="10.0.0.5",
                relevance_score=0.95,
                excerpt="Known C2 IP",
            )
        ]
        self._set_retriever_response(mock_assistant, matches)

        result = await mock_assistant.triage(sample_alert)
        assert len(result.context_matches) == 1

    async def test_ioc_matches_extracted(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        matches = [
            ContextMatch(
                source="ioc_database",
                document_id="ioc-1",
                title="10.0.0.5",
                relevance_score=0.95,
                excerpt="Known C2 IP",
            )
        ]
        self._set_retriever_response(mock_assistant, matches)

        result = await mock_assistant.triage(sample_alert)
        assert "10.0.0.5" in result.ioc_matches

    async def test_sigma_matches_extracted(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        self._set_llm_response(mock_assistant, mock_triage_response)
        matches = [
            ContextMatch(
                source="sigma_rules",
                document_id="rule-1",
                title="Encoded PowerShell",
                relevance_score=0.88,
                excerpt="Detects encoded PowerShell",
            )
        ]
        self._set_retriever_response(mock_assistant, matches)

        result = await mock_assistant.triage(sample_alert)
        assert "Encoded PowerShell" in result.sigma_rule_matches

    async def test_parse_markdown_wrapped_json(
        self, mock_assistant, sample_alert: RawAlert, mock_triage_response: str
    ) -> None:
        wrapped = f"```json\n{mock_triage_response}\n```"
        self._set_llm_response(mock_assistant, wrapped)
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert isinstance(result, TriageResult)
        assert result.verdict != TriageVerdict.needs_investigation or result.confidence == 0.0

    async def test_parse_failure_returns_safe_default(
        self, mock_assistant, sample_alert: RawAlert
    ) -> None:
        self._set_llm_response(mock_assistant, "This is not valid JSON at all!!!")
        self._set_retriever_response(mock_assistant)

        result = await mock_assistant.triage(sample_alert)
        assert result.verdict == TriageVerdict.needs_investigation
