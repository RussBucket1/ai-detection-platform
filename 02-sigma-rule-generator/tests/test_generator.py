"""Tests for SigmaGenerator — all Anthropic API calls are mocked."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sigma_generator.generator import SigmaGenerator
from sigma_generator.models.sigma import GenerationResult
from sigma_generator.utils.config import AppConfig, GeneratorConfig, LLMConfig, OutputConfig

_MOCK_RULE = {
    "title": "Suspicious PowerShell Download Cradle",
    "name": "suspicious-powershell-download-cradle",
    "description": (
        "Detects PowerShell download cradle patterns used by threat actors "
        "to download and execute payloads from the internet."
    ),
    "status": "experimental",
    "level": "high",
    "logsource": {
        "category": "process_creation",
        "product": "windows",
        "service": None,
    },
    "detection": {
        "keywords": None,
        "field_mappings": {
            "Image|endswith": ["\\powershell.exe"],
            "CommandLine|contains": ["DownloadString", "IEX"],
        },
        "condition": "selection",
        "timeframe": None,
    },
    "tags": ["attack.execution", "attack.t1059.001"],
    "falsepositives": ["Software deployment tools"],
    "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    "mitre_attack": [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "execution",
            "sub_technique": "001",
        }
    ],
    "confidence_score": 0.85,
    "confidence_rationale": "Specific cmdlets tied to download cradle patterns.",
    "source_type": "threat_report",
    "source_summary": "PowerShell download cradle abuse.",
}

_MOCK_LLM_RESPONSE_OBJ = {
    "rules": [_MOCK_RULE],
    "analysis_summary": "Detected PowerShell download cradle (T1059.001).",
}

_MOCK_LLM_RESPONSE_STR = json.dumps(_MOCK_LLM_RESPONSE_OBJ)


def _make_mock_anthropic_response(text: str = _MOCK_LLM_RESPONSE_STR) -> MagicMock:
    content_block = MagicMock()
    content_block.text = text
    response = MagicMock()
    response.content = [content_block]
    return response


@pytest.fixture()
def generator_config() -> AppConfig:
    return AppConfig(
        llm=LLMConfig(api_key="test-key", model="claude-sonnet-4-6"),
        output=OutputConfig(output_dir="./test-output"),
        generator=GeneratorConfig(validate_output=True, min_confidence_threshold=0.0),
    )


@pytest.fixture()
def sigma_generator(generator_config) -> SigmaGenerator:
    with patch("sigma_generator.generator.anthropic.AsyncAnthropic"):
        gen = SigmaGenerator(generator_config)
    return gen


class TestSigmaGenerator:
    @pytest.mark.asyncio
    async def test_generate_returns_generation_result(self, sigma_generator):
        mock_response = _make_mock_anthropic_response()
        sigma_generator._client.messages.create = AsyncMock(return_value=mock_response)

        result = await sigma_generator.generate("Mimikatz credential dumping activity detected.")

        assert isinstance(result, GenerationResult)
        assert result.success

    @pytest.mark.asyncio
    async def test_generate_sets_model_used(self, sigma_generator):
        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        result = await sigma_generator.generate("test input")
        assert result.model_used == "claude-sonnet-4-6"

    @pytest.mark.asyncio
    async def test_generate_tracks_timing(self, sigma_generator):
        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        result = await sigma_generator.generate("test input")
        assert result.generation_time_ms >= 0

    @pytest.mark.asyncio
    async def test_generate_handles_auth_error(self, sigma_generator):
        import httpx
        import anthropic

        fake_request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        fake_response = httpx.Response(401, request=fake_request)
        sigma_generator._client.messages.create = AsyncMock(
            side_effect=anthropic.AuthenticationError(
                message="Invalid API key",
                response=fake_response,
                body={"error": {"message": "Invalid API key"}},
            )
        )
        result = await sigma_generator.generate("test input")
        assert not result.success
        assert result.error is not None
        assert "auth" in result.error.lower() or "authentication" in result.error.lower()

    @pytest.mark.asyncio
    async def test_generate_handles_rate_limit(self, sigma_generator):
        import httpx
        import anthropic

        fake_request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        fake_response = httpx.Response(429, request=fake_request)
        sigma_generator._client.messages.create = AsyncMock(
            side_effect=anthropic.RateLimitError(
                message="Rate limit exceeded",
                response=fake_response,
                body={"error": {"message": "Rate limit exceeded"}},
            )
        )
        result = await sigma_generator.generate("test input")
        assert not result.success
        assert result.error is not None
        assert "rate" in result.error.lower() or "limit" in result.error.lower()

    @pytest.mark.asyncio
    async def test_generate_handles_api_error(self, sigma_generator):
        import httpx
        import anthropic

        fake_request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        fake_response = httpx.Response(500, request=fake_request)
        sigma_generator._client.messages.create = AsyncMock(
            side_effect=anthropic.APIStatusError(
                message="Internal server error",
                response=fake_response,
                body={"error": {"message": "Internal server error"}},
            )
        )
        result = await sigma_generator.generate("test input")
        assert not result.success
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_generate_from_file_reads_content(self, sigma_generator, tmp_path):
        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        test_file = tmp_path / "threat_report.txt"
        test_file.write_text("Cobalt Strike beacon activity observed in enterprise environment.")

        result = await sigma_generator.generate_from_file(test_file)
        assert isinstance(result, GenerationResult)
        sigma_generator._client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_from_file_missing_file(self, sigma_generator):
        result = await sigma_generator.generate_from_file("/nonexistent/path/file.txt")
        assert not result.success
        assert result.error is not None
        assert "not found" in result.error.lower() or "file" in result.error.lower()

    @pytest.mark.asyncio
    async def test_min_confidence_filter(self, sigma_generator, generator_config):
        generator_config.generator.min_confidence_threshold = 0.9
        sigma_generator._config = generator_config

        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        result = await sigma_generator.generate("test input")
        # _MOCK_RULE has confidence 0.85, below 0.9 threshold
        assert result.success
        assert result.rules == []

    @pytest.mark.asyncio
    async def test_author_override(self, sigma_generator):
        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        result = await sigma_generator.generate("test input", author="Test Author")
        assert result.success
        for rule in result.rules:
            assert rule.author == "Test Author"

    @pytest.mark.asyncio
    async def test_generate_never_raises(self, sigma_generator):
        sigma_generator._client.messages.create = AsyncMock(
            side_effect=RuntimeError("Completely unexpected error")
        )
        result = await sigma_generator.generate("test input")
        assert isinstance(result, GenerationResult)
        assert not result.success
        assert result.error is not None

    def test_generate_sync_works(self, sigma_generator):
        sigma_generator._client.messages.create = AsyncMock(
            return_value=_make_mock_anthropic_response()
        )
        result = sigma_generator.generate_sync("test input")
        assert isinstance(result, GenerationResult)
