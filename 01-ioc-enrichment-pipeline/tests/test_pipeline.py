"""Tests for the enrichment pipeline orchestration, scoring, and ECS output."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ioc_enricher.classifier import RiskClassifier
from ioc_enricher.models.ioc import IOC, IOCType, ProviderResult
from ioc_enricher.pipeline import EnrichmentPipeline
from ioc_enricher.utils.config import ScoringConfig
from ioc_enricher.utils.mitre import MitreMapper


def _make_mock_provider(
    name: str,
    supported_types: set[IOCType],
    result_data: dict,
    success: bool = True,
) -> MagicMock:
    """Create a mock provider returning a fixed ProviderResult."""
    provider = MagicMock()
    provider.name = name
    provider.supports = MagicMock(side_effect=lambda ioc: ioc.ioc_type in supported_types)

    async def _enrich(ioc: IOC, session: object) -> ProviderResult:
        return ProviderResult(
            provider=name,
            success=success,
            latency_ms=10.0,
            data=result_data,
        )

    provider.enrich = AsyncMock(side_effect=_enrich)
    return provider


@pytest.fixture
def mock_vt_provider() -> MagicMock:
    return _make_mock_provider(
        "virustotal",
        {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.SHA256},
        {
            "malicious_ratio": 0.214,
            "tags": ["vt:malicious"],
            "times_submitted": 8,
        },
    )


@pytest.fixture
def mock_abuse_provider() -> MagicMock:
    return _make_mock_provider(
        "abuseipdb",
        {IOCType.IPV4, IOCType.IPV6},
        {
            "abuse_confidence_score": 67.0,
            "total_reports": 34,
            "tags": ["abuseipdb:medium_confidence"],
        },
    )


@pytest.fixture
def pipeline(mock_vt_provider: MagicMock, mock_abuse_provider: MagicMock) -> EnrichmentPipeline:
    classifier = RiskClassifier(ScoringConfig())
    mitre_mapper = MitreMapper()
    pipe = EnrichmentPipeline(
        providers=[mock_vt_provider, mock_abuse_provider],
        classifier=classifier,
        mitre_mapper=mitre_mapper,
        concurrency=5,
        pipeline_version="1.0.0-test",
    )
    pipe._session = MagicMock()
    return pipe


@pytest.fixture
def ipv4_ioc() -> IOC:
    return IOC(value="198.51.100.1", ioc_type=IOCType.IPV4)


class TestEnrichOne:
    """Tests for single-IOC enrichment."""

    async def test_enriched_ioc_has_risk_score(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert result.risk is not None
        assert 0 <= result.risk.score <= 100

    async def test_enriched_ioc_has_provider_results(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert len(result.provider_results) == 2
        providers = {r.provider for r in result.provider_results}
        assert "virustotal" in providers
        assert "abuseipdb" in providers

    async def test_enriched_ioc_providers_queried_populated(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert len(result.providers_queried) == 2

    async def test_enriched_ioc_has_correlation_id(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert result.correlation_id is not None

    async def test_enriched_ioc_pipeline_version_set(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert result.pipeline_version == "1.0.0-test"

    async def test_tags_aggregated_from_providers(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        assert "vt:malicious" in result.all_tags
        assert "abuseipdb:medium_confidence" in result.all_tags

    async def test_failed_provider_recorded(self, ipv4_ioc: IOC) -> None:
        failing_provider = _make_mock_provider(
            "virustotal",
            {IOCType.IPV4},
            {},
            success=False,
        )
        pipeline = EnrichmentPipeline(
            providers=[failing_provider],
            classifier=RiskClassifier(ScoringConfig()),
            mitre_mapper=MitreMapper(),
        )
        pipeline._session = MagicMock()
        result = await pipeline.enrich_one(ipv4_ioc)
        assert "virustotal" in result.providers_failed

    async def test_no_providers_for_ioc_type(self, pipeline: EnrichmentPipeline) -> None:
        email_ioc = IOC(value="attacker@evil.com", ioc_type=IOCType.EMAIL)
        result = await pipeline.enrich_one(email_ioc)
        assert result.providers_queried == []
        assert result.risk is not None
        assert result.risk.score == 0


class TestEnrichBatch:
    """Tests for batch enrichment."""

    async def test_batch_returns_all_results(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        iocs = [IOC(value=f"198.51.100.{i}", ioc_type=IOCType.IPV4) for i in range(1, 6)]
        results = await pipeline.enrich_batch(iocs)
        assert len(results) == 5

    async def test_batch_sorted_by_risk_desc(self, pipeline: EnrichmentPipeline) -> None:
        iocs = [IOC(value=f"198.51.100.{i}", ioc_type=IOCType.IPV4) for i in range(1, 4)]
        results = await pipeline.enrich_batch(iocs)
        scores = [r.risk.score for r in results if r.risk]
        assert scores == sorted(scores, reverse=True)

    async def test_batch_empty_input(self, pipeline: EnrichmentPipeline) -> None:
        results = await pipeline.enrich_batch([])
        assert results == []

    async def test_batch_min_risk_filter(self) -> None:
        zero_provider = _make_mock_provider("virustotal", {IOCType.IPV4}, {"malicious_ratio": 0.0, "times_submitted": 0})
        pipeline = EnrichmentPipeline(
            providers=[zero_provider],
            classifier=RiskClassifier(ScoringConfig()),
            mitre_mapper=MitreMapper(),
        )
        pipeline._session = MagicMock()
        iocs = [IOC(value="198.51.100.1", ioc_type=IOCType.IPV4)]
        results = await pipeline.enrich_batch(iocs, min_risk_score=100)
        assert results == []


class TestECSOutput:
    """Tests for ECS serialization of enriched results."""

    async def test_ecs_output_has_required_fields(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        ecs = result.to_ecs()
        assert "@timestamp" in ecs
        assert "event" in ecs
        assert "threat" in ecs
        assert "labels" in ecs
        assert ecs["threat"]["indicator"]["ip"] == ipv4_ioc.value
        assert ecs["threat"]["indicator"]["type"] == "ipv4"

    async def test_ecs_labels_include_risk_score(self, pipeline: EnrichmentPipeline, ipv4_ioc: IOC) -> None:
        result = await pipeline.enrich_one(ipv4_ioc)
        ecs = result.to_ecs()
        assert isinstance(ecs["labels"]["risk_score"], int)


class TestPipelineLifecycle:
    """Tests for async context manager session lifecycle."""

    async def test_session_closed_after_context_exit(
        self,
        mock_vt_provider: MagicMock,
        mock_abuse_provider: MagicMock,
    ) -> None:
        classifier = RiskClassifier(ScoringConfig())
        mitre_mapper = MitreMapper()
        pipe = EnrichmentPipeline(
            providers=[mock_vt_provider, mock_abuse_provider],
            classifier=classifier,
            mitre_mapper=mitre_mapper,
        )
        async with pipe:
            assert pipe._session is not None
        assert pipe._session is None

    async def test_enrich_without_context_raises(
        self,
        mock_vt_provider: MagicMock,
        ipv4_ioc: IOC,
    ) -> None:
        classifier = RiskClassifier(ScoringConfig())
        pipe = EnrichmentPipeline(
            providers=[mock_vt_provider],
            classifier=classifier,
            mitre_mapper=MitreMapper(),
        )
        with pytest.raises(RuntimeError, match="context manager"):
            await pipe.enrich_one(ipv4_ioc)
