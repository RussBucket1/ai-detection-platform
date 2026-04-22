"""Async enrichment pipeline orchestrating providers, scoring, and MITRE mapping."""
from __future__ import annotations

import asyncio
from collections import Counter
from typing import AsyncIterator

import aiohttp

from ioc_enricher.classifier import RiskClassifier
from ioc_enricher.models.ioc import EnrichedIOC, IOC, RiskBand, ScoringFeatures
from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.utils.config import AppConfig
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.mitre import MitreMapper
from ioc_enricher.utils.rate_limiter import ProviderRateLimiters

_log = get_logger(__name__)

_USER_AGENT = "ioc-enricher/1.0.0 (Security Research)"


class EnrichmentPipeline:
    """Orchestrates async IOC enrichment across multiple providers.

    Manages a shared aiohttp session, concurrency control, scoring, and MITRE
    technique mapping. Use as an async context manager to handle session lifecycle.
    """

    def __init__(
        self,
        providers: list[BaseProvider],
        classifier: RiskClassifier,
        mitre_mapper: MitreMapper,
        concurrency: int = 20,
        pipeline_version: str = "1.0.0",
    ) -> None:
        """Initialize the pipeline with providers and operational parameters."""
        self._providers = providers
        self._classifier = classifier
        self._mitre_mapper = mitre_mapper
        self._semaphore = asyncio.Semaphore(concurrency)
        self._pipeline_version = pipeline_version
        self._session: aiohttp.ClientSession | None = None

    @classmethod
    def from_config(cls, config: AppConfig) -> EnrichmentPipeline:
        """Build a fully configured pipeline from an AppConfig instance.

        Only providers with both enabled=True and a non-empty api_key are instantiated.
        Warns if no providers are available.
        """
        from ioc_enricher.providers.abuseipdb import AbuseIPDBProvider
        from ioc_enricher.providers.otx import OTXProvider, URLScanProvider
        from ioc_enricher.providers.shodan import ShodanProvider
        from ioc_enricher.providers.virustotal import VirusTotalProvider

        pc = config.providers
        provider_rates: dict[str, float] = {
            "virustotal": pc.virustotal.rate_limit_rps,
            "abuseipdb": pc.abuseipdb.rate_limit_rps,
            "shodan": pc.shodan.rate_limit_rps,
            "otx": pc.otx.rate_limit_rps,
            "urlscan": pc.urlscan.rate_limit_rps,
        }
        rate_limiters = ProviderRateLimiters(provider_rates)

        providers: list[BaseProvider] = []

        if pc.virustotal.enabled and pc.virustotal.api_key:
            providers.append(VirusTotalProvider(
                api_key=pc.virustotal.api_key,
                base_url=pc.virustotal.base_url,
                rate_limiter=rate_limiters["virustotal"],
                timeout=config.pipeline.provider_timeout,
                max_retries=config.pipeline.max_retries,
            ))

        if pc.abuseipdb.enabled and pc.abuseipdb.api_key:
            providers.append(AbuseIPDBProvider(
                api_key=pc.abuseipdb.api_key,
                base_url=pc.abuseipdb.base_url,
                rate_limiter=rate_limiters["abuseipdb"],
                timeout=config.pipeline.provider_timeout,
                max_retries=config.pipeline.max_retries,
                max_age_days=pc.abuseipdb.max_age_days,
            ))

        if pc.shodan.enabled and pc.shodan.api_key:
            providers.append(ShodanProvider(
                api_key=pc.shodan.api_key,
                base_url=pc.shodan.base_url,
                rate_limiter=rate_limiters["shodan"],
                timeout=config.pipeline.provider_timeout,
                max_retries=config.pipeline.max_retries,
            ))

        if pc.otx.enabled and pc.otx.api_key:
            providers.append(OTXProvider(
                api_key=pc.otx.api_key,
                base_url=pc.otx.base_url,
                rate_limiter=rate_limiters["otx"],
                timeout=config.pipeline.provider_timeout,
                max_retries=config.pipeline.max_retries,
            ))

        if pc.urlscan.enabled and pc.urlscan.api_key:
            providers.append(URLScanProvider(
                api_key=pc.urlscan.api_key,
                base_url=pc.urlscan.base_url,
                rate_limiter=rate_limiters["urlscan"],
                timeout=config.pipeline.provider_timeout,
                max_retries=config.pipeline.max_retries,
            ))

        if not providers:
            _log.warning("no_providers_configured", hint="Set API keys via env vars or config file")

        classifier = RiskClassifier(config.scoring)
        mitre_mapper = MitreMapper()

        return cls(
            providers=providers,
            classifier=classifier,
            mitre_mapper=mitre_mapper,
            concurrency=config.pipeline.concurrency,
            pipeline_version=config.pipeline.version,
        )

    async def __aenter__(self) -> EnrichmentPipeline:
        """Create the shared aiohttp session with optimized TCP connector settings."""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": _USER_AGENT},
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        """Close the aiohttp session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def enrich_one(self, ioc: IOC) -> EnrichedIOC:
        """Enrich a single IOC by dispatching to all applicable providers concurrently."""
        if self._session is None:
            raise RuntimeError(
                "Pipeline must be used as an async context manager before enriching"
            )

        async with self._semaphore:
            applicable = [p for p in self._providers if p.supports(ioc)]
            tasks = [
                asyncio.create_task(p.enrich(ioc, self._session))
                for p in applicable
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        provider_results = list(results)
        providers_queried = [r.provider for r in provider_results if r.success]
        providers_failed = [r.provider for r in provider_results if not r.success]

        scoring_features: ScoringFeatures = self._classifier.extract_features(provider_results)
        risk = self._classifier.score(scoring_features)

        enriched = EnrichedIOC(
            pipeline_version=self._pipeline_version,
            providers_queried=providers_queried,
            providers_failed=providers_failed,
            ioc=ioc,
            provider_results=provider_results,
            scoring_features=scoring_features,
            risk=risk,
            mitre_techniques=[],
        )

        enriched.mitre_techniques = self._mitre_mapper.map(enriched)
        enriched.model_post_init(None)
        return enriched

    async def enrich_batch(
        self,
        iocs: list[IOC],
        *,
        min_risk_score: int = 0,
    ) -> list[EnrichedIOC]:
        """Enrich a batch of IOCs concurrently, filter by min_risk_score, sort by score desc."""
        if not iocs:
            return []

        tasks = [asyncio.create_task(self.enrich_one(ioc)) for ioc in iocs]
        all_results: list[EnrichedIOC] = await asyncio.gather(*tasks)

        if min_risk_score > 0:
            all_results = [
                r for r in all_results
                if r.risk is not None and r.risk.score >= min_risk_score
            ]

        all_results.sort(
            key=lambda r: r.risk.score if r.risk else 0,
            reverse=True,
        )

        band_counts: Counter[str] = Counter(
            r.risk.band.value if r.risk else RiskBand.UNKNOWN.value
            for r in all_results
        )
        _log.info(
            "batch_complete",
            total=len(iocs),
            returned=len(all_results),
            band_summary=dict(band_counts),
        )

        return all_results

    async def enrich_stream(self, iocs: list[IOC]) -> AsyncIterator[EnrichedIOC]:
        """Yield enriched IOCs as each completes (out of input order)."""
        if not iocs:
            return

        tasks = [asyncio.create_task(self.enrich_one(ioc)) for ioc in iocs]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result
