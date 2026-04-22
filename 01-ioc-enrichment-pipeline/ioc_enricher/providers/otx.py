"""OTX (AlienVault) and URLScan enrichment providers."""
from __future__ import annotations

from typing import Any

import aiohttp

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.rate_limiter import RateLimiter

_log = get_logger(__name__)

_OTX_TYPE_MAP: dict[IOCType, str] = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class OTXProvider(BaseProvider):
    """Enriches IOCs against the AlienVault OTX API.

    Returns pulse counts, malware families, threat actors, and community tags.
    """

    name = "otx"
    supported_types = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://otx.alienvault.com/api/v1",
        rate_limiter: RateLimiter | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize the OTX provider."""
        if rate_limiter is None:
            rate_limiter = RateLimiter(10.0)
        super().__init__(api_key, base_url, rate_limiter, timeout, max_retries)

    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Query OTX general indicator endpoint and extract pulse data."""
        otx_type = _OTX_TYPE_MAP.get(ioc.ioc_type, "IPv4")
        url = f"{self._base_url}/indicators/{otx_type}/{ioc.value}/general"
        headers = {"X-OTX-API-KEY": self._api_key}
        async with session.get(url, headers=headers, timeout=self._timeout) as resp:
            resp.raise_for_status()
            body = await resp.json()

        pulses: list[dict[str, Any]] = body.get("pulse_info", {}).get("pulses", [])
        return self._normalize(body, pulses)

    def _normalize(self, body: dict[str, Any], pulses: list[dict[str, Any]]) -> dict[str, Any]:
        """Aggregate pulse data into normalized enrichment fields."""
        all_tags: set[str] = set()
        malware_families: set[str] = set()
        adversaries: set[str] = set()
        industries: set[str] = set()
        pulse_names: list[str] = []

        for pulse in pulses:
            for tag in pulse.get("tags", []):
                if isinstance(tag, str):
                    all_tags.add(tag.lower())
            for mw in pulse.get("malware_families", []):
                name = mw.get("display_name") or mw.get("id", "")
                if name:
                    malware_families.add(name)
            for adv in pulse.get("adversary", []):
                if isinstance(adv, str) and adv:
                    adversaries.add(adv)
            for ind in pulse.get("industries", []):
                if isinstance(ind, str) and ind:
                    industries.add(ind)
            pulse_name = pulse.get("name", "")
            if pulse_name:
                pulse_names.append(pulse_name)

        pulse_count = len(pulses)
        result_tags: list[str] = []
        if pulse_count > 0:
            result_tags.append("otx:has_pulses")
        if malware_families:
            result_tags.append("otx:malware_associated")
        if adversaries:
            result_tags.append("otx:threat_actor_associated")

        return {
            "pulse_count": pulse_count,
            "pulse_names": pulse_names[:10],
            "malware_families": sorted(malware_families),
            "adversaries": sorted(adversaries),
            "industries": sorted(industries),
            "reputation": body.get("reputation", 0),
            "tags": sorted(result_tags),
        }


class URLScanProvider(BaseProvider):
    """Enriches URLs and domains against the URLScan.io API.

    Returns verdict scores, malicious classifications, screenshot URLs, and
    page metadata from the most recent scan.
    """

    name = "urlscan"
    supported_types = {IOCType.URL, IOCType.DOMAIN}

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://urlscan.io/api/v1",
        rate_limiter: RateLimiter | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize the URLScan provider."""
        if rate_limiter is None:
            rate_limiter = RateLimiter(5.0)
        super().__init__(api_key, base_url, rate_limiter, timeout, max_retries)

    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Query URLScan search API for recent scans of the given URL or domain."""
        if ioc.ioc_type == IOCType.DOMAIN:
            query = f"domain:{ioc.value}"
        else:
            query = f"page.url:{ioc.value}"

        url = f"{self._base_url}/search/"
        headers = {"API-Key": self._api_key}
        params = {"q": query, "size": "5"}
        async with session.get(url, headers=headers, params=params, timeout=self._timeout) as resp:
            resp.raise_for_status()
            body = await resp.json()

        results: list[dict[str, Any]] = body.get("results", [])
        return self._normalize(ioc, results)

    def _normalize(self, ioc: IOC, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract verdict and page metadata from the latest URLScan result."""
        if not results:
            return {
                "verdict_malicious": False,
                "verdict_score": 0.0,
                "categories": [],
                "tags": ["urlscan:no_results"],
                "screenshot_url": None,
                "page_domain": None,
                "page_ip": None,
                "tls_valid": None,
                "last_scan": None,
            }

        latest = results[0]
        verdicts: dict[str, Any] = latest.get("verdicts", {}).get("overall", {})
        malicious: bool = bool(verdicts.get("malicious", False))
        score: float = float(verdicts.get("score", 0)) / 100.0
        categories: list[str] = verdicts.get("categories", [])

        page: dict[str, Any] = latest.get("page", {})
        screenshot_url: str | None = latest.get("screenshot")
        task: dict[str, Any] = latest.get("task", {})

        tags: list[str] = []
        if malicious:
            tags.append("urlscan:malicious")
        elif score > 0.5:
            tags.append("urlscan:suspicious")

        return {
            "verdict_malicious": malicious,
            "verdict_score": score,
            "categories": categories,
            "tags": tags,
            "screenshot_url": screenshot_url,
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "tls_valid": page.get("tlsValidDays") is not None,
            "last_scan": task.get("time"),
        }
