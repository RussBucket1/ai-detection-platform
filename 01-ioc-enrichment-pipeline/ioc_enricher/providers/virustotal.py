"""VirusTotal enrichment provider."""
from __future__ import annotations

import base64
from typing import Any

import aiohttp

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.rate_limiter import RateLimiter

_log = get_logger(__name__)


class VirusTotalProvider(BaseProvider):
    """Enriches IOCs against the VirusTotal v3 API.

    Supports IPs, domains, URLs, and file hashes. Returns normalized analysis
    stats, malicious ratio, reputation, and contextual metadata.
    """

    name = "virustotal"
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
        base_url: str = "https://www.virustotal.com/api/v3",
        rate_limiter: RateLimiter | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize the VirusTotal provider."""
        if rate_limiter is None:
            rate_limiter = RateLimiter(4.0)
        super().__init__(api_key, base_url, rate_limiter, timeout, max_retries)

    def _build_url(self, ioc: IOC) -> str:
        """Construct the VirusTotal API endpoint URL for a given IOC."""
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"{self._base_url}/ip_addresses/{ioc.value}"
        if ioc.ioc_type == IOCType.DOMAIN:
            return f"{self._base_url}/domains/{ioc.value}"
        if ioc.ioc_type == IOCType.URL:
            encoded = base64.urlsafe_b64encode(ioc.value.encode()).rstrip(b"=").decode()
            return f"{self._base_url}/urls/{encoded}"
        return f"{self._base_url}/files/{ioc.value.lower()}"

    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Query the VirusTotal API and return normalized results."""
        url = self._build_url(ioc)
        headers = {"x-apikey": self._api_key}
        async with session.get(url, headers=headers, timeout=self._timeout) as resp:
            resp.raise_for_status()
            body = await resp.json()
        return self._normalize(ioc, body)

    def _normalize(self, ioc: IOC, body: dict[str, Any]) -> dict[str, Any]:
        """Extract and normalize VirusTotal response fields."""
        attrs: dict[str, Any] = body.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        malicious_ratio = malicious / total if total > 0 else 0.0

        tags: list[str] = []
        if malicious > 0:
            tags.append("vt:malicious")
        if suspicious > 0:
            tags.append("vt:suspicious")

        result: dict[str, Any] = {
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": total,
            "malicious_ratio": malicious_ratio,
            "reputation": attrs.get("reputation", 0),
            "tags": tags,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "times_submitted": attrs.get("times_submitted", 0),
        }

        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            result.update({
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "network": attrs.get("network"),
            })
        elif ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            result.update({
                "categories": attrs.get("categories", {}),
                "registrar": attrs.get("registrar"),
            })
        elif ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            result.update({
                "file_type": attrs.get("type_description"),
                "file_size": attrs.get("size"),
                "meaningful_name": attrs.get("meaningful_name"),
                "sha256": attrs.get("sha256"),
                "md5": attrs.get("md5"),
                "ssdeep": attrs.get("ssdeep"),
            })

        return result
