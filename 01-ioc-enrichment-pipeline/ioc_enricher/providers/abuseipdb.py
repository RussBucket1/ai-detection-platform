"""AbuseIPDB enrichment provider."""
from __future__ import annotations

from typing import Any

import aiohttp

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.rate_limiter import RateLimiter

_log = get_logger(__name__)

_CATEGORY_MAP: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBProvider(BaseProvider):
    """Enriches IP addresses against the AbuseIPDB v2 API.

    Returns confidence scores, report counts, ISP details, Tor exit node
    status, and categorized abuse report data.
    """

    name = "abuseipdb"
    supported_types = {IOCType.IPV4, IOCType.IPV6}

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.abuseipdb.com/api/v2",
        rate_limiter: RateLimiter | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        max_age_days: int = 90,
    ) -> None:
        """Initialize the AbuseIPDB provider with optional max_age_days."""
        if rate_limiter is None:
            rate_limiter = RateLimiter(1.0)
        super().__init__(api_key, base_url, rate_limiter, timeout, max_retries)
        self._max_age_days = max_age_days

    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Query AbuseIPDB check endpoint and return normalized results."""
        url = f"{self._base_url}/check"
        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {
            "ipAddress": ioc.value,
            "maxAgeInDays": str(self._max_age_days),
            "verbose": "",
        }
        async with session.get(url, headers=headers, params=params, timeout=self._timeout) as resp:
            resp.raise_for_status()
            body = await resp.json()
        return self._normalize(body)

    def _normalize(self, body: dict[str, Any]) -> dict[str, Any]:
        """Extract and normalize AbuseIPDB response fields."""
        data: dict[str, Any] = body.get("data", {})
        score: float = float(data.get("abuseConfidenceScore", 0))
        total_reports: int = int(data.get("totalReports", 0))
        is_tor: bool = bool(data.get("isTor", False))

        category_ids: set[int] = set()
        for report in data.get("reports", []):
            for cat_id in report.get("categories", []):
                category_ids.add(int(cat_id))

        abuse_categories = sorted(
            _CATEGORY_MAP.get(c, f"Unknown ({c})") for c in category_ids
        )

        tags: list[str] = []
        if score >= 80:
            tags.append("abuseipdb:high_confidence")
        elif score >= 40:
            tags.append("abuseipdb:medium_confidence")
        if is_tor:
            tags.append("tor_exit_node")

        tag_map = {
            4: "abuseipdb:ddos_attack",
            7: "abuseipdb:phishing",
            9: "abuseipdb:open_proxy",
            14: "abuseipdb:port_scan",
            18: "abuseipdb:brute-force",
            21: "abuseipdb:web_app_attack",
            22: "abuseipdb:ssh",
        }
        for cat_id, tag in tag_map.items():
            if cat_id in category_ids:
                tags.append(tag)

        return {
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": is_tor,
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType"),
            "abuse_categories": abuse_categories,
            "tags": sorted(set(tags)),
        }
