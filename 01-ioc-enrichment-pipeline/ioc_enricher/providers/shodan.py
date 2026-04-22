"""Shodan enrichment provider."""
from __future__ import annotations

from typing import Any

import aiohttp

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.rate_limiter import RateLimiter

_log = get_logger(__name__)

HIGH_RISK_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 445, 1433, 1521, 3306, 3389,
    4444, 5432, 5900, 6379, 7001, 8080, 8443, 9200, 27017,
})


def _compute_port_risk(open_ports: list[int]) -> float:
    """Calculate port risk score by counting high-risk open ports (capped at 1.0)."""
    risky_count = sum(1 for p in open_ports if p in HIGH_RISK_PORTS)
    return min(1.0, risky_count / 5.0)


class ShodanProvider(BaseProvider):
    """Enriches IP addresses against the Shodan host API.

    Returns open port data, CVE vulnerabilities, geolocation, ASN info,
    and a computed port-based risk score.
    """

    name = "shodan"
    supported_types = {IOCType.IPV4, IOCType.IPV6}

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.shodan.io",
        rate_limiter: RateLimiter | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize the Shodan provider."""
        if rate_limiter is None:
            rate_limiter = RateLimiter(1.0)
        super().__init__(api_key, base_url, rate_limiter, timeout, max_retries)

    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Query Shodan host endpoint; returns stub data for unindexed IPs (404)."""
        url = f"{self._base_url}/shodan/host/{ioc.value}"
        params = {"key": self._api_key}
        try:
            async with session.get(url, params=params, timeout=self._timeout) as resp:
                if resp.status == 404:
                    return {
                        "open_ports": [],
                        "tags": ["shodan:not_indexed"],
                        "open_ports_risk": 0.0,
                    }
                resp.raise_for_status()
                body = await resp.json()
        except aiohttp.ClientResponseError as exc:
            if exc.status == 404:
                return {
                    "open_ports": [],
                    "tags": ["shodan:not_indexed"],
                    "open_ports_risk": 0.0,
                }
            raise
        return self._normalize(body)

    def _normalize(self, body: dict[str, Any]) -> dict[str, Any]:
        """Extract and normalize Shodan host response fields."""
        open_ports: list[int] = sorted(body.get("ports", []))
        vulns: list[str] = sorted(body.get("vulns", {}).keys())
        body_tags: list[str] = body.get("tags", [])
        port_risk = _compute_port_risk(open_ports)

        tags: list[str] = []
        if vulns:
            tags.append("shodan:has_vulns")
        if any(p in HIGH_RISK_PORTS for p in open_ports):
            tags.append("shodan:risky_ports")
        if "honeypot" in body_tags:
            tags.append("shodan:honeypot")

        return {
            "open_ports": open_ports,
            "hostnames": body.get("hostnames", []),
            "os": body.get("os"),
            "org": body.get("org"),
            "isp": body.get("isp"),
            "asn": body.get("asn"),
            "country_code": body.get("country_code"),
            "city": body.get("city"),
            "vulns": vulns,
            "open_ports_risk": port_risk,
            "last_update": body.get("last_update"),
            "tags": tags,
        }
