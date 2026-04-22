"""Tests for enrichment providers using mocked HTTP sessions."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.providers.abuseipdb import AbuseIPDBProvider
from ioc_enricher.providers.otx import OTXProvider
from ioc_enricher.providers.shodan import ShodanProvider, _compute_port_risk
from ioc_enricher.providers.virustotal import VirusTotalProvider
from ioc_enricher.utils.rate_limiter import RateLimiter


@pytest.fixture
def rate_limiter() -> RateLimiter:
    """High-rate limiter to avoid sleeping in tests."""
    return RateLimiter(1000.0)


@pytest.fixture
def vt_provider(rate_limiter: RateLimiter) -> VirusTotalProvider:
    return VirusTotalProvider("test-key", rate_limiter=rate_limiter)


@pytest.fixture
def abuse_provider(rate_limiter: RateLimiter) -> AbuseIPDBProvider:
    return AbuseIPDBProvider("test-key", rate_limiter=rate_limiter)


@pytest.fixture
def shodan_provider(rate_limiter: RateLimiter) -> ShodanProvider:
    return ShodanProvider("test-key", rate_limiter=rate_limiter)


@pytest.fixture
def otx_provider(rate_limiter: RateLimiter) -> OTXProvider:
    return OTXProvider("test-key", rate_limiter=rate_limiter)


@pytest.fixture
def ipv4_ioc() -> IOC:
    return IOC(value="198.51.100.1", ioc_type=IOCType.IPV4)


@pytest.fixture
def domain_ioc() -> IOC:
    return IOC(value="evil.com", ioc_type=IOCType.DOMAIN)


@pytest.fixture
def sha256_ioc() -> IOC:
    return IOC(
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type=IOCType.SHA256,
    )


def _make_mock_response(json_data: dict) -> MagicMock:
    """Build a mock aiohttp response context manager."""
    response = MagicMock()
    response.status = 200
    response.json = AsyncMock(return_value=json_data)
    response.raise_for_status = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=response)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_mock_session(json_data: dict) -> MagicMock:
    """Build a mock aiohttp session that returns the given JSON on GET."""
    session = MagicMock()
    session.get = MagicMock(return_value=_make_mock_response(json_data))
    return session


class TestVirusTotalProvider:
    """Tests for VirusTotalProvider."""

    def test_name(self, vt_provider: VirusTotalProvider) -> None:
        assert vt_provider.name == "virustotal"

    def test_supports_ipv4(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        assert vt_provider.supports(ipv4_ioc)

    def test_supports_domain(self, vt_provider: VirusTotalProvider, domain_ioc: IOC) -> None:
        assert vt_provider.supports(domain_ioc)

    def test_supports_sha256(self, vt_provider: VirusTotalProvider, sha256_ioc: IOC) -> None:
        assert vt_provider.supports(sha256_ioc)

    def test_ip_url_construction(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        url = vt_provider._build_url(ipv4_ioc)
        assert "/ip_addresses/" in url

    def test_domain_url_construction(self, vt_provider: VirusTotalProvider, domain_ioc: IOC) -> None:
        url = vt_provider._build_url(domain_ioc)
        assert "/domains/" in url

    def test_hash_url_construction(self, vt_provider: VirusTotalProvider, sha256_ioc: IOC) -> None:
        url = vt_provider._build_url(sha256_ioc)
        assert "/files/" in url

    def test_normalize_extracts_malicious_ratio(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 20,
                        "suspicious": 0,
                        "harmless": 52,
                        "undetected": 10,
                    }
                }
            }
        }
        result = vt_provider._normalize(ipv4_ioc, body)
        assert result["malicious_count"] == 20
        assert result["total_engines"] == 82
        assert abs(result["malicious_ratio"] - 20 / 82) < 0.001

    def test_normalize_adds_suspicious_tag(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 3,
                        "harmless": 60,
                        "undetected": 5,
                    }
                }
            }
        }
        result = vt_provider._normalize(ipv4_ioc, body)
        assert "vt:suspicious" in result["tags"]
        assert "vt:malicious" not in result["tags"]

    def test_normalize_empty_response(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        result = vt_provider._normalize(ipv4_ioc, {})
        assert result["malicious_count"] == 0
        assert result["total_engines"] == 0
        assert result["malicious_ratio"] == 0.0

    async def test_unsupported_type_returns_failure(self, vt_provider: VirusTotalProvider) -> None:
        unknown_ioc = IOC(value="garbage", ioc_type=IOCType.UNKNOWN)
        session = MagicMock()
        result = await vt_provider.enrich(unknown_ioc, session)
        assert result.success is False
        session.get.assert_not_called()


class TestAbuseIPDBProvider:
    """Tests for AbuseIPDBProvider."""

    def test_name(self, abuse_provider: AbuseIPDBProvider) -> None:
        assert abuse_provider.name == "abuseipdb"

    def test_supports_ipv4(self, abuse_provider: AbuseIPDBProvider, ipv4_ioc: IOC) -> None:
        assert abuse_provider.supports(ipv4_ioc)

    def test_does_not_support_domain(self, abuse_provider: AbuseIPDBProvider, domain_ioc: IOC) -> None:
        assert not abuse_provider.supports(domain_ioc)

    def test_normalize_high_confidence(self, abuse_provider: AbuseIPDBProvider) -> None:
        body = {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 50,
                "numDistinctUsers": 12,
                "isTor": False,
                "isWhitelisted": False,
                "reports": [
                    {"categories": [14, 18]},
                ],
            }
        }
        result = abuse_provider._normalize(body)
        assert result["abuse_confidence_score"] == 95
        assert "abuseipdb:high_confidence" in result["tags"]

    def test_normalize_tor_exit_node(self, abuse_provider: AbuseIPDBProvider) -> None:
        body = {
            "data": {
                "abuseConfidenceScore": 50,
                "totalReports": 5,
                "isTor": True,
                "isWhitelisted": False,
                "reports": [],
            }
        }
        result = abuse_provider._normalize(body)
        assert "tor_exit_node" in result["tags"]

    def test_normalize_category_mapping(self, abuse_provider: AbuseIPDBProvider) -> None:
        body = {
            "data": {
                "abuseConfidenceScore": 60,
                "totalReports": 10,
                "isTor": False,
                "isWhitelisted": False,
                "reports": [
                    {"categories": [4, 11]},
                ],
            }
        }
        result = abuse_provider._normalize(body)
        assert "DDoS Attack" in result["abuse_categories"]
        assert "Email Spam" in result["abuse_categories"]

    async def test_unsupported_type_returns_failure(self, abuse_provider: AbuseIPDBProvider, domain_ioc: IOC) -> None:
        session = MagicMock()
        result = await abuse_provider.enrich(domain_ioc, session)
        assert result.success is False


class TestShodanProvider:
    """Tests for ShodanProvider."""

    def test_name(self, shodan_provider: ShodanProvider) -> None:
        assert shodan_provider.name == "shodan"

    def test_supports_ipv4(self, shodan_provider: ShodanProvider, ipv4_ioc: IOC) -> None:
        assert shodan_provider.supports(ipv4_ioc)

    def test_does_not_support_domain(self, shodan_provider: ShodanProvider, domain_ioc: IOC) -> None:
        assert not shodan_provider.supports(domain_ioc)

    def test_normalize_risky_ports(self, shodan_provider: ShodanProvider) -> None:
        body = {"ports": [22, 3389, 445, 3306, 5432]}
        result = shodan_provider._normalize(body)
        assert result["open_ports_risk"] == pytest.approx(1.0)
        assert "shodan:risky_ports" in result["tags"]

    def test_normalize_no_ports(self, shodan_provider: ShodanProvider) -> None:
        body = {"ports": [80, 443]}
        result = shodan_provider._normalize(body)
        assert result["open_ports_risk"] == pytest.approx(0.0)

    def test_port_risk_score_partial(self) -> None:
        risk = _compute_port_risk([22, 80, 443, 3389])
        assert risk == pytest.approx(2 / 5)

    def test_port_risk_capped_at_one(self) -> None:
        risky = [21, 22, 23, 445, 1433, 1521, 3306]
        risk = _compute_port_risk(risky)
        assert risk == pytest.approx(1.0)


class TestOTXProvider:
    """Tests for OTXProvider."""

    def test_name(self, otx_provider: OTXProvider) -> None:
        assert otx_provider.name == "otx"

    def test_normalize_with_pulses(self, otx_provider: OTXProvider) -> None:
        pulses = [
            {
                "name": "Pulse 1",
                "tags": ["malware", "c2"],
                "malware_families": [{"display_name": "Cobalt Strike"}],
                "adversary": ["APT28"],
                "industries": ["Finance"],
            },
            {
                "name": "Pulse 2",
                "tags": ["phishing"],
                "malware_families": [],
                "adversary": [],
                "industries": [],
            },
        ]
        body = {"reputation": -10, "pulse_info": {"pulses": pulses}}
        result = otx_provider._normalize(body, pulses)
        assert result["pulse_count"] == 2
        assert "otx:has_pulses" in result["tags"]
        assert "Cobalt Strike" in result["malware_families"]
        assert "APT28" in result["adversaries"]
        assert "otx:malware_associated" in result["tags"]
        assert "otx:threat_actor_associated" in result["tags"]

    def test_normalize_no_pulses(self, otx_provider: OTXProvider) -> None:
        body = {"reputation": 0, "pulse_info": {"pulses": []}}
        result = otx_provider._normalize(body, [])
        assert result["pulse_count"] == 0
        assert "otx:has_pulses" not in result["tags"]

    def test_pulse_names_capped_at_10(self, otx_provider: OTXProvider) -> None:
        pulses = [{"name": f"Pulse {i}", "tags": [], "malware_families": [], "adversary": [], "industries": []} for i in range(15)]
        body = {"reputation": 0}
        result = otx_provider._normalize(body, pulses)
        assert len(result["pulse_names"]) == 10


class TestBaseProviderErrorHandling:
    """Tests for cross-cutting error handling in BaseProvider."""

    async def test_unsupported_ioc_type_no_api_call(self, vt_provider: VirusTotalProvider) -> None:
        unknown_ioc = IOC(value="garbage-value-###", ioc_type=IOCType.UNKNOWN)
        session = MagicMock()
        session.get = MagicMock()
        result = await vt_provider.enrich(unknown_ioc, session)
        assert result.success is False
        session.get.assert_not_called()

    async def test_latency_is_recorded(self, vt_provider: VirusTotalProvider, ipv4_ioc: IOC) -> None:
        body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 10,
                    }
                }
            }
        }
        session = _make_mock_session(body)
        result = await vt_provider.enrich(ipv4_ioc, session)
        assert result.success is True
        assert result.latency_ms >= 0
