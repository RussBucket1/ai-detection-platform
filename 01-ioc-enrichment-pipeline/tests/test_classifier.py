"""Tests for risk scoring, feature extraction, and explainability."""
from __future__ import annotations

import pytest

from ioc_enricher.classifier import RiskClassifier
from ioc_enricher.models.ioc import ProviderResult, RiskBand, ScoringFeatures
from ioc_enricher.utils.config import RiskBandsConfig, ScoringConfig, ScoringWeightsConfig


def _make_classifier(**weight_overrides: float) -> RiskClassifier:
    """Build a RiskClassifier with optional weight overrides."""
    weights = ScoringWeightsConfig(**weight_overrides) if weight_overrides else ScoringWeightsConfig()
    return RiskClassifier(ScoringConfig(weights=weights))


def _max_features() -> ScoringFeatures:
    return ScoringFeatures(
        malicious_engine_ratio=1.0,
        abuse_confidence_score=100.0,
        community_pulse_count=50,
        historical_reports=100,
        open_ports_risk=1.0,
        urlscan_verdict=1.0,
    )


def _zero_features() -> ScoringFeatures:
    return ScoringFeatures()


def _make_provider_result(
    provider: str,
    success: bool,
    data: dict,
) -> ProviderResult:
    return ProviderResult(
        provider=provider,
        success=success,
        latency_ms=50.0,
        data=data,
    )


class TestRiskBands:
    """Tests for band assignment based on feature inputs."""

    def test_critical_band(self) -> None:
        clf = _make_classifier()
        result = clf.score(_max_features())
        assert result.band == RiskBand.CRITICAL
        assert result.score >= 90

    def test_info_band(self) -> None:
        clf = _make_classifier()
        result = clf.score(_zero_features())
        assert result.score == 0
        assert result.band == RiskBand.INFO

    def test_high_band(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(
            malicious_engine_ratio=1.0,
            abuse_confidence_score=100.0,
            open_ports_risk=1.0,
        )
        result = clf.score(features)
        assert result.band in (RiskBand.HIGH, RiskBand.CRITICAL)
        assert result.score >= 70

    def test_medium_band(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(
            malicious_engine_ratio=0.8,
            abuse_confidence_score=75.0,
        )
        result = clf.score(features)
        assert result.score >= 10

    def test_low_band(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(
            malicious_engine_ratio=0.05,
            abuse_confidence_score=15.0,
        )
        result = clf.score(features)
        assert result.band in (RiskBand.LOW, RiskBand.INFO, RiskBand.MEDIUM)


class TestScoreBounds:
    """Tests ensuring score and confidence stay within valid ranges."""

    def test_score_never_exceeds_100(self) -> None:
        clf = _make_classifier()
        result = clf.score(_max_features())
        assert result.score <= 100

    def test_score_never_below_zero(self) -> None:
        clf = _make_classifier()
        result = clf.score(_zero_features())
        assert result.score >= 0

    def test_confidence_between_zero_and_one(self) -> None:
        clf = _make_classifier()
        for features in [_max_features(), _zero_features()]:
            result = clf.score(features)
            assert 0.0 <= result.confidence <= 1.0


class TestConfidence:
    """Tests for confidence estimation based on feature population."""

    def test_low_confidence_with_sparse_data(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(malicious_engine_ratio=0.9)
        result = clf.score(features)
        assert result.confidence < 0.5

    def test_high_confidence_with_rich_data(self) -> None:
        clf = _make_classifier()
        features = _max_features()
        result = clf.score(features)
        assert result.confidence >= 0.75


class TestExplainability:
    """Tests for feature contribution transparency."""

    def test_feature_contributions_present(self) -> None:
        clf = _make_classifier()
        result = clf.score(_max_features())
        expected_keys = {
            "malicious_engine_ratio",
            "abuse_confidence_score",
            "community_pulse_count",
            "historical_reports",
            "open_ports_risk",
            "urlscan_verdict",
        }
        assert expected_keys == set(result.feature_contributions.keys())

    def test_dominant_feature_has_highest_contribution(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(
            malicious_engine_ratio=1.0,
            abuse_confidence_score=5.0,
        )
        result = clf.score(features)
        contribs = result.feature_contributions
        assert contribs["malicious_engine_ratio"] > contribs["abuse_confidence_score"]

    def test_zero_features_have_zero_contribution(self) -> None:
        clf = _make_classifier()
        features = ScoringFeatures(
            malicious_engine_ratio=0.9,
            open_ports_risk=0.0,
        )
        result = clf.score(features)
        assert result.feature_contributions["open_ports_risk"] == 0.0


class TestFeatureExtraction:
    """Tests for extract_features() from provider results."""

    def test_extract_from_virustotal_result(self) -> None:
        clf = _make_classifier()
        results = [_make_provider_result("virustotal", True, {
            "malicious_ratio": 0.75,
            "times_submitted": 12,
        })]
        features = clf.extract_features(results)
        assert features.malicious_engine_ratio == pytest.approx(0.75)
        assert features.historical_reports == 12

    def test_extract_from_abuseipdb_result(self) -> None:
        clf = _make_classifier()
        results = [_make_provider_result("abuseipdb", True, {
            "abuse_confidence_score": 87.0,
            "total_reports": 23,
        })]
        features = clf.extract_features(results)
        assert features.abuse_confidence_score == pytest.approx(87.0)
        assert features.historical_reports == 23

    def test_extract_from_shodan_result(self) -> None:
        clf = _make_classifier()
        results = [_make_provider_result("shodan", True, {
            "open_ports_risk": 0.6,
        })]
        features = clf.extract_features(results)
        assert features.open_ports_risk == pytest.approx(0.6)

    def test_extract_from_otx_result(self) -> None:
        clf = _make_classifier()
        results = [_make_provider_result("otx", True, {
            "pulse_count": 7,
        })]
        features = clf.extract_features(results)
        assert features.community_pulse_count == 7

    def test_extract_ignores_failed_results(self) -> None:
        clf = _make_classifier()
        results = [_make_provider_result("virustotal", False, {
            "malicious_ratio": 0.99,
            "times_submitted": 100,
        })]
        features = clf.extract_features(results)
        assert features.malicious_engine_ratio == 0.0
        assert features.historical_reports == 0

    def test_extract_accumulates_historical_reports(self) -> None:
        clf = _make_classifier()
        results = [
            _make_provider_result("virustotal", True, {"malicious_ratio": 0.5, "times_submitted": 8}),
            _make_provider_result("abuseipdb", True, {"abuse_confidence_score": 50.0, "total_reports": 15}),
        ]
        features = clf.extract_features(results)
        assert features.historical_reports == 23

    def test_extract_empty_results(self) -> None:
        clf = _make_classifier()
        features = clf.extract_features([])
        assert features.malicious_engine_ratio == 0.0
        assert features.abuse_confidence_score == 0.0
        assert features.community_pulse_count == 0
        assert features.historical_reports == 0
        assert features.open_ports_risk == 0.0
        assert features.urlscan_verdict == 0.0


class TestCustomWeights:
    """Tests that custom weight configurations affect scoring as expected."""

    def test_custom_weights_affect_score(self) -> None:
        clf = RiskClassifier(ScoringConfig(
            weights=ScoringWeightsConfig(
                malicious_engine_ratio=0.0,
                abuse_confidence_score=1.0,
                community_pulse_count=0.0,
                historical_reports=0.0,
                open_ports_risk=0.0,
                urlscan_verdict=0.0,
            )
        ))
        features = ScoringFeatures(abuse_confidence_score=50.0)
        result = clf.score(features)
        assert 45 <= result.score <= 55
