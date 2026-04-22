"""Risk scoring and feature extraction for enriched IOCs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ioc_enricher.models.ioc import ProviderResult, RiskBand, RiskScore, ScoringFeatures
from ioc_enricher.utils.config import ScoringConfig
from ioc_enricher.utils.logger import get_logger

_log = get_logger(__name__)


@dataclass
class FeatureWeight:
    """A single scored feature with its weight and computed contribution."""

    name: str
    value: float
    weight: float

    @property
    def contribution(self) -> float:
        """Weighted contribution of this feature to the raw score."""
        return self.value * self.weight


class RiskClassifier:
    """Computes a weighted risk score from a ScoringFeatures vector.

    Uses configurable weights to produce an explainable score with per-feature
    contributions and a confidence estimate based on data richness.
    """

    def __init__(self, config: ScoringConfig) -> None:
        """Initialize with scoring configuration, warning if weights don't sum to 1.0."""
        self._config = config
        w = config.weights
        self.weight_total = (
            w.malicious_engine_ratio
            + w.abuse_confidence_score
            + w.community_pulse_count
            + w.historical_reports
            + w.open_ports_risk
            + w.urlscan_verdict
        )
        if abs(self.weight_total - 1.0) > 0.01:
            _log.warning(
                "scoring_weights_do_not_sum_to_one",
                total=self.weight_total,
            )

    def _build_feature_weights(self, features: ScoringFeatures) -> list[FeatureWeight]:
        """Build a list of FeatureWeight objects from normalized feature values."""
        vector = features.to_feature_vector()
        w = self._config.weights
        return [
            FeatureWeight("malicious_engine_ratio", vector[0], w.malicious_engine_ratio),
            FeatureWeight("abuse_confidence_score", vector[1], w.abuse_confidence_score),
            FeatureWeight("community_pulse_count", vector[2], w.community_pulse_count),
            FeatureWeight("historical_reports", vector[3], w.historical_reports),
            FeatureWeight("open_ports_risk", vector[4], w.open_ports_risk),
            FeatureWeight("urlscan_verdict", vector[5], w.urlscan_verdict),
        ]

    def _compute_raw_score(self, feature_weights: list[FeatureWeight]) -> float:
        """Return weighted sum divided by total weight."""
        total = sum(fw.contribution for fw in feature_weights)
        return total / self.weight_total if self.weight_total > 0 else 0.0

    def _compute_confidence(self, feature_weights: list[FeatureWeight]) -> float:
        """Return confidence as nonzero feature count / 4.0, capped at 1.0.

        Full confidence is reached at 4 or more populated features.
        """
        nonzero = sum(1 for fw in feature_weights if fw.value > 0)
        return min(1.0, nonzero / 4.0)

    def _assign_band(self, score: int) -> RiskBand:
        """Map an integer score to a RiskBand using configured thresholds."""
        bands = self._config.risk_bands
        if score >= bands.CRITICAL:
            return RiskBand.CRITICAL
        if score >= bands.HIGH:
            return RiskBand.HIGH
        if score >= bands.MEDIUM:
            return RiskBand.MEDIUM
        if score >= bands.LOW:
            return RiskBand.LOW
        return RiskBand.INFO

    def score(self, features: ScoringFeatures) -> RiskScore:
        """Compute an explainable RiskScore from a ScoringFeatures object."""
        feature_weights = self._build_feature_weights(features)
        raw = self._compute_raw_score(feature_weights)
        score = max(0, min(100, int(raw * 100)))
        confidence = self._compute_confidence(feature_weights)

        contributions: dict[str, float] = {}
        for fw in feature_weights:
            pct = (fw.contribution / self.weight_total * 100) if self.weight_total > 0 else 0.0
            contributions[fw.name] = round(pct, 4)

        # Floor: VT-confirmed malicious IOCs should never score below LOW band
        # regardless of coverage gaps from other providers
        if features.malicious_engine_ratio > 0 and score < 20:
            score = 20

        # Assign band after floor adjustment so band always reflects final score
        band = self._assign_band(score)

        return RiskScore(
            score=score,
            band=band,
            confidence=confidence,
            feature_contributions=contributions,
        )

    def extract_features(self, provider_results: list[ProviderResult]) -> ScoringFeatures:
        """Aggregate scoring features from a list of provider results.

        Failed provider results are skipped. Historical reports are accumulated
        from both VirusTotal (times_submitted) and AbuseIPDB (total_reports).
        """
        features = ScoringFeatures()

        for result in provider_results:
            if not result.success:
                continue
            data = result.data
            provider = result.provider

            if provider == "virustotal":
                features.malicious_engine_ratio = float(data.get("malicious_ratio", 0.0))
                features.historical_reports += int(data.get("times_submitted", 0))
                reputation = int(data.get("reputation", 0))
                if reputation < 0:
                    # Negative reputation contributes to abuse_confidence_score
                    # -11 reputation → ~0.18 normalized signal
                    features.abuse_confidence_score = max(
                        features.abuse_confidence_score,
                        min(abs(reputation) / 60.0, 1.0) * 100
                    )

            elif provider == "abuseipdb":
                raw_score = float(data.get("abuse_confidence_score", 0.0))
                features.abuse_confidence_score = raw_score
                features.historical_reports += int(data.get("total_reports", 0))

            elif provider == "otx":
                features.community_pulse_count += int(data.get("pulse_count", 0))

            elif provider == "shodan":
                features.open_ports_risk = float(data.get("open_ports_risk", 0.0))

            elif provider == "urlscan":
                features.urlscan_verdict = float(data.get("verdict_score", 0.0))

        return features
