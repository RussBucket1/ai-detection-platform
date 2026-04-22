"""Pydantic v2 data models for the IOC enrichment pipeline."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator


class IOCType(str, Enum):
    """Supported indicator of compromise types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class RiskBand(str, Enum):
    """Risk classification bands."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IOC(BaseModel):
    """A single indicator of compromise with metadata."""

    value: str
    ioc_type: IOCType
    source: str = "manual"
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=_utcnow)
    context: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}

    def model_post_init(self, __context: Any) -> None:
        """Normalize value on creation."""
        object.__setattr__(self, "value", self.value.strip())

    @property
    def fingerprint(self) -> str:
        """SHA256 of '{type}:{value.lower()}' for deduplication."""
        raw = f"{self.ioc_type.value}:{self.value.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()


class ScoringFeatures(BaseModel):
    """Normalized feature vector extracted from provider results."""

    malicious_engine_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    abuse_confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    community_pulse_count: int = Field(default=0, ge=0)
    historical_reports: int = Field(default=0, ge=0)
    open_ports_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    urlscan_verdict: float = Field(default=0.0, ge=0.0, le=1.0)

    def to_feature_vector(self) -> list[float]:
        """Return all features normalized to [0, 1]."""
        pulse_norm = min(self.community_pulse_count / 50.0, 1.0)
        reports_norm = min(self.historical_reports / 100.0, 1.0)
        return [
            self.malicious_engine_ratio,
            self.abuse_confidence_score / 100.0,
            pulse_norm,
            reports_norm,
            self.open_ports_risk,
            self.urlscan_verdict,
        ]


class RiskScore(BaseModel):
    """Computed risk score with explainability."""

    score: int = Field(ge=0, le=100)
    band: RiskBand
    confidence: float = Field(ge=0.0, le=1.0)
    feature_contributions: dict[str, float]


class ProviderResult(BaseModel):
    """Result from a single enrichment provider."""

    provider: str
    success: bool
    queried_at: datetime = Field(default_factory=_utcnow)
    latency_ms: float
    data: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] | None = None
    error: str | None = None


class MitreMapping(BaseModel):
    """A MITRE ATT&CK technique mapping with confidence."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)


class EnrichedIOC(BaseModel):
    """Fully enriched IOC with all provider data, scoring, and MITRE mappings."""

    correlation_id: UUID = Field(default_factory=uuid4)
    pipeline_version: str
    enriched_at: datetime = Field(default_factory=_utcnow)
    providers_queried: list[str] = Field(default_factory=list)
    providers_failed: list[str] = Field(default_factory=list)
    ioc: IOC
    provider_results: list[ProviderResult] = Field(default_factory=list)
    scoring_features: ScoringFeatures | None = None
    risk: RiskScore | None = None
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    all_tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def aggregate_tags(self) -> EnrichedIOC:
        """Aggregate tags from IOC and all provider results."""
        tag_set: set[str] = set(self.ioc.tags)
        for result in self.provider_results:
            if result.success:
                provider_tags = result.data.get("tags", [])
                if isinstance(provider_tags, list):
                    tag_set.update(provider_tags)
        self.all_tags = sorted(tag_set)
        return self

    def to_ecs(self) -> dict[str, Any]:
        """Serialize to Elastic Common Schema format."""
        indicator: dict[str, Any] = {
            "type": self.ioc.ioc_type.value,
        }
        _ioc_type = self.ioc.ioc_type
        if _ioc_type in (IOCType.IPV4, IOCType.IPV6):
            indicator["ip"] = self.ioc.value
        elif _ioc_type == IOCType.DOMAIN:
            indicator["domain"] = self.ioc.value
        elif _ioc_type == IOCType.URL:
            indicator["url"] = {"full": self.ioc.value}
        elif _ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            indicator["file"] = {"hash": {_ioc_type.value: self.ioc.value}}
        elif _ioc_type == IOCType.EMAIL:
            indicator["email"] = {"address": self.ioc.value}
        else:
            indicator["description"] = self.ioc.value

        techniques = [
            {"id": t.technique_id, "name": t.technique_name}
            for t in self.mitre_techniques
        ]
        tactics = list(
            {t.tactic for t in self.mitre_techniques}
        )

        risk_score = self.risk.score if self.risk else 0
        risk_band = self.risk.band.value if self.risk else RiskBand.UNKNOWN.value

        provider_results_serial = [
            {
                "provider": r.provider,
                "success": r.success,
                "latency_ms": r.latency_ms,
                "queried_at": r.queried_at.isoformat(),
                "error": r.error,
            }
            for r in self.provider_results
        ]

        features_dict: dict[str, Any] = {}
        if self.scoring_features:
            features_dict = self.scoring_features.model_dump()

        return {
            "@timestamp": self.enriched_at.isoformat(),
            "event": {
                "kind": "enrichment",
                "category": ["threat"],
                "type": ["indicator"],
            },
            "threat": {
                "indicator": indicator,
                "technique": techniques,
                "tactic": [{"name": t} for t in tactics],
            },
            "labels": {
                "risk_score": risk_score,
                "risk_band": risk_band,
                "pipeline_version": self.pipeline_version,
            },
            "tags": self.all_tags,
            "ioc_enrichment": {
                "correlation_id": str(self.correlation_id),
                "providers_queried": self.providers_queried,
                "providers_failed": self.providers_failed,
                "risk": {
                    "score": risk_score,
                    "band": risk_band,
                    "confidence": self.risk.confidence if self.risk else 0.0,
                },
                "features": features_dict,
                "provider_results": provider_results_serial,
            },
        }
