"""Pydantic v2 models for SIGMA rule representation and generation results."""
from __future__ import annotations

import datetime as _dt
from datetime import date, datetime, timezone
from enum import Enum
from io import StringIO
from typing import Any
from uuid import UUID, uuid4

# Captured before class bodies can shadow these names
_today = _dt.date.today
_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731

from pydantic import BaseModel, ConfigDict, Field, field_validator
from ruamel.yaml import YAML


class SigmaStatus(str, Enum):
    """SIGMA rule lifecycle status."""

    experimental = "experimental"
    test = "test"
    stable = "stable"
    deprecated = "deprecated"


class SigmaLevel(str, Enum):
    """SIGMA rule severity level."""

    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IOCType(str, Enum):
    """Indicator of compromise type classification."""

    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    email = "email"
    unknown = "unknown"


class MitreAttack(BaseModel):
    """MITRE ATT&CK technique mapping."""

    model_config = ConfigDict(frozen=False)

    technique_id: str = Field(description="ATT&CK technique ID, e.g. 'T1059.001'")
    technique_name: str = Field(description="Human-readable technique name")
    tactic: str = Field(description="ATT&CK tactic slug, e.g. 'execution'")
    sub_technique: str | None = Field(default=None, description="Sub-technique identifier")


class SigmaDetection(BaseModel):
    """SIGMA detection block representation."""

    model_config = ConfigDict(frozen=False)

    keywords: list[str] = Field(
        default_factory=list,
        description="Free-text keywords for the detection block",
    )
    field_mappings: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Field name to value list mappings, e.g. {'CommandLine|contains': ['mimikatz']}",
    )
    condition: str = Field(description="SIGMA condition expression, e.g. 'keywords or selection'")
    timeframe: str | None = Field(default=None, description="Optional timeframe, e.g. '5m', '1h'")


class SigmaLogsource(BaseModel):
    """SIGMA logsource specification."""

    model_config = ConfigDict(frozen=False)

    category: str | None = Field(default=None, description="Log category, e.g. 'process_creation'")
    product: str | None = Field(default=None, description="Product, e.g. 'windows'")
    service: str | None = Field(default=None, description="Service, e.g. 'sysmon'")


class SigmaRule(BaseModel):
    """Complete SIGMA rule with metadata, detection logic, and AI-generated annotations."""

    model_config = ConfigDict(frozen=False)

    rule_id: UUID = Field(default_factory=uuid4, description="Unique rule identifier")
    title: str = Field(max_length=100, description="Human-readable rule title")
    name: str = Field(description="Machine-readable slug (lowercase, hyphens)")
    status: SigmaStatus = Field(default=SigmaStatus.experimental)
    description: str = Field(description="Detailed rule description")
    author: str = Field(default="AI Detection Platform")
    date: _dt.date = Field(default_factory=_today)
    modified: _dt.date = Field(default_factory=_today)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list, description="SIGMA tags, e.g. 'attack.execution'")
    logsource: SigmaLogsource = Field(default_factory=SigmaLogsource)
    detection: SigmaDetection = Field(
        default_factory=lambda: SigmaDetection(condition="selection")
    )
    falsepositives: list[str] = Field(default_factory=list)
    level: SigmaLevel = Field(default=SigmaLevel.medium)
    mitre_attack: list[MitreAttack] = Field(default_factory=list)
    confidence_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="LLM confidence in rule quality (0.0–1.0)",
    )
    confidence_rationale: str = Field(default="", description="Explanation of confidence score")
    generated_at: datetime = Field(
        default_factory=_utcnow,
        description="UTC timestamp of generation",
    )
    source_type: str = Field(default="", description="Input type that produced this rule")
    source_summary: str = Field(default="", description="Brief summary of the source content")

    @field_validator("name")
    @classmethod
    def name_must_be_slug(cls, v: str) -> str:
        """Normalize name to lowercase slug with hyphens."""
        import re

        slug = re.sub(r"[^a-z0-9-]", "-", v.lower())
        slug = re.sub(r"-+", "-", slug).strip("-")
        return slug or "unnamed-rule"

    def to_sigma_yaml(self) -> str:
        """Serialize to standard SIGMA rule YAML format.

        Follows the SIGMA specification exactly. Metadata fields (confidence_score,
        generated_at, mitre_attack objects, source_type) are excluded — MITRE
        techniques appear as tags only.
        """
        yaml = YAML()
        yaml.default_flow_style = False
        yaml.allow_unicode = True
        yaml.width = 4096

        data: dict[str, Any] = {
            "title": self.title,
            "id": str(self.rule_id),
            "status": self.status.value,
            "description": self.description,
            "author": self.author,
            "date": self.date.strftime("%Y/%m/%d"),
            "modified": self.modified.strftime("%Y/%m/%d"),
        }

        if self.references:
            data["references"] = list(self.references)

        if self.tags:
            data["tags"] = list(self.tags)

        logsource: dict[str, str] = {}
        if self.logsource.category:
            logsource["category"] = self.logsource.category
        if self.logsource.product:
            logsource["product"] = self.logsource.product
        if self.logsource.service:
            logsource["service"] = self.logsource.service
        data["logsource"] = logsource

        detection: dict[str, Any] = {}
        if self.detection.field_mappings:
            detection["selection"] = dict(self.detection.field_mappings)
        if self.detection.keywords:
            detection["keywords"] = list(self.detection.keywords)
        detection["condition"] = self.detection.condition
        if self.detection.timeframe:
            detection["timeframe"] = self.detection.timeframe
        data["detection"] = detection

        if self.falsepositives:
            data["falsepositives"] = list(self.falsepositives)
        else:
            data["falsepositives"] = ["Unknown"]

        data["level"] = self.level.value

        stream = StringIO()
        yaml.dump(data, stream)
        return stream.getvalue()

    def to_dict(self) -> dict[str, Any]:
        """Full serialization including all metadata fields."""
        return {
            "rule_id": str(self.rule_id),
            "title": self.title,
            "name": self.name,
            "status": self.status.value,
            "description": self.description,
            "author": self.author,
            "date": self.date.isoformat(),
            "modified": self.modified.isoformat(),
            "references": self.references,
            "tags": self.tags,
            "logsource": {
                "category": self.logsource.category,
                "product": self.logsource.product,
                "service": self.logsource.service,
            },
            "detection": {
                "keywords": self.detection.keywords,
                "field_mappings": self.detection.field_mappings,
                "condition": self.detection.condition,
                "timeframe": self.detection.timeframe,
            },
            "falsepositives": self.falsepositives,
            "level": self.level.value,
            "mitre_attack": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "sub_technique": m.sub_technique,
                }
                for m in self.mitre_attack
            ],
            "confidence_score": self.confidence_score,
            "confidence_rationale": self.confidence_rationale,
            "generated_at": self.generated_at.isoformat(),
            "source_type": self.source_type,
            "source_summary": self.source_summary,
        }


class ValidationResult(BaseModel):
    """Result of SIGMA rule validation."""

    model_config = ConfigDict(frozen=False)

    valid: bool
    rule: SigmaRule | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    yaml_output: str | None = None


class GenerationResult(BaseModel):
    """Result of the full rule generation pipeline."""

    model_config = ConfigDict(frozen=False)

    success: bool
    rules: list[SigmaRule] = Field(default_factory=list)
    source_type: str = ""
    source_summary: str = ""
    total_generated: int = 0
    generation_time_ms: float = 0.0
    model_used: str = ""
    error: str | None = None
