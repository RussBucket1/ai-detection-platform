"""Pydantic v2 models for structured triage output."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from triage_assistant.models.alert import AlertSeverity


class TriageVerdict(str, Enum):
    """Analyst verdict for the triaged alert."""

    true_positive = "true_positive"
    likely_true_positive = "likely_true_positive"
    needs_investigation = "needs_investigation"
    likely_false_positive = "likely_false_positive"
    false_positive = "false_positive"


class RecommendedAction(str, Enum):
    """Recommended analyst action following triage."""

    escalate_immediately = "escalate_immediately"
    investigate = "investigate"
    monitor = "monitor"
    suppress = "suppress"
    close = "close"


class ContextMatch(BaseModel):
    """A single retrieved document from the RAG knowledge base."""

    source: str
    document_id: str
    title: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    excerpt: str = Field(max_length=500)


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique attribution from the triage LLM."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)


class TriageResult(BaseModel):
    """Fully structured triage assessment produced by the triage pipeline."""

    triage_id: UUID = Field(default_factory=uuid4)
    alert_id: str
    verdict: TriageVerdict
    recommended_action: RecommendedAction
    severity_assessment: AlertSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_rationale: str
    summary: str
    analyst_notes: str
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    context_matches: list[ContextMatch] = Field(default_factory=list)
    ioc_matches: list[str] = Field(default_factory=list)
    sigma_rule_matches: list[str] = Field(default_factory=list)
    recommended_searches: list[str] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    escalation_path: str | None = None
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    triage_duration_ms: float = 0.0
    model_used: str = ""
    context_documents_used: int = 0

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, v)), 4)

    def to_analyst_report(self) -> str:
        """Format a human-readable markdown report suitable for a SOC ticket or incident report."""
        verdict_display = self.verdict.value.replace("_", " ").title()
        action_display = self.recommended_action.value.replace("_", " ").title()
        severity_display = self.severity_assessment.value.upper()

        lines: list[str] = [
            "# Alert Triage Report",
            "",
            f"**Triage ID:** `{self.triage_id}`",
            f"**Alert ID:** `{self.alert_id}`",
            f"**Triaged At:** {self.triaged_at.isoformat()}",
            f"**Model:** {self.model_used}",
            f"**Duration:** {self.triage_duration_ms:.0f} ms",
            "",
            "## Verdict",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Verdict | **{verdict_display}** |",
            f"| Severity | **{severity_display}** |",
            f"| Confidence | **{self.confidence:.0%}** |",
            f"| Recommended Action | **{action_display}** |",
            "",
            "## Summary",
            "",
            self.summary,
            "",
            "## Analyst Notes",
            "",
            self.analyst_notes,
        ]

        if self.mitre_techniques:
            lines += [
                "",
                "## MITRE ATT&CK Techniques",
                "",
                "| Technique ID | Name | Tactic | Confidence |",
                "|-------------|------|--------|------------|",
            ]
            for t in self.mitre_techniques:
                lines.append(
                    f"| {t.technique_id} | {t.technique_name} | {t.tactic} | {t.confidence:.0%} |"
                )

        if self.context_matches:
            lines += [
                "",
                "## RAG Context Matches",
                "",
                "| Source | Title | Relevance |",
                "|--------|-------|-----------|",
            ]
            for m in self.context_matches:
                lines.append(f"| {m.source} | {m.title} | {m.relevance_score:.2f} |")

        if self.ioc_matches:
            lines += ["", "## IOC Matches", ""]
            for ioc in self.ioc_matches:
                lines.append(f"- `{ioc}`")

        if self.sigma_rule_matches:
            lines += ["", "## SIGMA Rule Matches", ""]
            for rule in self.sigma_rule_matches:
                lines.append(f"- {rule}")

        if self.recommended_searches:
            lines += ["", "## Recommended Follow-Up Searches", ""]
            for i, search in enumerate(self.recommended_searches, 1):
                lines += [f"**{i}.** ```", search, "```", ""]

        if self.false_positive_indicators:
            lines += ["", "## False Positive Indicators", ""]
            for fp in self.false_positive_indicators:
                lines.append(f"- {fp}")

        if self.escalation_path:
            lines += ["", "## Escalation Path", "", self.escalation_path]

        lines += ["", "## Confidence Rationale", "", self.confidence_rationale]

        return "\n".join(lines)
