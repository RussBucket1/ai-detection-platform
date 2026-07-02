"""Tests for triage_assistant.models.alert and triage_assistant.models.triage."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from triage_assistant.models.alert import AlertSeverity, AlertSource, ElasticAlert, RawAlert, SplunkAlert
from triage_assistant.models.triage import (
    ContextMatch,
    MitreTechnique,
    RecommendedAction,
    TriageResult,
    TriageVerdict,
)


# ---------------------------------------------------------------------------
# TestRawAlert
# ---------------------------------------------------------------------------


class TestRawAlert:
    def test_default_fields_set(self) -> None:
        alert = RawAlert(title="Test Alert", description="desc")
        assert alert.alert_id  # uuid4 string generated
        assert isinstance(alert.timestamp, datetime)
        assert alert.source == AlertSource.manual
        assert alert.severity == AlertSeverity.medium

    def test_to_context_string_includes_non_none_fields(self) -> None:
        alert = RawAlert(
            title="Suspicious Network",
            description="Outbound connection detected",
            source_ip="192.168.1.100",
        )
        ctx = alert.to_context_string()
        assert "192.168.1.100" in ctx
        assert "Suspicious Network" in ctx
        assert "Outbound connection detected" in ctx

    def test_to_context_string_excludes_none_fields(self) -> None:
        alert = RawAlert(title="T", description="D")
        ctx = alert.to_context_string()
        assert "SourceIP" not in ctx
        assert "DestIP" not in ctx
        assert "FileHash" not in ctx
        assert "CommandLine" not in ctx

    def test_splunk_alert_conversion(self) -> None:
        splunk = SplunkAlert(
            search_name="Mimikatz Detected",
            result={
                "src_ip": "10.0.0.5",
                "user": "CORP\\jdoe",
                "host": "WIN-WORKSTATION",
                "CommandLine": "sekurlsa::logonpasswords",
                "EventCode": "4688",
            },
        )
        alert = splunk.to_raw_alert()
        assert alert.title == "Mimikatz Detected"
        assert alert.source_ip == "10.0.0.5"
        assert alert.user == "CORP\\jdoe"
        assert alert.host == "WIN-WORKSTATION"
        assert alert.command_line == "sekurlsa::logonpasswords"
        assert alert.event_id == "4688"
        assert alert.source == AlertSource.splunk

    def test_elastic_alert_conversion(self) -> None:
        elastic = ElasticAlert(
            rule={
                "name": "PowerShell Execution Policy Bypass",
                "description": "Detects PowerShell with bypass flag",
                "severity": "high",
            },
            signal={"_source": {"host": {"name": "srv-01"}, "user": {"name": "alice"}}},
        )
        alert = elastic.to_raw_alert()
        assert alert.title == "PowerShell Execution Policy Bypass"
        assert alert.severity == AlertSeverity.high
        assert alert.host == "srv-01"
        assert alert.user == "alice"
        assert alert.source == AlertSource.elastic


# ---------------------------------------------------------------------------
# TestTriageResult
# ---------------------------------------------------------------------------


class TestTriageResult:
    def _make_result(self, **kwargs) -> TriageResult:
        defaults = dict(
            alert_id="alert-123",
            verdict=TriageVerdict.likely_true_positive,
            recommended_action=RecommendedAction.investigate,
            severity_assessment=AlertSeverity.high,
            confidence=0.85,
            confidence_rationale="IOC hit on known C2 IP",
            summary="Alert appears to be a true positive lateral movement attempt.",
            analyst_notes="The source IP 1.2.3.4 matches a known Cobalt Strike C2.",
        )
        defaults.update(kwargs)
        return TriageResult(**defaults)

    def test_default_fields_set(self) -> None:
        result = self._make_result()
        assert isinstance(result.triage_id, uuid.UUID)
        assert isinstance(result.triaged_at, datetime)

    def test_to_analyst_report_contains_verdict(self) -> None:
        result = self._make_result()
        report = result.to_analyst_report()
        assert "Likely True Positive" in report

    def test_to_analyst_report_contains_summary(self) -> None:
        result = self._make_result()
        report = result.to_analyst_report()
        assert "lateral movement" in report

    def test_to_analyst_report_contains_mitre(self) -> None:
        result = self._make_result(
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    tactic="Execution",
                    confidence=0.9,
                )
            ]
        )
        report = result.to_analyst_report()
        assert "T1059.001" in report
        assert "PowerShell" in report

    def test_context_match_relevance_bounds(self) -> None:
        match = ContextMatch(
            source="ioc_database",
            document_id="abc",
            title="1.2.3.4",
            relevance_score=0.95,
            excerpt="Known C2 IP",
        )
        assert 0.0 <= match.relevance_score <= 1.0

    def test_context_match_relevance_min_boundary(self) -> None:
        match = ContextMatch(
            source="sigma_rules",
            document_id="x",
            title="rule",
            relevance_score=0.0,
            excerpt="...",
        )
        assert match.relevance_score == 0.0

    def test_context_match_relevance_max_boundary(self) -> None:
        match = ContextMatch(
            source="mitre_attack",
            document_id="T1059",
            title="Command and Scripting Interpreter",
            relevance_score=1.0,
            excerpt="...",
        )
        assert match.relevance_score == 1.0
