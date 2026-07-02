"""Pydantic v2 models for incoming SIEM alerts."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    """Origin system for the alert."""

    splunk = "splunk"
    elastic = "elastic"
    sentinel = "sentinel"
    manual = "manual"
    unknown = "unknown"


class AlertSeverity(str, Enum):
    """Analyst-facing severity classification."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class RawAlert(BaseModel):
    """Normalized SIEM alert ready for triage pipeline ingestion."""

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    source: AlertSource = AlertSource.manual
    severity: AlertSeverity = AlertSeverity.medium
    raw_log: str | None = None
    host: str | None = None
    user: str | None = None
    process: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    file_hash: str | None = None
    file_path: str | None = None
    event_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    extra_fields: dict[str, Any] = Field(default_factory=dict)

    def to_context_string(self) -> str:
        """Format all non-None fields into a readable text block for embedding and LLM injection."""
        lines: list[str] = [
            f"Alert: {self.title}",
            f"Description: {self.description}",
            f"Source: {self.source.value}",
            f"Severity: {self.severity.value}",
        ]
        if self.host:
            lines.append(f"Host: {self.host}")
        if self.user:
            lines.append(f"User: {self.user}")
        if self.process:
            lines.append(f"Process: {self.process}")
        if self.command_line:
            lines.append(f"CommandLine: {self.command_line}")
        if self.source_ip:
            lines.append(f"SourceIP: {self.source_ip}")
        if self.dest_ip:
            lines.append(f"DestIP: {self.dest_ip}")
        if self.file_hash:
            lines.append(f"FileHash: {self.file_hash}")
        if self.file_path:
            lines.append(f"FilePath: {self.file_path}")
        if self.event_id:
            lines.append(f"EventID: {self.event_id}")
        if self.raw_log:
            lines.append(f"RawLog: {self.raw_log}")
        if self.extra_fields:
            for k, v in self.extra_fields.items():
                lines.append(f"{k}: {v}")
        lines.append(f"Timestamp: {self.timestamp.isoformat()}")
        return "\n".join(lines)


class SplunkAlert(BaseModel):
    """Splunk webhook payload format for real-time alert ingestion."""

    result: dict[str, Any]
    search_name: str
    owner: str | None = None
    app: str | None = None

    def to_raw_alert(self) -> RawAlert:
        """Convert Splunk webhook payload to a normalized RawAlert.

        Extracts common Splunk result fields: src_ip → source_ip, dest_ip, user,
        host, process, CommandLine → command_line, EventCode → event_id.
        Uses search_name as the alert title.
        """
        r = self.result
        severity_map = {
            "critical": AlertSeverity.critical,
            "high": AlertSeverity.high,
            "medium": AlertSeverity.medium,
            "low": AlertSeverity.low,
            "informational": AlertSeverity.informational,
        }
        raw_severity = str(r.get("severity", r.get("urgency", "medium"))).lower()
        severity = severity_map.get(raw_severity, AlertSeverity.medium)

        return RawAlert(
            title=self.search_name,
            description=str(r.get("_raw", r.get("message", f"Splunk alert: {self.search_name}"))),
            source=AlertSource.splunk,
            severity=severity,
            raw_log=str(r.get("_raw")) if r.get("_raw") else None,
            host=str(r["host"]) if r.get("host") else None,
            user=str(r["user"]) if r.get("user") else None,
            process=str(r["process"]) if r.get("process") else None,
            command_line=str(r["CommandLine"]) if r.get("CommandLine") else None,
            source_ip=str(r["src_ip"]) if r.get("src_ip") else None,
            dest_ip=str(r["dest_ip"]) if r.get("dest_ip") else None,
            file_hash=str(r["file_hash"]) if r.get("file_hash") else None,
            file_path=str(r["file_path"]) if r.get("file_path") else None,
            event_id=str(r["EventCode"]) if r.get("EventCode") else None,
            extra_fields={
                k: v
                for k, v in r.items()
                if k
                not in {
                    "host",
                    "user",
                    "process",
                    "CommandLine",
                    "src_ip",
                    "dest_ip",
                    "file_hash",
                    "file_path",
                    "EventCode",
                    "_raw",
                    "severity",
                    "urgency",
                    "message",
                }
            },
        )


class ElasticAlert(BaseModel):
    """Elastic alerting webhook payload format for real-time alert ingestion."""

    rule: dict[str, Any]
    signal: dict[str, Any] | None = None

    def to_raw_alert(self) -> RawAlert:
        """Convert Elastic alerting payload to a normalized RawAlert.

        Extracts: rule.name → title, rule.description, rule.severity → severity,
        signal fields for host/user/process where available.
        """
        severity_map = {
            "critical": AlertSeverity.critical,
            "high": AlertSeverity.high,
            "medium": AlertSeverity.medium,
            "low": AlertSeverity.low,
            "informational": AlertSeverity.informational,
        }
        raw_severity = str(self.rule.get("severity", "medium")).lower()
        severity = severity_map.get(raw_severity, AlertSeverity.medium)

        signal_source: dict[str, Any] = {}
        if self.signal:
            signal_source = self.signal.get("_source", self.signal)

        host = None
        if signal_source.get("host"):
            host_data = signal_source["host"]
            host = host_data.get("name") if isinstance(host_data, dict) else str(host_data)

        user = None
        if signal_source.get("user"):
            user_data = signal_source["user"]
            user = user_data.get("name") if isinstance(user_data, dict) else str(user_data)

        process = None
        if signal_source.get("process"):
            proc_data = signal_source["process"]
            process = proc_data.get("name") if isinstance(proc_data, dict) else str(proc_data)

        return RawAlert(
            title=str(self.rule.get("name", "Elastic Alert")),
            description=str(self.rule.get("description", "No description provided")),
            source=AlertSource.elastic,
            severity=severity,
            host=host,
            user=user,
            process=process,
            source_ip=str(signal_source["source"]["ip"])
            if signal_source.get("source", {}).get("ip")
            else None,
            dest_ip=str(signal_source["destination"]["ip"])
            if signal_source.get("destination", {}).get("ip")
            else None,
            extra_fields={"rule_id": self.rule.get("id", ""), "rule_tags": self.rule.get("tags", [])},
        )


def _sha256_hex(value: str) -> str:
    """Return the first 16 hex chars of a SHA-256 hash — used for deterministic IDs."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]
