"""Tests for IOC, SIGMA, and MITRE ingestion modules."""
from __future__ import annotations

import json
import textwrap
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from triage_assistant.ingestion.ioc_ingester import IOCIngester
from triage_assistant.ingestion.mitre_ingester import MitreIngester
from triage_assistant.ingestion.sigma_ingester import SigmaIngester


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_mock_store(add_returns: int = 1) -> MagicMock:
    store = MagicMock()
    store.add_documents.return_value = add_returns
    return store


# ---------------------------------------------------------------------------
# TestIOCIngester
# ---------------------------------------------------------------------------


class TestIOCIngester:
    _SAMPLE_IOC = {
        "ioc_value": "192.168.100.5",
        "ioc_type": "ipv4",
        "risk_score": 87,
        "risk_band": "HIGH",
        "tags": ["botnet", "scanner"],
        "mitre_techniques": ["T1071.001"],
        "source": "abuseipdb",
        "enriched_at": "2024-01-01T00:00:00Z",
        "fingerprint": "abc123",
    }

    def test_ingest_single_ioc_json(self, tmp_path: Path) -> None:
        ioc_file = tmp_path / "ioc.json"
        ioc_file.write_text(json.dumps(self._SAMPLE_IOC))

        store = _make_mock_store(1)
        ingester = IOCIngester(store)
        count = ingester.ingest_file(ioc_file)

        assert count == 1
        store.add_documents.assert_called_once()

    def test_ioc_to_document_format(self) -> None:
        store = _make_mock_store()
        ingester = IOCIngester(store)
        doc_text, meta, doc_id = ingester._ioc_to_document(self._SAMPLE_IOC)

        assert "192.168.100.5" in doc_text
        assert "HIGH" in doc_text
        assert "botnet" in doc_text

    def test_ioc_to_document_metadata_keys(self) -> None:
        store = _make_mock_store()
        ingester = IOCIngester(store)
        _, meta, _ = ingester._ioc_to_document(self._SAMPLE_IOC)

        assert "ioc_value" in meta
        assert "ioc_type" in meta
        assert "risk_score" in meta

    def test_ingest_ndjson_line_by_line(self, tmp_path: Path) -> None:
        ndjson_file = tmp_path / "iocs.ndjson"
        lines = [json.dumps({**self._SAMPLE_IOC, "ioc_value": f"10.0.0.{i}"}) for i in range(3)]
        ndjson_file.write_text("\n".join(lines))

        store = _make_mock_store(3)
        ingester = IOCIngester(store)
        count = ingester.ingest_file(ndjson_file)

        assert count == 3

    def test_ingest_missing_file_returns_zero(self) -> None:
        store = _make_mock_store()
        ingester = IOCIngester(store)
        count = ingester.ingest_file("/nonexistent/path/ioc.json")
        assert count == 0
        store.add_documents.assert_not_called()


# ---------------------------------------------------------------------------
# TestSigmaIngester
# ---------------------------------------------------------------------------


_SIGMA_YAML = textwrap.dedent("""\
    title: Mimikatz Credential Dump
    id: 12345678-1234-1234-1234-123456789012
    status: stable
    description: Detects Mimikatz usage via known command line patterns
    level: critical
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        CommandLine|contains:
          - sekurlsa::logonpasswords
          - mimikatz.exe
      condition: selection
    tags:
      - attack.credential_access
      - attack.t1003
    falsepositives:
      - Security testing
      - Authorized pen testing
    author: Test Author
    date: 2024-01-01
""")


class TestSigmaIngester:
    def test_ingest_single_yaml(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(_SIGMA_YAML)

        store = _make_mock_store(1)
        ingester = SigmaIngester(store)
        count = ingester.ingest_file(rule_file)

        assert count == 1
        store.add_documents.assert_called_once()

    def test_sigma_to_document_format(self) -> None:
        from ruamel.yaml import YAML
        _yaml = YAML()
        rule_dict = _yaml.load(_SIGMA_YAML)

        store = _make_mock_store()
        ingester = SigmaIngester(store)
        doc_text, meta, doc_id = ingester._rule_to_document(rule_dict)

        assert "Mimikatz Credential Dump" in doc_text
        assert "windows" in doc_text
        assert "process_creation" in doc_text
        assert "sekurlsa" in doc_text or "logonpasswords" in doc_text

    def test_sigma_to_document_metadata_keys(self) -> None:
        from ruamel.yaml import YAML
        _yaml = YAML()
        rule_dict = _yaml.load(_SIGMA_YAML)

        store = _make_mock_store()
        ingester = SigmaIngester(store)
        _, meta, _ = ingester._rule_to_document(rule_dict)

        assert "title" in meta
        assert "level" in meta
        assert "logsource_category" in meta

    def test_ingest_directory(self, tmp_path: Path) -> None:
        (tmp_path / "rule1.yml").write_text(_SIGMA_YAML)
        (tmp_path / "rule2.yml").write_text(_SIGMA_YAML.replace("Mimikatz", "Rubeus").replace("12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321"))

        store = _make_mock_store(1)
        ingester = SigmaIngester(store)
        count = ingester.ingest_directory(tmp_path)

        assert count == 2

    def test_ingest_invalid_yaml_returns_zero(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("key: [unclosed bracket")

        store = _make_mock_store()
        ingester = SigmaIngester(store)
        count = ingester.ingest_file(bad_file)
        # Invalid YAML returns 0 and does not raise
        assert count == 0


# ---------------------------------------------------------------------------
# TestMitreIngester
# ---------------------------------------------------------------------------


def _make_stix_technique(
    technique_id: str = "T1059",
    name: str = "Command and Scripting Interpreter",
    revoked: bool = False,
    deprecated: bool = False,
) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{technique_id}",
        "name": name,
        "description": f"Adversaries may abuse {name} to execute commands.",
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "x_mitre_is_subtechnique": "." in technique_id,
        "x_mitre_platforms": ["Windows", "Linux"],
        "x_mitre_data_sources": ["Process: Process Creation"],
        "x_mitre_detection": "Monitor for command execution with suspicious arguments.",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": technique_id}
        ],
    }


def _make_stix_bundle(techniques: list[dict]) -> dict:
    return {"type": "bundle", "objects": techniques}


class TestMitreIngester:
    def test_technique_to_document_format(self) -> None:
        store = _make_mock_store()
        ingester = MitreIngester(store)
        technique = _make_stix_technique("T1059", "Command and Scripting Interpreter")
        doc_text, meta, doc_id = ingester._technique_to_document(technique)

        assert "T1059" in doc_text
        assert "Command and Scripting Interpreter" in doc_text
        assert "Execution" in doc_text

    def test_technique_to_document_metadata(self) -> None:
        store = _make_mock_store()
        ingester = MitreIngester(store)
        technique = _make_stix_technique("T1059.001", "PowerShell")
        _, meta, _ = ingester._technique_to_document(technique)

        assert meta["technique_id"] == "T1059.001"
        assert meta["tactic"] == "Execution"
        assert meta["is_subtechnique"] is True

    def test_deprecated_techniques_skipped(self) -> None:
        bundle = _make_stix_bundle([
            _make_stix_technique("T1059"),
            _make_stix_technique("T1060", "Legacy Technique", revoked=True),
            _make_stix_technique("T1061", "Old Technique", deprecated=True),
        ])

        store = _make_mock_store(1)
        ingester = MitreIngester(store)
        with patch.object(ingester, "download_mitre_data", return_value=bundle):
            count = ingester.ingest()

        # Only T1059 (not revoked/deprecated) should be ingested
        assert count == 1

    def test_cache_used_if_exists(self, tmp_path: Path) -> None:
        bundle = _make_stix_bundle([_make_stix_technique("T1059")])
        cache_file = tmp_path / "mitre.json"
        cache_file.write_text(json.dumps(bundle))

        store = _make_mock_store(1)
        ingester = MitreIngester(store)

        with patch("requests.get") as mock_get:
            ingester.ingest(cache_path=cache_file)
            mock_get.assert_not_called()

    def test_ingest_count(self) -> None:
        techniques = [_make_stix_technique(f"T100{i}") for i in range(5)]
        bundle = _make_stix_bundle(techniques)

        store = _make_mock_store(5)
        ingester = MitreIngester(store)
        with patch.object(ingester, "download_mitre_data", return_value=bundle):
            count = ingester.ingest()

        assert count == 5
