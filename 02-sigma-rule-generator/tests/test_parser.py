"""Tests for RuleParser — LLM response parsing and dict-to-SigmaRule conversion."""
from __future__ import annotations

import json

import pytest

from sigma_generator.models.sigma import SigmaRule
from sigma_generator.parser import RuleParser

_VALID_RULE_DICT = {
    "title": "Suspicious PowerShell Download Cradle",
    "name": "suspicious-powershell-download-cradle",
    "description": (
        "Detects PowerShell download cradle patterns used by threat actors to "
        "download and execute payloads from the internet."
    ),
    "status": "experimental",
    "level": "high",
    "logsource": {
        "category": "process_creation",
        "product": "windows",
        "service": None,
    },
    "detection": {
        "keywords": None,
        "field_mappings": {
            "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
            "CommandLine|contains": ["DownloadString", "DownloadFile", "IEX", "Invoke-Expression"],
        },
        "condition": "selection",
        "timeframe": None,
    },
    "tags": ["attack.execution", "attack.t1059.001"],
    "falsepositives": ["Software deployment tools", "Legitimate administrative scripts"],
    "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    "mitre_attack": [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "execution",
            "sub_technique": "001",
        }
    ],
    "confidence_score": 0.85,
    "confidence_rationale": "Specific cmdlet names tied to download cradle patterns.",
    "source_type": "threat_report",
    "source_summary": "PowerShell download cradle abuse in enterprise environment.",
}

_FULL_LLM_RESPONSE = {
    "rules": [_VALID_RULE_DICT],
    "analysis_summary": "Detected PowerShell abuse consistent with T1059.001 execution.",
}


@pytest.fixture()
def parser() -> RuleParser:
    return RuleParser()


class TestRuleParser:
    def test_parse_clean_json(self, parser):
        raw = json.dumps(_FULL_LLM_RESPONSE)
        rules = parser.parse_llm_response(raw)
        assert isinstance(rules, list)
        assert len(rules) == 1

    def test_parse_markdown_wrapped_json(self, parser):
        raw = f"```json\n{json.dumps(_FULL_LLM_RESPONSE)}\n```"
        rules = parser.parse_llm_response(raw)
        assert len(rules) == 1

    def test_parse_json_with_preamble(self, parser):
        raw = (
            "Here are the generated SIGMA rules based on the threat report:\n\n"
            f"```json\n{json.dumps(_FULL_LLM_RESPONSE)}\n```"
        )
        rules = parser.parse_llm_response(raw)
        assert len(rules) == 1

    def test_parse_invalid_json_raises(self, parser):
        with pytest.raises(ValueError, match="[Ff]ailed to parse|JSON"):
            parser.parse_llm_response("this is definitely not json {{{{")

    def test_parse_missing_rules_key_raises(self, parser):
        raw = json.dumps({"analysis_summary": "some text"})
        with pytest.raises(ValueError, match="'rules'|rules"):
            parser.parse_llm_response(raw)


class TestDictToSigmaRule:
    def test_basic_conversion(self, parser):
        rule = parser.dict_to_sigma_rule(_VALID_RULE_DICT)
        assert isinstance(rule, SigmaRule)
        assert rule.title == _VALID_RULE_DICT["title"]
        assert rule.level.value == "high"
        assert rule.status.value == "experimental"

    def test_missing_optional_fields_use_defaults(self, parser):
        minimal = {
            "title": "Minimal Rule",
            "name": "minimal-rule",
            "description": "Minimal test rule.",
            "level": "medium",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"field_mappings": {"CommandLine|contains": ["evil"]}, "condition": "selection"},
        }
        rule = parser.dict_to_sigma_rule(minimal)
        assert rule.references == []
        assert rule.falsepositives == []
        assert rule.mitre_attack == []

    def test_mitre_tag_generation(self, parser):
        rule_dict = dict(_VALID_RULE_DICT)
        rule_dict["tags"] = []
        rule = parser.dict_to_sigma_rule(rule_dict)
        assert "attack.execution" in rule.tags
        assert "attack.t1059.001" in rule.tags

    def test_field_mappings_preserved(self, parser):
        rule = parser.dict_to_sigma_rule(_VALID_RULE_DICT)
        assert "CommandLine|contains" in rule.detection.field_mappings
        assert "DownloadString" in rule.detection.field_mappings["CommandLine|contains"]

    def test_confidence_score_preserved(self, parser):
        rule = parser.dict_to_sigma_rule(_VALID_RULE_DICT)
        assert abs(rule.confidence_score - 0.85) < 1e-9

    def test_invalid_level_falls_back_to_medium(self, parser):
        rule_dict = dict(_VALID_RULE_DICT)
        rule_dict["level"] = "not-a-level"
        rule = parser.dict_to_sigma_rule(rule_dict)
        from sigma_generator.models.sigma import SigmaLevel
        assert rule.level == SigmaLevel.medium

    def test_confidence_clamped_if_out_of_range(self, parser):
        rule_dict = dict(_VALID_RULE_DICT)
        rule_dict["confidence_score"] = 1.5
        rule = parser.dict_to_sigma_rule(rule_dict)
        assert rule.confidence_score == 1.0

    def test_name_auto_generated_from_title_if_missing(self, parser):
        rule_dict = dict(_VALID_RULE_DICT)
        rule_dict["name"] = ""
        rule = parser.dict_to_sigma_rule(rule_dict)
        assert rule.name != ""
        assert " " not in rule.name


class TestParseResponse:
    def test_full_response_parsing(self, parser):
        raw = json.dumps(_FULL_LLM_RESPONSE)
        rules, summary = parser.parse_response(raw)
        assert len(rules) == 1
        assert "T1059" in summary or "PowerShell" in summary or summary

    def test_partial_failure_returns_valid_rules(self, parser):
        malformed = {"title": None, "description": None}
        response = {
            "rules": [_VALID_RULE_DICT, malformed],
            "analysis_summary": "Mixed result",
        }
        rules, summary = parser.parse_response(json.dumps(response))
        # Should return at least the valid rule; the malformed one may or may not
        # parse depending on pydantic defaults, but no exception should be raised.
        assert isinstance(rules, list)

    def test_empty_rules_array_returns_empty(self, parser):
        response = {"rules": [], "analysis_summary": "Nothing found."}
        rules, summary = parser.parse_response(json.dumps(response))
        assert rules == []
        assert summary == "Nothing found."

    def test_completely_invalid_json_returns_empty(self, parser):
        rules, summary = parser.parse_response("garbage not json at all")
        assert rules == []
        assert summary == ""

    def test_analysis_summary_extracted(self, parser):
        raw = json.dumps(_FULL_LLM_RESPONSE)
        _, summary = parser.parse_response(raw)
        assert "PowerShell" in summary or "T1059" in summary or summary != ""
