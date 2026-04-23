"""Tests for Pydantic models in sigma_generator.models.sigma."""
from __future__ import annotations

import re
from datetime import date, datetime
from io import StringIO
from uuid import UUID

import pytest
from pydantic import ValidationError
from ruamel.yaml import YAML

from sigma_generator.models.sigma import (
    GenerationResult,
    MitreAttack,
    SigmaDetection,
    SigmaLevel,
    SigmaLogsource,
    SigmaRule,
    SigmaStatus,
    ValidationResult,
)

_YAML_PARSER = YAML()


def _make_minimal_rule(**overrides) -> SigmaRule:
    defaults = dict(
        title="Test Detection Rule",
        name="test-detection-rule",
        description="Detects suspicious test activity for unit testing purposes.",
        logsource=SigmaLogsource(category="process_creation", product="windows"),
        detection=SigmaDetection(
            field_mappings={"CommandLine|contains": ["mimikatz"]},
            condition="selection",
        ),
        level=SigmaLevel.high,
        tags=["attack.execution", "attack.t1059.001"],
        mitre_attack=[
            MitreAttack(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                sub_technique="001",
            )
        ],
        confidence_score=0.85,
        confidence_rationale="High confidence based on specific command line strings.",
        falsepositives=["Legitimate security testing tools"],
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )
    defaults.update(overrides)
    return SigmaRule(**defaults)


class TestSigmaRule:
    def test_rule_creation_with_defaults(self):
        rule = _make_minimal_rule()
        assert isinstance(rule.rule_id, UUID)
        assert isinstance(rule.date, date)
        assert rule.status == SigmaStatus.experimental
        assert isinstance(rule.generated_at, datetime)

    def test_to_sigma_yaml_contains_required_fields(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        for key in ("title", "id", "status", "description", "logsource", "detection", "level"):
            assert key in yaml_str, f"'{key}' missing from SIGMA YAML output"

    def test_to_sigma_yaml_excludes_metadata(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        assert "confidence_score" not in yaml_str
        assert "generated_at" not in yaml_str
        assert "source_type" not in yaml_str

    def test_to_sigma_yaml_valid_parseable_yaml(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert isinstance(parsed, dict)

    def test_detection_condition_in_yaml(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert "condition" in parsed["detection"]

    def test_mitre_tags_format(self):
        rule = _make_minimal_rule()
        technique_tags = [t for t in rule.tags if t.startswith("attack.t")]
        assert any(re.match(r"attack\.t\d{4}(\.\d{3})?", tag) for tag in technique_tags)

    def test_name_slug_format(self):
        rule = _make_minimal_rule(name="My Rule With SPACES and Capitals!")
        assert rule.name == rule.name.lower()
        assert " " not in rule.name
        assert re.match(r"^[a-z0-9-]+$", rule.name)

    def test_confidence_score_bounds(self):
        with pytest.raises(ValidationError):
            _make_minimal_rule(confidence_score=1.5)
        with pytest.raises(ValidationError):
            _make_minimal_rule(confidence_score=-0.1)

    def test_to_dict_contains_all_metadata(self):
        rule = _make_minimal_rule()
        d = rule.to_dict()
        assert "confidence_score" in d
        assert "generated_at" in d
        assert "mitre_attack" in d
        assert isinstance(d["mitre_attack"], list)

    def test_logsource_in_yaml(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert "category" in parsed["logsource"]
        assert parsed["logsource"]["category"] == "process_creation"

    def test_field_mappings_appear_as_selection_in_yaml(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert "selection" in parsed["detection"]

    def test_keywords_appear_in_yaml(self):
        rule = _make_minimal_rule(
            detection=SigmaDetection(
                keywords=["mimikatz", "sekurlsa"],
                field_mappings={},
                condition="keywords",
            )
        )
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert "keywords" in parsed["detection"]

    def test_rule_id_is_uuid_string_in_yaml(self):
        rule = _make_minimal_rule()
        yaml_str = rule.to_sigma_yaml()
        parsed = _YAML_PARSER.load(StringIO(yaml_str))
        assert UUID(parsed["id"])  # raises if not valid UUID


class TestValidationResult:
    def test_valid_result_construction(self):
        rule = _make_minimal_rule()
        result = ValidationResult(valid=True, rule=rule, errors=[], warnings=[])
        assert result.valid
        assert result.rule is not None
        assert result.errors == []

    def test_invalid_result_has_errors(self):
        result = ValidationResult(valid=False, errors=["title is empty"], warnings=[])
        assert not result.valid
        assert "title is empty" in result.errors
        assert result.rule is None


class TestGenerationResult:
    def test_success_result_has_rules(self):
        rule = _make_minimal_rule()
        result = GenerationResult(
            success=True,
            rules=[rule],
            total_generated=1,
            generation_time_ms=500.0,
            model_used="claude-sonnet-4-6",
        )
        assert result.success
        assert len(result.rules) == 1
        assert result.total_generated == 1

    def test_failure_result_has_error(self):
        result = GenerationResult(
            success=False,
            error="API authentication failed",
            model_used="claude-sonnet-4-6",
        )
        assert not result.success
        assert result.error == "API authentication failed"
        assert result.rules == []
