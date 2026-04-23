"""Tests for SigmaValidator — validation logic for SIGMA rules and YAML."""
from __future__ import annotations

import pytest

from sigma_generator.models.sigma import (
    MitreAttack,
    SigmaDetection,
    SigmaLevel,
    SigmaLogsource,
    SigmaRule,
    SigmaStatus,
)
from sigma_generator.validator import SigmaValidator

_VALID_YAML = """\
title: Mimikatz Credential Dumping
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects mimikatz credential dumping activity via LSASS access.
author: AI Detection Platform
date: 2024/01/01
modified: 2024/01/01
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - mimikatz
      - sekurlsa
  condition: selection
falsepositives:
  - Legitimate security assessment tools used by pentesters
level: high
"""


@pytest.fixture()
def validator() -> SigmaValidator:
    return SigmaValidator()


@pytest.fixture()
def valid_sigma_rule() -> SigmaRule:
    return SigmaRule(
        title="Mimikatz Credential Dumping via LSASS",
        name="mimikatz-credential-dumping-via-lsass",
        description="Detects mimikatz sekurlsa module executing credential dumping against LSASS.",
        status=SigmaStatus.experimental,
        level=SigmaLevel.high,
        logsource=SigmaLogsource(category="process_creation", product="windows"),
        detection=SigmaDetection(
            field_mappings={
                "CommandLine|contains": ["mimikatz", "sekurlsa"],
                "Image|endswith": ["\\mimikatz.exe"],
            },
            condition="selection",
        ),
        tags=["attack.credential_access", "attack.t1003.001"],
        falsepositives=["Authorised penetration testing activities"],
        references=["https://attack.mitre.org/techniques/T1003/001/"],
        mitre_attack=[
            MitreAttack(
                technique_id="T1003.001",
                technique_name="LSASS Memory",
                tactic="credential_access",
                sub_technique="001",
            )
        ],
        confidence_score=0.9,
        confidence_rationale="Very specific strings that are exclusive to mimikatz.",
    )


class TestSigmaValidator:
    def test_valid_rule_passes(self, validator, valid_sigma_rule):
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert result.errors == []

    def test_empty_title_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.title = ""
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("title" in e.lower() for e in result.errors)

    def test_title_too_long_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.title = "A" * 101
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("100" in e or "title" in e.lower() for e in result.errors)

    def test_empty_description_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.description = ""
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("description" in e.lower() for e in result.errors)

    def test_no_logsource_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.logsource = SigmaLogsource(
            category=None, product=None, service=None
        )
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("logsource" in e.lower() for e in result.errors)

    def test_empty_condition_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.detection.condition = ""
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("condition" in e.lower() for e in result.errors)

    def test_no_detection_content_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.detection.field_mappings = {}
        valid_sigma_rule.detection.keywords = []
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("detection" in e.lower() or "keywords" in e.lower() for e in result.errors)

    def test_invalid_confidence_raises(self):
        with pytest.raises(Exception):
            SigmaRule(
                title="Test",
                name="test",
                description="desc",
                logsource=SigmaLogsource(category="process_creation"),
                detection=SigmaDetection(keywords=["x"], condition="keywords"),
                confidence_score=1.5,
            )

    def test_invalid_mitre_id_fails(self, validator, valid_sigma_rule):
        valid_sigma_rule.mitre_attack = [
            MitreAttack(
                technique_id="TXXX",
                technique_name="Bad",
                tactic="execution",
            )
        ]
        result = validator.validate_rule(valid_sigma_rule)
        assert not result.valid
        assert any("TXXX" in e or "technique" in e.lower() for e in result.errors)

    def test_valid_mitre_pattern_passes(self, validator, valid_sigma_rule):
        for tid in ["T1059", "T1059.001"]:
            valid_sigma_rule.mitre_attack = [
                MitreAttack(technique_id=tid, technique_name="Test", tactic="execution")
            ]
            result = validator.validate_rule(valid_sigma_rule)
            assert result.valid, f"T{tid} should be valid but got errors: {result.errors}"

    def test_empty_falsepositives_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.falsepositives = []
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("false positive" in w.lower() or "falsepositives" in w.lower() for w in result.warnings)

    def test_keyword_only_detection_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.detection.field_mappings = {}
        valid_sigma_rule.detection.keywords = ["mimikatz", "sekurlsa"]
        valid_sigma_rule.detection.condition = "keywords"
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("keyword" in w.lower() or "field" in w.lower() for w in result.warnings)

    def test_low_confidence_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.confidence_score = 0.3
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("confidence" in w.lower() for w in result.warnings)

    def test_critical_level_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.level = SigmaLevel.critical
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("critical" in w.lower() for w in result.warnings)

    def test_no_references_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.references = []
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("reference" in w.lower() for w in result.warnings)

    def test_no_mitre_mapping_warns(self, validator, valid_sigma_rule):
        valid_sigma_rule.mitre_attack = []
        result = validator.validate_rule(valid_sigma_rule)
        assert result.valid
        assert any("mitre" in w.lower() or "att&ck" in w.lower() for w in result.warnings)


class TestYamlValidation:
    def test_valid_yaml_passes(self, validator):
        is_valid, errors = validator.validate_yaml(_VALID_YAML)
        assert is_valid, f"Expected valid but got errors: {errors}"
        assert errors == []

    def test_missing_title_fails(self, validator):
        yaml_no_title = _VALID_YAML.replace("title: Mimikatz Credential Dumping\n", "")
        is_valid, errors = validator.validate_yaml(yaml_no_title)
        assert not is_valid
        assert any("title" in e.lower() for e in errors)

    def test_missing_detection_condition_fails(self, validator):
        yaml_no_condition = _VALID_YAML.replace("  condition: selection\n", "")
        is_valid, errors = validator.validate_yaml(yaml_no_condition)
        assert not is_valid
        assert any("condition" in e.lower() for e in errors)

    def test_unparseable_yaml_fails(self, validator):
        is_valid, errors = validator.validate_yaml("this: is: not: valid: yaml: !!!")
        assert not is_valid
        assert len(errors) > 0
