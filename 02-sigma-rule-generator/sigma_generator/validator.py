"""Validate SigmaRule objects and their YAML output against the SIGMA specification."""
from __future__ import annotations

import re

from ruamel.yaml import YAML
from ruamel.yaml.scanner import ScannerError

from sigma_generator.models.sigma import SigmaRule, ValidationResult
from sigma_generator.utils.logger import get_logger

logger = get_logger(__name__)

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

_YAML_PARSER = YAML()
_YAML_PARSER.preserve_quotes = True


class SigmaValidator:
    """Validates SigmaRule objects against the SIGMA specification.

    Distinguishes between hard errors (rule is unusable) and warnings
    (rule is valid but suboptimal and needs review before production use).
    """

    REQUIRED_FIELDS: list[str] = ["title", "description", "logsource", "detection"]

    VALID_TACTICS: set[str] = {
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
        "resource_development",
        "reconnaissance",
    }

    VALID_LOGSOURCE_CATEGORIES: set[str] = {
        "process_creation",
        "network_connection",
        "file_event",
        "registry_event",
        "registry_add",
        "registry_set",
        "dns_query",
        "image_load",
        "pipe_created",
        "driver_loaded",
        "create_remote_thread",
        "raw_access_read",
        "access_process",
        "wmi_event",
        "scheduled_task",
        "user_account",
        "authentication",
        "web",
        "firewall",
        "proxy",
        "antivirus",
    }

    def validate_rule(self, rule: SigmaRule) -> ValidationResult:
        """Run all validations on a SigmaRule and collect errors and warnings.

        Args:
            rule: The SigmaRule to validate.

        Returns:
            ValidationResult with valid flag, errors list, warnings list,
            and the YAML output if valid.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # --- Hard errors ---

        if not rule.title or not rule.title.strip():
            errors.append("Rule title is empty.")
        elif len(rule.title) > 100:
            errors.append(
                f"Rule title exceeds 100 characters ({len(rule.title)} chars): {rule.title[:50]!r}..."
            )

        if not rule.description or not rule.description.strip():
            errors.append("Rule description is empty.")

        logsource = rule.logsource
        if not any([logsource.category, logsource.product, logsource.service]):
            errors.append(
                "Logsource has no category, product, or service set. "
                "At least one logsource field is required."
            )

        if not rule.detection.condition or not rule.detection.condition.strip():
            errors.append("Detection condition is empty.")

        has_keywords = bool(rule.detection.keywords)
        has_field_mappings = bool(rule.detection.field_mappings)
        if not has_keywords and not has_field_mappings:
            errors.append(
                "Detection block has neither keywords nor field_mappings. "
                "At least one must be present."
            )

        if not (0.0 <= rule.confidence_score <= 1.0):
            errors.append(
                f"confidence_score {rule.confidence_score} is outside valid range [0.0, 1.0]."
            )

        for mitre in rule.mitre_attack:
            if not _TECHNIQUE_ID_RE.match(mitre.technique_id):
                errors.append(
                    f"Invalid MITRE technique ID format: {mitre.technique_id!r}. "
                    "Expected pattern: T####[.###]"
                )

        # --- Warnings ---

        from sigma_generator.models.sigma import SigmaLevel, SigmaStatus

        if rule.status != SigmaStatus.experimental:
            warnings.append(
                f"Rule status is '{rule.status.value}' — AI-generated rules should start "
                "as 'experimental' until reviewed by a human analyst."
            )

        if rule.level == SigmaLevel.critical:
            warnings.append(
                "Rule level is 'critical'. Critical severity should be used sparingly — "
                "only for confirmed active exploitation with immediate, significant impact."
            )

        if not rule.falsepositives:
            warnings.append(
                "No false positives specified. Adding specific false positive guidance "
                "helps SOC analysts tune the rule for their environment."
            )

        if has_keywords and not has_field_mappings:
            warnings.append(
                "Detection uses only keywords without field mappings. "
                "Field-based detection provides higher precision and fewer false positives."
            )

        if rule.confidence_score < 0.5:
            warnings.append(
                f"Low confidence score ({rule.confidence_score:.2f}). "
                "This rule requires careful review by a detection engineer before deployment."
            )

        if not rule.references:
            warnings.append(
                "No source references provided. Adding references helps analysts "
                "understand the threat context and validate the rule logic."
            )

        if not rule.mitre_attack:
            warnings.append(
                "No MITRE ATT&CK mapping. Adding ATT&CK technique IDs enables "
                "coverage tracking and threat-informed defense workflows."
            )

        valid = len(errors) == 0
        yaml_output: str | None = None

        if valid:
            try:
                yaml_output = rule.to_sigma_yaml()
                yaml_valid, yaml_errors = self.validate_yaml(yaml_output)
                if not yaml_valid:
                    errors.extend(yaml_errors)
                    valid = False
            except Exception as exc:
                errors.append(f"YAML serialization failed: {exc}")
                valid = False

        logger.debug(
            "Rule validated",
            title=rule.title,
            valid=valid,
            errors=len(errors),
            warnings=len(warnings),
        )

        return ValidationResult(
            valid=valid,
            rule=rule if valid else None,
            errors=errors,
            warnings=warnings,
            yaml_output=yaml_output,
        )

    def validate_yaml(self, yaml_str: str) -> tuple[bool, list[str]]:
        """Parse a SIGMA YAML string and verify structural validity.

        Checks that required top-level keys are present and that the detection
        block contains a 'condition' key.

        Args:
            yaml_str: SIGMA rule YAML string.

        Returns:
            Tuple of (is_valid, list_of_error_messages).
        """
        errors: list[str] = []

        try:
            from io import StringIO

            data = _YAML_PARSER.load(StringIO(yaml_str))
        except ScannerError as exc:
            return False, [f"YAML syntax error: {exc}"]
        except Exception as exc:
            return False, [f"YAML parse error: {exc}"]

        if not isinstance(data, dict):
            return False, ["YAML top level is not a mapping."]

        required_keys = {"title", "id", "status", "description", "logsource", "detection", "level"}
        missing = required_keys - set(data.keys())
        if missing:
            errors.append(f"Missing required SIGMA keys: {sorted(missing)}")

        detection = data.get("detection")
        if isinstance(detection, dict):
            if "condition" not in detection:
                errors.append("Detection block is missing the required 'condition' key.")
        elif detection is not None:
            errors.append(
                f"Detection block must be a YAML mapping, got {type(detection).__name__}."
            )

        logsource = data.get("logsource")
        if logsource is not None and not isinstance(logsource, dict):
            errors.append(
                f"Logsource block must be a YAML mapping, got {type(logsource).__name__}."
            )

        return len(errors) == 0, errors
