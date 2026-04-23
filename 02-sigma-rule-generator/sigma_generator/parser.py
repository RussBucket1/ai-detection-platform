"""Parse and validate LLM JSON output into SigmaRule models."""
from __future__ import annotations

import json
import re
from typing import Any

from sigma_generator.models.sigma import MitreAttack, SigmaDetection, SigmaLogsource, SigmaRule
from sigma_generator.utils.logger import get_logger

logger = get_logger(__name__)

_CODE_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.MULTILINE)
_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}", re.MULTILINE)

_TACTIC_SLUG_MAP: dict[str, str] = {
    "initial access": "initial_access",
    "initial_access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege escalation": "privilege_escalation",
    "privilege_escalation": "privilege_escalation",
    "defense evasion": "defense_evasion",
    "defense_evasion": "defense_evasion",
    "credential access": "credential_access",
    "credential_access": "credential_access",
    "discovery": "discovery",
    "lateral movement": "lateral_movement",
    "lateral_movement": "lateral_movement",
    "collection": "collection",
    "command and control": "command_and_control",
    "command_and_control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "resource development": "resource_development",
    "resource_development": "resource_development",
    "reconnaissance": "reconnaissance",
}


class RuleParser:
    """Converts raw LLM text responses into validated SigmaRule objects."""

    def _extract_json_obj(self, response_text: str) -> dict[str, Any]:
        """Extract and parse the top-level JSON object from an LLM response.

        Handles responses wrapped in markdown code fences and responses with
        leading preamble text before the JSON object.

        Raises:
            ValueError: If no valid JSON object can be found or parsed.
        """
        code_match = _CODE_BLOCK_RE.search(response_text)
        if code_match:
            candidate = code_match.group(1).strip()
        else:
            obj_match = _JSON_OBJ_RE.search(response_text)
            if obj_match:
                candidate = obj_match.group(0).strip()
            else:
                candidate = response_text.strip()

        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Failed to parse JSON from LLM response: {exc}\n"
                f"Attempted to parse: {candidate[:200]!r}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"Expected a JSON object at the top level, got {type(data).__name__}"
            )
        return data

    def parse_llm_response(self, response_text: str) -> list[dict[str, Any]]:
        """Extract the rules array from a raw LLM response string.

        Args:
            response_text: Raw text from the LLM, possibly with code fences or preamble.

        Returns:
            List of rule dicts from the 'rules' key.

        Raises:
            ValueError: If JSON cannot be extracted or 'rules' key is missing.
        """
        data = self._extract_json_obj(response_text)
        if "rules" not in data:
            raise ValueError(
                f"LLM response JSON is missing the 'rules' key. "
                f"Keys present: {list(data.keys())}"
            )
        rules = data["rules"]
        if not isinstance(rules, list):
            raise ValueError(
                f"Expected 'rules' to be a list, got {type(rules).__name__}"
            )
        return rules

    def dict_to_sigma_rule(self, rule_dict: dict[str, Any]) -> SigmaRule:
        """Convert a parsed rule dict into a SigmaRule model.

        Handles missing optional fields with sensible defaults.
        Generates MITRE-based tags if tags list is empty.

        Args:
            rule_dict: Dictionary parsed from LLM JSON response.

        Returns:
            Populated SigmaRule instance.

        Raises:
            ValueError: If required fields are missing or unparseable.
        """
        detection_raw = rule_dict.get("detection", {})
        detection = SigmaDetection(
            keywords=detection_raw.get("keywords") or [],
            field_mappings=detection_raw.get("field_mappings") or {},
            condition=detection_raw.get("condition", "selection"),
            timeframe=detection_raw.get("timeframe"),
        )

        logsource_raw = rule_dict.get("logsource", {})
        logsource = SigmaLogsource(
            category=logsource_raw.get("category"),
            product=logsource_raw.get("product"),
            service=logsource_raw.get("service"),
        )

        mitre_raw = rule_dict.get("mitre_attack") or []
        mitre_attacks: list[MitreAttack] = []
        for m in mitre_raw:
            if not isinstance(m, dict):
                continue
            mitre_attacks.append(
                MitreAttack(
                    technique_id=str(m.get("technique_id", "")),
                    technique_name=str(m.get("technique_name", "")),
                    tactic=str(m.get("tactic", "")).lower(),
                    sub_technique=m.get("sub_technique"),
                )
            )

        tags: list[str] = list(rule_dict.get("tags") or [])
        if not tags and mitre_attacks:
            tags = self._build_mitre_tags(mitre_attacks)

        title = str(rule_dict.get("title", "Untitled Detection Rule"))
        name = str(rule_dict.get("name", "")).strip()
        if not name:
            import re as _re
            name = _re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "unnamed-rule"

        confidence_raw = rule_dict.get("confidence_score", 0.5)
        try:
            confidence = float(confidence_raw)
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.5

        from sigma_generator.models.sigma import SigmaLevel, SigmaStatus

        status_raw = rule_dict.get("status", "experimental")
        try:
            status = SigmaStatus(status_raw)
        except ValueError:
            status = SigmaStatus.experimental

        level_raw = rule_dict.get("level", "medium")
        try:
            level = SigmaLevel(level_raw)
        except ValueError:
            level = SigmaLevel.medium

        return SigmaRule(
            title=title[:100],
            name=name,
            description=str(rule_dict.get("description", "")),
            status=status,
            level=level,
            logsource=logsource,
            detection=detection,
            tags=tags,
            falsepositives=list(rule_dict.get("falsepositives") or []),
            references=list(rule_dict.get("references") or []),
            mitre_attack=mitre_attacks,
            confidence_score=confidence,
            confidence_rationale=str(rule_dict.get("confidence_rationale", "")),
            source_type=str(rule_dict.get("source_type", "")),
            source_summary=str(rule_dict.get("source_summary", "")),
        )

    def _build_mitre_tags(self, mitre_attacks: list[MitreAttack]) -> list[str]:
        """Generate SIGMA-format tags from MitreAttack objects.

        Produces tags like 'attack.execution' and 'attack.t1059.001'.
        """
        tags: list[str] = []
        seen: set[str] = set()

        for m in mitre_attacks:
            tactic_slug = _TACTIC_SLUG_MAP.get(m.tactic.lower().strip(), m.tactic.lower())
            tactic_tag = f"attack.{tactic_slug}"
            if tactic_tag not in seen:
                tags.append(tactic_tag)
                seen.add(tactic_tag)

            tech_id = m.technique_id.upper().replace(" ", "")
            if tech_id.startswith("T"):
                tech_tag = f"attack.{tech_id.lower()}"
            else:
                tech_tag = f"attack.t{tech_id.lower()}"

            if tech_tag not in seen:
                tags.append(tech_tag)
                seen.add(tech_tag)

        return tags

    def parse_response(self, response_text: str) -> tuple[list[SigmaRule], str]:
        """Full parsing pipeline from raw LLM text to SigmaRule list.

        Extracts JSON, converts each rule dict to a SigmaRule, and returns
        both the rules and the analysis_summary. Never raises — logs warnings
        for individual failures and returns an empty list on complete failure.

        Returns:
            Tuple of (list_of_successfully_parsed_rules, analysis_summary_string).
        """
        try:
            data = self._extract_json_obj(response_text)
        except ValueError as exc:
            logger.error("Failed to extract JSON from LLM response", error=str(exc))
            return [], ""

        rules_data = data.get("rules", [])
        analysis_summary = str(data.get("analysis_summary", ""))

        if not isinstance(rules_data, list):
            logger.warning(
                "LLM response 'rules' is not a list",
                rules_type=type(rules_data).__name__,
            )
            return [], analysis_summary

        rules: list[SigmaRule] = []
        for i, rule_dict in enumerate(rules_data):
            if not isinstance(rule_dict, dict):
                logger.warning("Skipping non-dict rule entry", index=i, entry=str(rule_dict)[:100])
                continue
            try:
                rule = self.dict_to_sigma_rule(rule_dict)
                rules.append(rule)
                logger.debug("Parsed rule", title=rule.title, index=i)
            except Exception as exc:
                logger.warning(
                    "Failed to parse individual rule",
                    index=i,
                    title=rule_dict.get("title", "<unknown>"),
                    error=str(exc),
                )

        return rules, analysis_summary
