"""Jinja2 prompt templates for different threat intelligence input types."""
from __future__ import annotations

import re

from jinja2 import Environment, StrictUndefined

_JINJA_ENV = Environment(undefined=StrictUndefined, autoescape=False)

_IOC_PATTERN = re.compile(
    r"(?:"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"           # IPv4
    r"|[0-9a-fA-F]{32,64}\b"                  # MD5/SHA1/SHA256
    r"|\b(?:CVE-\d{4}-\d{4,})\b"              # CVE IDs (for negative match)
    r")"
)
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_LOG_PATTERN = re.compile(
    r"(?:"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"      # ISO/common timestamps
    r"|EventID[:\s]+\d+"                       # Windows Event IDs
    r"|event_id[:\s]+\d+"
    r"|\bSysmon\b"
    r"|\bWinEvtLog\b"
    r")"
)

_DOMAIN_HASH_PATTERN = re.compile(
    r"(?:"
    r"[0-9a-fA-F]{32}\b"                      # MD5
    r"|[0-9a-fA-F]{40}\b"                     # SHA1
    r"|[0-9a-fA-F]{64}\b"                     # SHA256
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"           # IPv4
    r"|https?://\S+"                           # URLs
    r"|\b[a-zA-Z0-9-]{3,63}\.[a-zA-Z]{2,6}\b" # Domains
    r")"
)


class PromptTemplate:
    """Jinja2-backed prompt templates for each threat intelligence input type."""

    THREAT_REPORT: str = """\
You are analyzing a **threat intelligence report** from a security research team or SOC.

## Input: Threat Intelligence Report

{{ content }}

---

## Instructions

1. Identify all **detectable behaviors** described in this report — focus on what would \
appear in logs (process names, command line arguments, network connections, file paths, \
registry keys, named pipes, etc.)

2. Generate {{ rule_count }} SIGMA detection rule(s) covering the most impactful and \
detectable behaviors. Prioritize rules that would catch the attacker at key stages \
of the kill chain.

3. For each rule:
   - Choose the correct SIGMA logsource based on the behavior (do not guess fields \
that don't exist in that logsource)
   - Use specific field-based detection where possible (CommandLine, Image, ParentImage, \
TargetObject, DestinationIp, etc.)
   - Write realistic false positives for enterprise environments
   - Map accurately to MITRE ATT&CK

4. Focus on **what is detectable**, not just what is malicious. A behavior that leaves \
no log trace cannot be detected by SIGMA.

5. Return ONLY the JSON object specified in your system instructions — no other text.
"""

    CVE: str = """\
You are analyzing a **CVE description or vulnerability report**.

## Input: CVE / Vulnerability Report

{{ content }}

---

## Instructions

1. Identify the **exploitation behavior** this CVE would produce in logs — what \
processes spawn, what files are written, what network connections occur, what registry \
keys are modified during exploitation or post-exploitation.

2. Generate 1-2 SIGMA detection rules:
   - **Exploitation rule**: Detect the initial exploitation attempt or its immediate \
observable effects in logs
   - **Post-exploitation rule** (if applicable): Detect persistence, C2 communication, \
or lateral movement enabled by this vulnerability

3. Do not write rules for the vulnerability itself (e.g., detecting malformed HTTP \
requests) unless that is genuinely detectable via a SIGMA logsource. Focus on \
host-based or network log evidence.

4. If exploitation evidence is not reliably observable in standard logs, say so in \
the confidence_rationale and generate what detection IS possible.

5. Return ONLY the JSON object specified in your system instructions — no other text.
"""

    IOC_LIST: str = """\
You are analyzing a **list of Indicators of Compromise (IOCs)**.

## Input: IOC List

{{ content }}

---

## Instructions

1. Analyze the IOC types present (IPs, domains, file hashes, URLs, email addresses).

2. Generate 1-2 SIGMA detection rules that would catch activity involving these IOCs:
   - **Network-based rule**: Detect connections to malicious IPs/domains (use \
dns_query logsource for domain lookups, network_connection for IP connections)
   - **File/process rule**: If hashes are present, detect execution of known-bad \
binaries via process_creation with Hashes field

3. Important constraints:
   - Do NOT use long lists of 50+ IOCs in a single rule — choose the most impactful ones
   - Prefer behavioral detection over pure IOC matching where possible
   - For domains/IPs, use |contains or |endswith modifiers appropriately

4. If the IOC list has no context about the threat, note this in confidence_rationale \
and set confidence_score accordingly.

5. Return ONLY the JSON object specified in your system instructions — no other text.
"""

    LOG_SNIPPET: str = """\
You are analyzing **raw log data** showing potentially malicious activity.

## Input: Log Snippet

{{ content }}

---

## Instructions

1. Parse the log format and identify:
   - What log source this is (Windows Event Log, Sysmon, firewall, proxy, etc.)
   - What event type/ID is shown
   - What fields are available and what values indicate malicious behavior

2. Generate a SIGMA rule that would detect this exact behavior (or the pattern it \
represents) using the CORRECT logsource that matches this log type.

3. Critical: Only use field names that actually exist in this logsource type. \
Derive field names from the log lines themselves — do not invent fields.

4. The detection logic should catch the malicious pattern, not the specific log line \
(make it general enough to catch variants of the same attack).

5. Set confidence based on how clearly malicious this log activity is and how \
precisely the SIGMA rule can target it.

6. Return ONLY the JSON object specified in your system instructions — no other text.
"""

    FREEFORM: str = """\
You are analyzing **threat intelligence input** of unspecified format.

## Input

{{ content }}

---

## Instructions

1. Determine what type of threat intelligence this is and what detectable behaviors \
it describes.

2. Generate 1-3 SIGMA detection rules appropriate for the content:
   - If it describes specific attack behaviors → create behavioral detection rules
   - If it describes tools or malware → detect execution patterns and artifacts
   - If it describes network activity → create network-based detection rules

3. Apply all SIGMA best practices from your system instructions.

4. Set source_type in your response to the most appropriate value: \
threat_report, cve, ioc_list, log_snippet, or freeform.

5. Return ONLY the JSON object specified in your system instructions — no other text.
"""


class PromptBuilder:
    """Builds user prompts by detecting input type and rendering Jinja2 templates."""

    _TEMPLATE_MAP: dict[str, str] = {
        "threat_report": PromptTemplate.THREAT_REPORT,
        "cve": PromptTemplate.CVE,
        "ioc_list": PromptTemplate.IOC_LIST,
        "log_snippet": PromptTemplate.LOG_SNIPPET,
        "freeform": PromptTemplate.FREEFORM,
    }

    def detect_input_type(self, content: str) -> str:
        """Heuristically detect the input type from content patterns.

        Checks for CVE identifiers, IOC patterns (IPs, hashes), log-like content
        (timestamps, event IDs), and falls back to threat_report otherwise.
        """
        sample = content[:2000]

        if _CVE_PATTERN.search(sample):
            return "cve"

        log_match = _LOG_PATTERN.search(sample)
        if log_match:
            return "log_snippet"

        ioc_count = len(_DOMAIN_HASH_PATTERN.findall(sample))
        word_count = len(sample.split())
        if ioc_count >= 3 and ioc_count / max(word_count, 1) > 0.05:
            return "ioc_list"

        return "threat_report"

    def build_prompt(
        self,
        content: str,
        input_type: str | None = None,
    ) -> tuple[str, str]:
        """Render the appropriate Jinja2 template for the given content.

        Args:
            content: Raw threat intelligence text.
            input_type: Override for detected type. One of: threat_report, cve,
                ioc_list, log_snippet, freeform. Auto-detected if None.

        Returns:
            Tuple of (rendered_prompt, detected_or_forced_input_type).
        """
        detected = input_type or self.detect_input_type(content)
        if detected not in self._TEMPLATE_MAP:
            detected = "freeform"

        template_str = self._TEMPLATE_MAP[detected]
        template = _JINJA_ENV.from_string(template_str)

        word_count = len(content.split())
        rule_count = "2-3" if word_count > 300 else "1-2"

        rendered = template.render(content=content, rule_count=rule_count)
        return rendered, detected
