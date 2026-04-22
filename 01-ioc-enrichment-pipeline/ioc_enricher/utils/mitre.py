"""MITRE ATT&CK technique mapping for enriched IOCs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ioc_enricher.models.ioc import EnrichedIOC, MitreMapping


@dataclass(frozen=True)
class TechniqueRule:
    """A MITRE ATT&CK rule that maps tag signals to a technique."""

    technique_id: str
    technique_name: str
    tactic: str
    base_confidence: float
    triggers: frozenset[str]


_RULES: tuple[TechniqueRule, ...] = (
    TechniqueRule(
        "T1071.001",
        "Application Layer Protocol: Web Protocols",
        "Command and Control",
        0.7,
        frozenset({"c2", "cobalt_strike", "beacon", "http_c2", "https_c2", "url", "urlscan:malicious"}),
    ),
    TechniqueRule(
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
        0.65,
        frozenset({"dns_tunneling", "dga", "fast_flux", "domain_generation_algorithm"}),
    ),
    TechniqueRule(
        "T1090",
        "Proxy",
        "Command and Control",
        0.75,
        frozenset({"proxy", "vpn", "tor_exit_node", "abuseipdb:open_proxy", "open_proxy"}),
    ),
    TechniqueRule(
        "T1219",
        "Remote Access Software",
        "Command and Control",
        0.7,
        frozenset({"rat", "remote_access", "remote_access_trojan"}),
    ),
    TechniqueRule(
        "T1566.001",
        "Phishing: Spearphishing Attachment",
        "Initial Access",
        0.75,
        frozenset({"phishing", "abuseipdb:phishing", "spearphishing"}),
    ),
    TechniqueRule(
        "T1566.002",
        "Phishing: Spearphishing Link",
        "Initial Access",
        0.7,
        frozenset({"phishing_url", "malicious_url", "urlscan:malicious"}),
    ),
    TechniqueRule(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        0.65,
        frozenset({"exploit", "web_attack", "abuseipdb:web_app_attack", "shodan:has_vulns"}),
    ),
    TechniqueRule(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        0.6,
        frozenset({"dropper", "downloader", "malware", "trojan", "vt:malicious"}),
    ),
    TechniqueRule(
        "T1027",
        "Obfuscated Files or Information",
        "Defense Evasion",
        0.6,
        frozenset({"obfuscated", "packed", "encrypted_payload", "packer"}),
    ),
    TechniqueRule(
        "T1110",
        "Brute Force",
        "Credential Access",
        0.8,
        frozenset({"brute_force", "abuseipdb:brute-force", "abuseipdb:ssh", "ssh_brute_force", "rdp_brute_force"}),
    ),
    TechniqueRule(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        0.75,
        frozenset({"scanner", "port_scan", "abuseipdb:port_scan", "masscan", "nmap"}),
    ),
    TechniqueRule(
        "T1498",
        "Network Denial of Service",
        "Impact",
        0.8,
        frozenset({"ddos", "abuseipdb:ddos_attack", "dos", "flood"}),
    ),
    TechniqueRule(
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        0.55,
        frozenset({"exfil", "data_theft", "infostealer", "stealer"}),
    ),
    TechniqueRule(
        "T1078",
        "Valid Accounts",
        "Persistence",
        0.5,
        frozenset({"credential_abuse", "compromised_account", "account_takeover"}),
    ),
    TechniqueRule(
        "T1583.001",
        "Acquire Infrastructure: Domains",
        "Resource Development",
        0.6,
        frozenset({"newly_registered_domain", "nrd", "typosquat", "lookalike_domain"}),
    ),
    TechniqueRule(
        "T1588.002",
        "Obtain Capabilities: Tool",
        "Resource Development",
        0.55,
        frozenset({"hack_tool", "exploit_kit", "rat", "loader"}),
    ),
)


class MitreMapper:
    """Maps enriched IOC tags and type signals to MITRE ATT&CK techniques."""

    def map(self, enriched_ioc: EnrichedIOC) -> list[MitreMapping]:
        """Return up to 5 MITRE technique mappings sorted by confidence descending.

        Confidence is boosted by +0.05 per additional matching trigger beyond the
        first, capped at a maximum boost of 0.2.
        """
        from ioc_enricher.models.ioc import MitreMapping as MitreMappingModel

        signals: set[str] = {tag.lower() for tag in enriched_ioc.all_tags}
        signals.add(enriched_ioc.ioc.ioc_type.value)

        seen: dict[str, MitreMappingModel] = {}
        for rule in _RULES:
            matched = rule.triggers & signals
            if not matched:
                continue
            boost = min(0.2, (len(matched) - 1) * 0.05)
            confidence = min(1.0, rule.base_confidence + boost)
            if rule.technique_id not in seen or confidence > seen[rule.technique_id].confidence:
                seen[rule.technique_id] = MitreMappingModel(
                    technique_id=rule.technique_id,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    confidence=confidence,
                )

        return sorted(seen.values(), key=lambda m: m.confidence, reverse=True)[:5]
