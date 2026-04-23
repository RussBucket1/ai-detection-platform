"""Configuration management with YAML and environment variable overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


@dataclass
class ProviderConfig:
    """Configuration for a single enrichment provider."""

    enabled: bool = True
    api_key: str = ""
    base_url: str = ""
    rate_limit_rps: float = 4.0
    supported_types: list[str] = field(default_factory=list)


@dataclass
class AbuseIPDBConfig(ProviderConfig):
    """AbuseIPDB-specific provider config."""

    max_age_days: int = 90


@dataclass
class ProvidersConfig:
    """Container for all provider configurations."""

    virustotal: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        base_url="https://www.virustotal.com/api/v3",
        rate_limit_rps=4.0,
        supported_types=["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
    ))
    abuseipdb: AbuseIPDBConfig = field(default_factory=lambda: AbuseIPDBConfig(
        base_url="https://api.abuseipdb.com/api/v2",
        rate_limit_rps=1.0,
        supported_types=["ipv4", "ipv6"],
        max_age_days=90,
    ))
    shodan: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        base_url="https://api.shodan.io",
        rate_limit_rps=1.0,
        supported_types=["ipv4", "ipv6"],
    ))
    otx: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        base_url="https://otx.alienvault.com/api/v1",
        rate_limit_rps=10.0,
        supported_types=["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
    ))
    urlscan: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        base_url="https://urlscan.io/api/v1",
        rate_limit_rps=5.0,
        supported_types=["url", "domain"],
    ))


@dataclass
class ScoringWeightsConfig:
    """Feature weights for the risk scoring model. Should sum to ~1.0."""

    malicious_engine_ratio: float = 0.35
    abuse_confidence_score: float = 0.25
    community_pulse_count: float = 0.15
    historical_reports: float = 0.10
    open_ports_risk: float = 0.10
    urlscan_verdict: float = 0.05


@dataclass
class RiskBandsConfig:
    """Minimum score thresholds for each risk band."""

    CRITICAL: int = 90
    HIGH: int = 70
    MEDIUM: int = 40
    LOW: int = 20
    INFO: int = 0


@dataclass
class ScoringConfig:
    """Scoring configuration including weights and band thresholds."""

    weights: ScoringWeightsConfig = field(default_factory=ScoringWeightsConfig)
    risk_bands: RiskBandsConfig = field(default_factory=RiskBandsConfig)


@dataclass
class PipelineConfig:
    """Core pipeline operational configuration."""

    concurrency: int = 20
    provider_timeout: int = 30
    max_retries: int = 3
    log_level: str = "INFO"
    output_dir: str = "./output"
    min_risk_score: int = 0
    version: str = "1.0.0"


@dataclass
class MISPConfig:
    """MISP integration configuration."""

    url: str = ""
    api_key: str = ""
    verify_ssl: bool = True
    distribution: int = 0
    enrichment_tag: str = "tlp:white"


@dataclass
class OutputConfig:
    """Output format and serialization configuration."""

    formats: list[str] = field(default_factory=lambda: ["json", "ndjson"])
    include_raw_responses: bool = False
    pretty_json: bool = True
    sort_by: str = "risk_score"
    sort_descending: bool = True


@dataclass
class AppConfig:
    """Top-level application configuration."""

    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    misp: MISPConfig = field(default_factory=MISPConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def _apply_dict(obj: Any, data: dict[str, Any]) -> None:
    """Recursively apply a nested dictionary onto a dataclass instance."""
    for key, value in data.items():
        if not hasattr(obj, key):
            continue
        current = getattr(obj, key)
        if isinstance(value, dict) and hasattr(current, "__dataclass_fields__"):
            _apply_dict(current, value)
        else:
            target_type = type(current)
            if target_type is not type(None) and not isinstance(value, type(None)):
                try:
                    coerced = target_type(value)
                except (TypeError, ValueError):
                    coerced = value
            else:
                coerced = value
            setattr(obj, key, coerced)


def _set_nested(obj: Any, dotted_path: str, value: str) -> None:
    """Set a value on a nested dataclass using a dotted path string."""
    parts = dotted_path.split(".")
    target = obj
    for part in parts[:-1]:
        if not hasattr(target, part):
            return
        target = getattr(target, part)
    attr = parts[-1]
    if not hasattr(target, attr):
        return
    current = getattr(target, attr)
    target_type = type(current)
    try:
        if target_type is bool:
            coerced: Any = value.lower() in ("true", "1", "yes")
        elif target_type is int:
            coerced = int(value)
        elif target_type is float:
            coerced = float(value)
        elif target_type is list:
            coerced = [v.strip() for v in value.split(",")]
        else:
            coerced = value
    except (ValueError, AttributeError):
        coerced = value
    setattr(target, attr, coerced)


_ENV_MAP: dict[str, str] = {
    "VT_API_KEY": "providers.virustotal.api_key",
    "ABUSEIPDB_API_KEY": "providers.abuseipdb.api_key",
    "SHODAN_API_KEY": "providers.shodan.api_key",
    "OTX_API_KEY": "providers.otx.api_key",
    "URLSCAN_API_KEY": "providers.urlscan.api_key",
    "MISP_API_KEY": "misp.api_key",
    "MISP_URL": "misp.url",
    "LOG_LEVEL": "pipeline.log_level",
    "PIPELINE_CONCURRENCY": "pipeline.concurrency",
}


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load config from defaults, YAML file, secrets.pem, then environment variable overrides.

    Search order for YAML: explicit path → ./config/config.yaml → ./config.yaml.
    After loading YAML, secrets.pem is loaded from the same directory as the config file
    (or config/ by default) and its KEY=VALUE pairs are injected into the environment
    without overriding variables already set in the shell.
    Environment variables always take highest priority.
    """
    config = AppConfig()

    search_paths: list[Path] = []
    if config_path:
        search_paths.append(Path(config_path))
    search_paths += [Path("config/config.yaml"), Path("config.yaml")]

    loaded_config_dir: Path | None = None
    for candidate in search_paths:
        if candidate.exists():
            with candidate.open() as fh:
                data = yaml.safe_load(fh) or {}
            _apply_dict(config, data)
            loaded_config_dir = candidate.parent
            break

    # Load secrets.pem from the config directory (non-overriding: shell env vars win).
    secrets_candidates: list[Path] = []
    if loaded_config_dir:
        secrets_candidates.append(loaded_config_dir / "secrets.pem")
    secrets_candidates += [Path("config/secrets.pem"), Path("secrets.pem")]

    for secrets_path in secrets_candidates:
        if secrets_path.exists():
            load_dotenv(secrets_path, override=False)
            break

    for env_var, dotted_path in _ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            _set_nested(config, dotted_path, value)

    return config
