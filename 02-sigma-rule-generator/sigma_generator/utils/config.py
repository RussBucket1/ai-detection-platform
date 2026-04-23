"""Configuration management with YAML file and environment variable overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 4096
    temperature: float = 0.0


@dataclass
class OutputConfig:
    """Output file configuration."""

    output_dir: str = "./output"
    formats: list[str] = field(default_factory=lambda: ["yaml", "json"])
    pretty_json: bool = True


@dataclass
class GeneratorConfig:
    """SIGMA rule generator behavior configuration."""

    default_author: str = "AI Detection Platform"
    default_status: str = "experimental"
    min_confidence_threshold: float = 0.0
    validate_output: bool = True
    log_level: str = "INFO"


@dataclass
class AppConfig:
    """Root application configuration."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override dict into base dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load AppConfig from an optional YAML file, then apply environment variable overrides.

    Search order for the config file:
      1. ``config_path`` argument (if provided)
      2. ``SIGMA_CONFIG`` environment variable
      3. ``./config/config.yaml`` relative to the working directory
      4. Pure defaults if no file is found

    Environment variable overrides (always take priority):
      - ``ANTHROPIC_API_KEY``  → llm.api_key
      - ``SIGMA_MODEL``        → llm.model
      - ``SIGMA_OUTPUT_DIR``   → output.output_dir
      - ``SIGMA_AUTHOR``       → generator.default_author
      - ``LOG_LEVEL``          → generator.log_level

    Args:
        config_path: Explicit path to a YAML config file.

    Returns:
        Populated AppConfig dataclass.
    """
    raw: dict[str, Any] = {}

    paths_to_try: list[Path] = []
    if config_path:
        paths_to_try.append(Path(config_path))
    env_path = os.environ.get("SIGMA_CONFIG")
    if env_path:
        paths_to_try.append(Path(env_path))
    paths_to_try.append(Path("config/config.yaml"))

    loaded_config_dir: Path | None = None
    for path in paths_to_try:
        if path.exists():
            with open(path) as fh:
                loaded = yaml.safe_load(fh) or {}
            raw = _deep_merge(raw, loaded)
            loaded_config_dir = path.parent
            break

    # Load .env from the project root (parent of config/) or current directory.
    # override=False means variables already set in the shell always win.
    dotenv_candidates: list[Path] = []
    if loaded_config_dir:
        dotenv_candidates.append(loaded_config_dir.parent / ".env")
        dotenv_candidates.append(loaded_config_dir / ".env")
    dotenv_candidates.append(Path(".env"))

    for dotenv_path in dotenv_candidates:
        if dotenv_path.exists():
            load_dotenv(dotenv_path, override=False)
            break

    llm_raw = raw.get("llm", {})
    output_raw = raw.get("output", {})
    generator_raw = raw.get("generator", {})

    llm = LLMConfig(
        api_key=llm_raw.get("api_key", ""),
        model=llm_raw.get("model", "claude-sonnet-4-6"),
        max_tokens=int(llm_raw.get("max_tokens", 4096)),
        temperature=float(llm_raw.get("temperature", 0.0)),
    )
    output = OutputConfig(
        output_dir=output_raw.get("output_dir", "./output"),
        formats=list(output_raw.get("formats", ["yaml", "json"])),
        pretty_json=bool(output_raw.get("pretty_json", True)),
    )
    generator = GeneratorConfig(
        default_author=generator_raw.get("default_author", "AI Detection Platform"),
        default_status=generator_raw.get("default_status", "experimental"),
        min_confidence_threshold=float(generator_raw.get("min_confidence_threshold", 0.0)),
        validate_output=bool(generator_raw.get("validate_output", True)),
        log_level=generator_raw.get("log_level", "INFO"),
    )

    # Environment variable overrides
    llm.api_key = os.environ.get("ANTHROPIC_API_KEY", llm.api_key)
    llm.model = os.environ.get("SIGMA_MODEL", llm.model)
    output.output_dir = os.environ.get("SIGMA_OUTPUT_DIR", output.output_dir)
    generator.default_author = os.environ.get("SIGMA_AUTHOR", generator.default_author)
    generator.log_level = os.environ.get("LOG_LEVEL", generator.log_level)

    return AppConfig(llm=llm, output=output, generator=generator)
