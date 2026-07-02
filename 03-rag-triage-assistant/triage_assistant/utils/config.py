"""Configuration management with YAML file and environment variable overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


@dataclass
class VectorStoreConfig:
    """ChromaDB vector store configuration."""

    persist_directory: str = "./data/chroma"
    embedding_model: str = "all-MiniLM-L6-v2"
    n_results_per_collection: int = 5


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    api_key: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 2048
    temperature: float = 0.0


@dataclass
class APIConfig:
    """FastAPI server configuration."""

    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class TriageConfig:
    """Triage behavior configuration."""

    default_verdict_on_error: str = "needs_investigation"
    min_context_documents: int = 1
    log_level: str = "INFO"


@dataclass
class AppConfig:
    """Root application configuration."""

    vector_store: VectorStoreConfig = field(default_factory=VectorStoreConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    api: APIConfig = field(default_factory=APIConfig)
    triage: TriageConfig = field(default_factory=TriageConfig)


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
      2. ``TRIAGE_CONFIG`` environment variable
      3. ``./config/config.yaml`` relative to the working directory
      4. Pure defaults if no file is found

    Environment variable overrides (always take priority):
      - ``ANTHROPIC_API_KEY``  → llm.api_key
      - ``TRIAGE_CHROMA_DIR``  → vector_store.persist_directory
      - ``TRIAGE_PORT``        → api.port
      - ``LOG_LEVEL``          → triage.log_level

    Args:
        config_path: Explicit path to a YAML config file.

    Returns:
        Populated AppConfig dataclass.
    """
    raw: dict[str, Any] = {}

    paths_to_try: list[Path] = []
    if config_path:
        paths_to_try.append(Path(config_path))
    env_path = os.environ.get("TRIAGE_CONFIG")
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

    dotenv_candidates: list[Path] = []
    if loaded_config_dir:
        dotenv_candidates.append(loaded_config_dir.parent / ".env")
        dotenv_candidates.append(loaded_config_dir / ".env")
    dotenv_candidates.append(Path(".env"))

    for dotenv_path in dotenv_candidates:
        if dotenv_path.exists():
            load_dotenv(dotenv_path, override=False)
            break

    vs_raw = raw.get("vector_store", {})
    llm_raw = raw.get("llm", {})
    api_raw = raw.get("api", {})
    triage_raw = raw.get("triage", {})

    vector_store = VectorStoreConfig(
        persist_directory=vs_raw.get("persist_directory", "./data/chroma"),
        embedding_model=vs_raw.get("embedding_model", "all-MiniLM-L6-v2"),
        n_results_per_collection=int(vs_raw.get("n_results_per_collection", 5)),
    )
    llm = LLMConfig(
        api_key=llm_raw.get("api_key", ""),
        model=llm_raw.get("model", "claude-sonnet-4-20250514"),
        max_tokens=int(llm_raw.get("max_tokens", 2048)),
        temperature=float(llm_raw.get("temperature", 0.0)),
    )
    api = APIConfig(
        host=api_raw.get("host", "0.0.0.0"),
        port=int(api_raw.get("port", 8000)),
        cors_origins=list(api_raw.get("cors_origins", ["*"])),
    )
    triage = TriageConfig(
        default_verdict_on_error=triage_raw.get("default_verdict_on_error", "needs_investigation"),
        min_context_documents=int(triage_raw.get("min_context_documents", 1)),
        log_level=triage_raw.get("log_level", "INFO"),
    )

    # Environment variable overrides
    llm.api_key = os.environ.get("ANTHROPIC_API_KEY", llm.api_key)
    vector_store.persist_directory = os.environ.get(
        "TRIAGE_CHROMA_DIR", vector_store.persist_directory
    )
    api.port = int(os.environ.get("TRIAGE_PORT", str(api.port)))
    triage.log_level = os.environ.get("LOG_LEVEL", triage.log_level)

    return AppConfig(vector_store=vector_store, llm=llm, api=api, triage=triage)
