"""Tests for config merging, dotted-path overrides, and layered config loading."""
from __future__ import annotations

import pytest

from ioc_enricher.utils.config import (
    AppConfig,
    _apply_dict,
    _set_nested,
    load_config,
)

_ENV_VARS = [
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "SHODAN_API_KEY",
    "OTX_API_KEY",
    "URLSCAN_API_KEY",
    "MISP_API_KEY",
    "MISP_URL",
    "LOG_LEVEL",
    "PIPELINE_CONCURRENCY",
]


@pytest.fixture(autouse=True)
def _clear_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the real shell environment can't leak into config-loading tests."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


class TestApplyDict:
    def test_sets_known_scalar_field(self) -> None:
        config = AppConfig()
        _apply_dict(config.pipeline, {"concurrency": 50})
        assert config.pipeline.concurrency == 50

    def test_ignores_unknown_keys(self) -> None:
        config = AppConfig()
        _apply_dict(config.pipeline, {"not_a_real_field": "x"})
        assert not hasattr(config.pipeline, "not_a_real_field")

    def test_recurses_into_nested_dataclass(self) -> None:
        config = AppConfig()
        _apply_dict(config, {"providers": {"virustotal": {"api_key": "abc123"}}})
        assert config.providers.virustotal.api_key == "abc123"

    def test_falls_back_to_raw_value_when_coercion_fails(self) -> None:
        config = AppConfig()
        _apply_dict(config.pipeline, {"concurrency": "not-an-int"})
        assert config.pipeline.concurrency == "not-an-int"

    def test_preserves_none_without_coercion(self) -> None:
        config = AppConfig()
        _apply_dict(config.misp, {"url": None})
        assert config.misp.url is None


class TestSetNested:
    def test_sets_bool_field(self) -> None:
        config = AppConfig()
        _set_nested(config, "misp.verify_ssl", "false")
        assert config.misp.verify_ssl is False

    def test_sets_int_field(self) -> None:
        config = AppConfig()
        _set_nested(config, "pipeline.concurrency", "42")
        assert config.pipeline.concurrency == 42

    def test_sets_float_field(self) -> None:
        config = AppConfig()
        _set_nested(config, "providers.virustotal.rate_limit_rps", "2.5")
        assert config.providers.virustotal.rate_limit_rps == 2.5

    def test_sets_list_field(self) -> None:
        config = AppConfig()
        _set_nested(config, "providers.virustotal.supported_types", "ipv4, domain")
        assert config.providers.virustotal.supported_types == ["ipv4", "domain"]

    def test_sets_string_field(self) -> None:
        config = AppConfig()
        _set_nested(config, "providers.virustotal.api_key", "secret")
        assert config.providers.virustotal.api_key == "secret"

    def test_silently_ignores_unknown_top_level_path(self) -> None:
        config = AppConfig()
        _set_nested(config, "nonexistent.field", "x")
        assert not hasattr(config, "nonexistent")

    def test_silently_ignores_unknown_leaf_attribute(self) -> None:
        config = AppConfig()
        _set_nested(config, "pipeline.nonexistent", "x")
        assert not hasattr(config.pipeline, "nonexistent")

    def test_falls_back_to_raw_string_on_coercion_error(self) -> None:
        config = AppConfig()
        _set_nested(config, "pipeline.concurrency", "not-a-number")
        assert config.pipeline.concurrency == "not-a-number"


class TestLoadConfig:
    def test_returns_defaults_when_no_files_present(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert isinstance(config, AppConfig)
        assert config.pipeline.concurrency == 20

    def test_loads_explicit_yaml_path(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text("pipeline:\n  concurrency: 99\n")
        config = load_config(config_path=yaml_file)
        assert config.pipeline.concurrency == 99

    def test_loads_default_config_yaml_from_cwd(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.yaml").write_text("pipeline:\n  min_risk_score: 30\n")
        config = load_config()
        assert config.pipeline.min_risk_score == 30

    def test_loads_secrets_pem_without_overriding_shell_env(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("VT_API_KEY", "shell-key")
        (tmp_path / "secrets.pem").write_text("VT_API_KEY=file-key\nOTX_API_KEY=file-otx-key\n")
        config = load_config()
        assert config.providers.virustotal.api_key == "shell-key"
        assert config.providers.otx.api_key == "file-otx-key"

    def test_env_vars_override_yaml(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.yaml").write_text("pipeline:\n  concurrency: 5\n")
        monkeypatch.setenv("PIPELINE_CONCURRENCY", "77")
        config = load_config()
        assert config.pipeline.concurrency == 77
