import os
import pytest
from pathlib import Path
from pydantic import ValidationError
from artemis.config.schema import load_config, AppConfig, ConfigError
from artemis.config.paths import Paths
from artemis.config.baseline import clamp_to_baseline

def test_default_config(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    paths = Paths.resolve()
    config, clamps = load_config(paths)
    assert config.logging.level == "INFO"
    assert config.db.read_pool_size == 4

def test_toml_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    paths = Paths.resolve()
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text('[logging]\nlevel = "DEBUG"\n[db]\nread_pool_size = 10\n')
    
    config, clamps = load_config(paths)
    assert config.logging.level == "DEBUG"
    assert config.db.read_pool_size == 10

def test_environment_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARTEMIS_LOGGING__LEVEL", "WARNING")
    paths = Paths.resolve()
    
    config, clamps = load_config(paths)
    assert config.logging.level == "WARNING"

def test_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    paths = Paths.resolve()
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text('[logging]\nlevel = "DEBUG"\n')
    
    # Env should beat TOML
    monkeypatch.setenv("ARTEMIS_LOGGING__LEVEL", "ERROR")
    
    config, clamps = load_config(paths)
    assert config.logging.level == "ERROR"

def test_invalid_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    paths = Paths.resolve()
    monkeypatch.setenv("ARTEMIS_LOGGING__LEVEL", "INVALID_LEVEL")
    
    with pytest.raises(ConfigError):
        load_config(paths)

def test_security_baseline_cannot_be_weakened(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTEMIS_DATA_DIR", str(tmp_path))
    paths = Paths.resolve()
    # Attempt to raise max_file_bytes beyond baseline
    monkeypatch.setenv("ARTEMIS_LOGGING__MAX_FILE_BYTES", "999999999")
    
    config, clamps = load_config(paths)
    # Baseline clamping should reduce it
    assert config.logging.max_file_bytes < 999999999
    assert len(clamps) > 0
    
    # Attempt to override security keys (should be rejected/ignored or cause error depending on schema)
    # The schema forbids setting security keys via config (ConfigError)
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text('[security]\nrequire_auth = false\n')
    
    with pytest.raises(ConfigError):
        load_config(paths)
