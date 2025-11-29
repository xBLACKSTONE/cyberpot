"""
Tests for configuration management.
"""

import pytest

from cyberpot.config import load_config, CyberPotConfig


class TestConfigLoading:
    """Test configuration loading."""

    def test_load_valid_config(self, sample_config_yaml):
        """Test loading valid configuration file."""
        config = load_config(sample_config_yaml)

        assert isinstance(config, CyberPotConfig)
        assert config.storage.max_events == 1000
        assert config.storage.max_sessions == 100
        assert config.tui.enabled is True
        assert config.irc.enabled is False

    def test_load_nonexistent_config(self, tmp_path):
        """Test loading non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_config_defaults(self, sample_config_yaml):
        """Test that configuration has proper defaults."""
        config = load_config(sample_config_yaml)

        assert config.core.batch_size == 100
        assert config.core.watch_interval == 0.1
        assert config.enrichment.threat_intel.cache_ttl == 3600

    def test_config_path_resolution(self, tmp_path):
        """Test that relative paths are resolved correctly."""
        config_file = tmp_path / "config.yaml"
        config_content = f"""
cowrie:
  deployment: docker
  log_file: logs/cowrie.json

storage:
  max_events: 100
"""
        config_file.write_text(config_content)

        config = load_config(config_file)

        # Path should be resolved relative to config file location
        expected_log_path = tmp_path / "logs" / "cowrie.json"
        assert config.cowrie.log_file == expected_log_path
