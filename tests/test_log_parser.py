"""
Tests for Cowrie log parser.
"""

import json
from datetime import datetime

import pytest

from cyberpot.core.log_parser import CowrieLogParser
from cyberpot.core.models import CommandEvent, EventType, LoginEvent


class TestCowrieLogParser:
    """Test CowrieLogParser functionality."""

    def test_parse_login_failed_event(self, sample_cowrie_login_json):
        """Test parsing login failed event."""
        parser = CowrieLogParser()
        event = parser.parse_line(sample_cowrie_login_json)

        assert event is not None
        assert isinstance(event, LoginEvent)
        assert event.event_type == EventType.LOGIN_FAILED
        assert event.username == "root"
        assert event.password == "admin"
        assert event.success is False
        assert str(event.src_ip) == "192.168.1.100"
        assert event.src_port == 12345

    def test_parse_login_success_event(self):
        """Test parsing login success event."""
        parser = CowrieLogParser()
        json_line = json.dumps({
            "eventid": "cowrie.login.success",
            "timestamp": "2025-01-15T12:00:00.000000Z",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "session": "session_456",
            "username": "admin",
            "password": "password123",
        })

        event = parser.parse_line(json_line)

        assert event is not None
        assert isinstance(event, LoginEvent)
        assert event.event_type == EventType.LOGIN_SUCCESS
        assert event.success is True

    def test_parse_command_event(self, sample_cowrie_command_json):
        """Test parsing command event."""
        parser = CowrieLogParser()
        event = parser.parse_line(sample_cowrie_command_json)

        assert event is not None
        assert isinstance(event, CommandEvent)
        assert event.event_type == EventType.COMMAND_EXECUTION
        assert event.command == "ls -la"

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        parser = CowrieLogParser()
        event = parser.parse_line("invalid json {")

        assert event is None
        assert parser.error_count == 1

    def test_parse_missing_eventid(self):
        """Test parsing JSON without eventid."""
        parser = CowrieLogParser()
        json_line = json.dumps({
            "timestamp": "2025-01-15T12:00:00.000000Z",
            "src_ip": "192.168.1.100",
        })

        event = parser.parse_line(json_line)
        assert event is None

    def test_parse_unsupported_event_type(self):
        """Test parsing unsupported event type."""
        parser = CowrieLogParser()
        json_line = json.dumps({
            "eventid": "cowrie.unknown.event",
            "timestamp": "2025-01-15T12:00:00.000000Z",
            "src_ip": "192.168.1.100",
            "src_port": 12345,
            "session": "test",
        })

        event = parser.parse_line(json_line)
        assert event is None

    def test_parse_batch(self, sample_cowrie_login_json, sample_cowrie_command_json):
        """Test parsing batch of log lines."""
        parser = CowrieLogParser()
        lines = [sample_cowrie_login_json, sample_cowrie_command_json, "invalid"]

        events = parser.parse_batch(lines)

        assert len(events) == 2
        assert isinstance(events[0], LoginEvent)
        assert isinstance(events[1], CommandEvent)

    def test_parser_stats(self):
        """Test parser statistics."""
        parser = CowrieLogParser()

        # Parse some valid and invalid events
        parser.parse_line(json.dumps({
            "eventid": "cowrie.login.failed",
            "timestamp": "2025-01-15T12:00:00.000000Z",
            "src_ip": "192.168.1.100",
            "src_port": 12345,
            "session": "test",
            "username": "root",
        }))
        parser.parse_line("invalid")

        stats = parser.get_stats()
        assert stats["parsed_count"] == 1
        assert stats["error_count"] == 1
        assert stats["success_rate"] == 0.5
