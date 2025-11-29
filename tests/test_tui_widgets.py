"""
Tests for TUI widgets.
"""

import pytest
from textual.widgets import Label

from cyberpot.tui.widgets.event_feed import EventFeed, EventListItem
from cyberpot.tui.widgets.alert_panel import AlertPanel, AlertListItem
from cyberpot.tui.widgets.statistics import StatsOverview, TopIPsWidget
from cyberpot.core.models import Alert, Severity, Statistics
from datetime import datetime


class TestEventFeed:
    """Test EventFeed widget."""

    def test_add_event(self, sample_login_event):
        """Test adding event to feed."""
        feed = EventFeed(max_events=10)
        feed.add_event(sample_login_event)

        assert feed.get_event_count() == 1

    def test_max_events_limit(self, sample_login_event):
        """Test that feed respects max events limit."""
        feed = EventFeed(max_events=5)

        # Add more events than max
        for _ in range(10):
            feed.add_event(sample_login_event)

        assert feed.get_event_count() == 5

    def test_clear_events(self, sample_login_event):
        """Test clearing events from feed."""
        feed = EventFeed(max_events=10)
        feed.add_event(sample_login_event)
        feed.clear_events()

        assert feed.get_event_count() == 0

    def test_toggle_auto_scroll(self):
        """Test toggling auto-scroll."""
        feed = EventFeed()
        assert feed.auto_scroll is True

        feed.toggle_auto_scroll()
        assert feed.auto_scroll is False


class TestEventListItem:
    """Test EventListItem formatting."""

    def test_format_login_event(self, sample_login_event):
        """Test formatting login event."""
        item = EventListItem(sample_login_event)
        text = item._format_event()

        assert str(text) is not None
        assert "root" in str(text)

    def test_format_command_event(self, sample_command_event):
        """Test formatting command event."""
        item = EventListItem(sample_command_event)
        text = item._format_event()

        assert str(text) is not None
        assert "wget" in str(text)


class TestAlertPanel:
    """Test AlertPanel widget."""

    def test_add_alert(self):
        """Test adding alert to panel."""
        panel = AlertPanel(max_alerts=10)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="Test Alert",
            description="Test",
        )

        panel.add_alert(alert)
        assert panel.get_alert_count() == 1

    def test_clear_alerts(self):
        """Test clearing alerts."""
        panel = AlertPanel(max_alerts=10)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
        )

        panel.add_alert(alert)
        panel.clear_alerts()

        assert panel.get_alert_count() == 0


class TestStatsOverview:
    """Test StatsOverview widget."""

    def test_update_stats(self):
        """Test updating statistics."""
        widget = StatsOverview()
        stats = Statistics(
            timestamp=datetime.now(),
            total_events=100,
            total_sessions=10,
            active_sessions=5,
            total_alerts=2,
        )

        widget.stats = stats
        # Widget should update via reactive
        assert widget.stats == stats
