"""
Tests for alert manager.
"""

import pytest

from cyberpot.core.alert_manager import AlertManager, RuleEvaluator, AlertCorrelator
from cyberpot.core.models import AlertRule, EventType, Severity


class TestAlertCorrelator:
    """Test AlertCorrelator functionality."""

    def test_add_event_and_get_count(self, sample_login_event):
        """Test adding events and getting count."""
        correlator = AlertCorrelator()

        count1 = correlator.add_event("test_rule", sample_login_event, 60)
        assert count1 == 1

        count2 = correlator.add_event("test_rule", sample_login_event, 60)
        assert count2 == 2

    def test_window_expiry(self, sample_login_event):
        """Test that events outside window are not counted."""
        import time
        from datetime import datetime, timedelta

        correlator = AlertCorrelator()

        # Create old event (simulated)
        old_event = sample_login_event.model_copy()
        old_event.timestamp = datetime.now() - timedelta(seconds=120)

        # Add old event
        correlator.add_event("test_rule", old_event, 60)

        # Wait and check (old event should be expired)
        time.sleep(0.1)
        count = correlator.get_count("test_rule", sample_login_event, 60)
        assert count == 0

    def test_get_events(self, sample_login_event):
        """Test retrieving events from window."""
        correlator = AlertCorrelator()

        correlator.add_event("test_rule", sample_login_event, 60)
        correlator.add_event("test_rule", sample_login_event, 60)

        events = correlator.get_events("test_rule", sample_login_event, 60)
        assert len(events) == 2


class TestRuleEvaluator:
    """Test RuleEvaluator functionality."""

    def test_evaluate_event_type_match(self, sample_login_event):
        """Test rule evaluation with event type match."""
        correlator = AlertCorrelator()
        evaluator = RuleEvaluator(correlator)

        rule = AlertRule(
            name="login_failed",
            description="Login failed",
            severity=Severity.LOW,
            event_type=EventType.LOGIN_FAILED,
        )

        alert = evaluator.evaluate(rule, sample_login_event)
        assert alert is not None
        assert alert.severity == Severity.LOW

    def test_evaluate_event_type_no_match(self, sample_login_event):
        """Test rule evaluation with event type mismatch."""
        correlator = AlertCorrelator()
        evaluator = RuleEvaluator(correlator)

        rule = AlertRule(
            name="command_rule",
            description="Command rule",
            severity=Severity.MEDIUM,
            event_type=EventType.COMMAND_EXECUTION,
        )

        alert = evaluator.evaluate(rule, sample_login_event)
        assert alert is None

    def test_evaluate_count_based_rule(self, sample_login_event):
        """Test count-based rule evaluation."""
        correlator = AlertCorrelator()
        evaluator = RuleEvaluator(correlator)

        rule = AlertRule(
            name="brute_force",
            description="Brute force detected",
            severity=Severity.HIGH,
            event_type=EventType.LOGIN_FAILED,
            count=3,
            time_window=60,
        )

        # First two events should not trigger
        alert1 = evaluator.evaluate(rule, sample_login_event)
        assert alert1 is None

        alert2 = evaluator.evaluate(rule, sample_login_event)
        assert alert2 is None

        # Third event should trigger
        alert3 = evaluator.evaluate(rule, sample_login_event)
        assert alert3 is not None
        assert alert3.severity == Severity.HIGH
        assert len(alert3.event_ids) == 3

    def test_evaluate_command_pattern_rule(self, sample_command_event):
        """Test command pattern rule evaluation."""
        correlator = AlertCorrelator()
        evaluator = RuleEvaluator(correlator)

        rule = AlertRule(
            name="wget_detected",
            description="Wget command detected",
            severity=Severity.MEDIUM,
            event_type=EventType.COMMAND_EXECUTION,
            command_pattern=r"wget",
        )

        alert = evaluator.evaluate(rule, sample_command_event)
        assert alert is not None

    def test_evaluate_disabled_rule(self, sample_login_event):
        """Test that disabled rules don't trigger."""
        correlator = AlertCorrelator()
        evaluator = RuleEvaluator(correlator)

        rule = AlertRule(
            name="disabled_rule",
            description="Disabled",
            severity=Severity.LOW,
            enabled=False,
        )

        alert = evaluator.evaluate(rule, sample_login_event)
        assert alert is None


class TestAlertManager:
    """Test AlertManager functionality."""

    @pytest.mark.asyncio
    async def test_evaluate_no_rules(self, sample_login_event):
        """Test evaluation with no rules."""
        manager = AlertManager()
        await manager.evaluate(sample_login_event)

        assert manager.alerts_generated == 0

    @pytest.mark.asyncio
    async def test_evaluate_matching_rule(self, sample_login_event):
        """Test evaluation with matching rule."""
        rule = AlertRule(
            name="test_rule",
            description="Test rule",
            severity=Severity.MEDIUM,
            event_type=EventType.LOGIN_FAILED,
        )

        manager = AlertManager(rules=[rule])
        alerts_received = []

        async def alert_callback(alert):
            alerts_received.append(alert)

        manager.subscribe_alerts(alert_callback)
        await manager.evaluate(sample_login_event)

        assert manager.alerts_generated == 1
        assert len(alerts_received) == 1

    @pytest.mark.asyncio
    async def test_alert_deduplication(self, sample_login_event):
        """Test that duplicate alerts are suppressed."""
        rule = AlertRule(
            name="test_rule",
            description="Test rule",
            severity=Severity.MEDIUM,
            event_type=EventType.LOGIN_FAILED,
        )

        manager = AlertManager(rules=[rule])
        manager._dedup_window = 60  # 1 minute

        alerts_received = []

        async def alert_callback(alert):
            alerts_received.append(alert)

        manager.subscribe_alerts(alert_callback)

        # Evaluate same event twice
        await manager.evaluate(sample_login_event)
        await manager.evaluate(sample_login_event)

        # Should only generate one alert
        assert manager.alerts_generated == 1
        assert len(alerts_received) == 1

    @pytest.mark.asyncio
    async def test_add_rule(self):
        """Test adding rule dynamically."""
        manager = AlertManager()
        assert len(manager.rules) == 0

        rule = AlertRule(
            name="new_rule",
            description="New rule",
            severity=Severity.LOW,
        )

        manager.add_rule(rule)
        assert len(manager.rules) == 1

    @pytest.mark.asyncio
    async def test_remove_rule(self):
        """Test removing rule."""
        rule = AlertRule(
            name="test_rule",
            description="Test",
            severity=Severity.LOW,
        )

        manager = AlertManager(rules=[rule])
        assert len(manager.rules) == 1

        removed = manager.remove_rule("test_rule")
        assert removed is True
        assert len(manager.rules) == 0

    def test_get_stats(self):
        """Test getting alert manager statistics."""
        rule = AlertRule(
            name="test",
            description="Test",
            severity=Severity.LOW,
        )

        manager = AlertManager(rules=[rule])
        stats = manager.get_stats()

        assert stats["rule_count"] == 1
        assert stats["alerts_generated"] == 0
        assert stats["active_rules"] == 1
