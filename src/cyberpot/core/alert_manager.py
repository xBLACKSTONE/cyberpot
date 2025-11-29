"""
Alert manager with rule-based alerting and correlation.

Evaluates events against alert rules and generates alerts for TUI and IRC distribution.
"""

import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

import structlog

from .models import Alert, AlertRule, CommandEvent, Event, EventType, LoginEvent, Severity

logger = structlog.get_logger(__name__)


class AlertCorrelator:
    """
    Correlates events for time-windowed alert rules.

    Tracks event occurrences within time windows for counting and grouping.
    """

    def __init__(self):
        """Initialize alert correlator."""
        self._event_windows: Dict[str, deque] = defaultdict(lambda: deque())
        self._last_cleanup = time.time()

    def add_event(self, rule_name: str, event: Event, window_seconds: int) -> int:
        """
        Add event to correlation window.

        Args:
            rule_name: Name of rule
            event: Event to track
            window_seconds: Time window size

        Returns:
            Current count of events in window
        """
        key = self._make_key(rule_name, event)
        timestamp = event.timestamp.timestamp()

        # Add to window
        self._event_windows[key].append((timestamp, event))

        # Trim old events
        self._trim_window(key, window_seconds)

        # Periodic cleanup
        if time.time() - self._last_cleanup > 300:  # Every 5 minutes
            self._cleanup_old_windows()
            self._last_cleanup = time.time()

        return len(self._event_windows[key])

    def get_count(self, rule_name: str, event: Event, window_seconds: int) -> int:
        """
        Get count of events in window.

        Args:
            rule_name: Name of rule
            event: Event to check
            window_seconds: Time window size

        Returns:
            Count of events in window
        """
        key = self._make_key(rule_name, event)
        self._trim_window(key, window_seconds)
        return len(self._event_windows[key])

    def get_events(self, rule_name: str, event: Event, window_seconds: int) -> List[Event]:
        """
        Get all events in window.

        Args:
            rule_name: Name of rule
            event: Event to check
            window_seconds: Time window size

        Returns:
            List of events in window
        """
        key = self._make_key(rule_name, event)
        self._trim_window(key, window_seconds)
        return [e for _, e in self._event_windows[key]]

    def _make_key(self, rule_name: str, event: Event) -> str:
        """Create key for event grouping."""
        # Default grouping by src_ip
        return f"{rule_name}:{event.src_ip}"

    def _trim_window(self, key: str, window_seconds: int) -> None:
        """Remove events outside time window."""
        if key not in self._event_windows:
            return

        cutoff = time.time() - window_seconds
        window = self._event_windows[key]

        while window and window[0][0] < cutoff:
            window.popleft()

    def _cleanup_old_windows(self) -> None:
        """Remove empty windows."""
        empty_keys = [key for key, window in self._event_windows.items() if not window]
        for key in empty_keys:
            del self._event_windows[key]


class RuleEvaluator:
    """
    Evaluates events against alert rules.
    """

    def __init__(self, correlator: AlertCorrelator):
        """
        Initialize rule evaluator.

        Args:
            correlator: Alert correlator for time-windowed rules
        """
        self.correlator = correlator

    def evaluate(self, rule: AlertRule, event: Event) -> Optional[Alert]:
        """
        Evaluate event against rule.

        Args:
            rule: Alert rule to evaluate
            event: Event to evaluate

        Returns:
            Alert if rule matches, None otherwise
        """
        if not rule.enabled:
            return None

        # Check event type
        if rule.event_type and event.event_type != rule.event_type:
            return None

        # Check count-based rules
        if rule.count and rule.time_window:
            current_count = self.correlator.add_event(rule.name, event, rule.time_window)

            if current_count < rule.count:
                return None

            # Generate alert with all events in window
            events_in_window = self.correlator.get_events(rule.name, event, rule.time_window)
            event_ids = [e.id for e in events_in_window]

            return Alert(
                timestamp=datetime.now(),
                rule_name=rule.name,
                severity=rule.severity,
                title=self._generate_title(rule, event, current_count),
                description=self._generate_description(rule, event, events_in_window),
                event_ids=event_ids,
                session_id=event.session_id,
                src_ip=event.src_ip,
            )

        # Check pattern-based rules
        if rule.command_pattern and isinstance(event, CommandEvent):
            if not re.search(rule.command_pattern, event.command, re.IGNORECASE):
                return None

        # Check GeoIP country rules
        if rule.geoip_country and event.geoip:
            if event.geoip.country_code not in rule.geoip_country:
                return None

        # Check username pattern
        if rule.username_pattern and isinstance(event, LoginEvent):
            if not re.search(rule.username_pattern, event.username, re.IGNORECASE):
                return None

        # Rule matched
        return Alert(
            timestamp=datetime.now(),
            rule_name=rule.name,
            severity=rule.severity,
            title=self._generate_title(rule, event),
            description=self._generate_description(rule, event),
            event_ids=[event.id],
            session_id=event.session_id,
            src_ip=event.src_ip,
        )

    def _generate_title(
        self, rule: AlertRule, event: Event, count: Optional[int] = None
    ) -> str:
        """Generate alert title."""
        if count:
            return f"{rule.description} ({count} occurrences)"
        return rule.description

    def _generate_description(
        self,
        rule: AlertRule,
        event: Event,
        events: Optional[List[Event]] = None,
    ) -> str:
        """Generate alert description."""
        parts = [f"Rule: {rule.name}"]
        parts.append(f"Source: {event.src_ip}")

        if event.geoip:
            parts.append(f"Location: {event.geoip}")

        if event.threat_intel and event.threat_intel.is_malicious:
            parts.append(f"Threat Intel: {event.threat_intel}")

        if events and len(events) > 1:
            parts.append(f"Event count: {len(events)}")

        if isinstance(event, LoginEvent):
            parts.append(f"Username: {event.username}")
            if event.password:
                parts.append(f"Password: {event.password}")

        if isinstance(event, CommandEvent):
            parts.append(f"Command: {event.command[:100]}")

        return " | ".join(parts)


class AlertManager:
    """
    Main alert manager that coordinates rule evaluation and alert distribution.
    """

    def __init__(self, rules: Optional[List[AlertRule]] = None):
        """
        Initialize alert manager.

        Args:
            rules: List of alert rules to evaluate
        """
        self.rules = rules or []
        self.correlator = AlertCorrelator()
        self.evaluator = RuleEvaluator(self.correlator)

        # Alert deduplication (prevent duplicate alerts within 5 minutes)
        self._recent_alerts: Dict[str, float] = {}
        self._dedup_window = 300  # 5 minutes

        # Callbacks for alert distribution
        self._alert_callbacks: List = []

        self.alerts_generated = 0

        logger.info("alert_manager_initialized", rule_count=len(self.rules))

    async def evaluate(self, event: Event) -> None:
        """
        Evaluate event against all rules.

        Args:
            event: Event to evaluate
        """
        for rule in self.rules:
            try:
                alert = self.evaluator.evaluate(rule, event)

                if alert and not self._is_duplicate(alert):
                    await self._distribute_alert(alert)
                    self.alerts_generated += 1

            except Exception as e:
                logger.error(
                    "rule_evaluation_error",
                    rule_name=rule.name,
                    event_id=event.id,
                    error=str(e),
                    exc_info=True,
                )

    def add_rule(self, rule: AlertRule) -> None:
        """
        Add alert rule.

        Args:
            rule: Alert rule to add
        """
        self.rules.append(rule)
        logger.info("alert_rule_added", rule_name=rule.name)

    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove alert rule by name.

        Args:
            rule_name: Name of rule to remove

        Returns:
            True if rule was removed
        """
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                del self.rules[i]
                logger.info("alert_rule_removed", rule_name=rule_name)
                return True
        return False

    def subscribe_alerts(self, callback) -> None:
        """
        Subscribe to alert notifications.

        Args:
            callback: Async or sync function to call with Alert
        """
        self._alert_callbacks.append(callback)

    async def _distribute_alert(self, alert: Alert) -> None:
        """Distribute alert to all subscribers."""
        logger.info(
            "alert_generated",
            rule=alert.rule_name,
            severity=alert.severity.value,
            title=alert.title,
        )

        # Call all subscribers
        import asyncio

        for callback in self._alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error("alert_callback_error", error=str(e), exc_info=True)

    def _is_duplicate(self, alert: Alert) -> bool:
        """
        Check if alert is a duplicate of a recent alert.

        Args:
            alert: Alert to check

        Returns:
            True if duplicate
        """
        # Create dedup key
        key = f"{alert.rule_name}:{alert.src_ip}:{alert.title}"

        # Check if recent
        if key in self._recent_alerts:
            last_time = self._recent_alerts[key]
            if time.time() - last_time < self._dedup_window:
                logger.debug("alert_deduplicated", rule=alert.rule_name)
                return True

        # Record alert
        self._recent_alerts[key] = time.time()

        # Cleanup old entries
        cutoff = time.time() - self._dedup_window
        self._recent_alerts = {
            k: v for k, v in self._recent_alerts.items() if v > cutoff
        }

        return False

    def get_stats(self) -> dict:
        """Get alert manager statistics."""
        return {
            "rule_count": len(self.rules),
            "alerts_generated": self.alerts_generated,
            "active_rules": sum(1 for r in self.rules if r.enabled),
        }
