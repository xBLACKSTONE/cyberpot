"""
Real-time statistics aggregation with time-windowed metrics.

Tracks event counts, top-N lists, and rates for monitoring dashboards.
"""

import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from threading import RLock
from typing import Dict, List, Optional, Tuple, Union

import structlog

from ..core.models import Alert, Event, EventType, Session, Statistics

logger = structlog.get_logger(__name__)


class TimeWindowStats:
    """
    Statistics for a specific time window.

    Tracks events within a sliding time window for rate calculations.
    """

    def __init__(self, window_seconds: int):
        """
        Initialize time window stats.

        Args:
            window_seconds: Size of time window in seconds
        """
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = RLock()

    def add_event(self, timestamp: Optional[float] = None) -> None:
        """
        Record an event at timestamp.

        Args:
            timestamp: Unix timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            self._timestamps.append(timestamp)
            self._trim_old()

    def get_count(self) -> int:
        """Get count of events in window."""
        with self._lock:
            self._trim_old()
            return len(self._timestamps)

    def get_rate(self) -> float:
        """Get events per second in window."""
        with self._lock:
            count = self.get_count()
            return count / self.window_seconds if self.window_seconds > 0 else 0.0

    def _trim_old(self) -> None:
        """Remove events outside time window."""
        cutoff = time.time() - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


class TopNTracker:
    """
    Efficiently track top N items by frequency.
    """

    def __init__(self, n: int = 10):
        """
        Initialize top-N tracker.

        Args:
            n: Number of top items to track
        """
        self.n = n
        self._counter: Counter = Counter()
        self._lock = RLock()

    def add(self, item: str, count: int = 1) -> None:
        """
        Add item occurrence(s).

        Args:
            item: Item to track
            count: Number of occurrences
        """
        with self._lock:
            self._counter[item] += count

    def get_top_n(self) -> List[Tuple[str, int]]:
        """
        Get top N items.

        Returns:
            List of (item, count) tuples
        """
        with self._lock:
            return self._counter.most_common(self.n)

    def clear(self) -> None:
        """Clear all counts."""
        with self._lock:
            self._counter.clear()


class StatsAggregator:
    """
    Main statistics aggregator with multiple time windows.

    Provides real-time statistics for dashboards and monitoring.
    """

    def __init__(self, time_windows: Optional[List[int]] = None):
        """
        Initialize statistics aggregator.

        Args:
            time_windows: List of time window sizes in seconds (default: [3600, 86400, 604800])
        """
        if time_windows is None:
            time_windows = [3600, 86400, 604800]  # 1h, 1d, 1w

        self.time_windows = {seconds: TimeWindowStats(seconds) for seconds in time_windows}

        # Overall counters
        self.total_events = 0
        self.total_sessions = 0
        self.total_alerts = 0

        # Event type breakdown
        self.events_by_type: Counter = Counter()

        # Top-N trackers
        self.top_ips = TopNTracker(10)
        self.top_countries = TopNTracker(10)
        self.top_usernames = TopNTracker(10)
        self.top_passwords = TopNTracker(10)
        self.top_commands = TopNTracker(10)

        # Session tracking
        self.active_session_ids: set = set()

        # Rates
        self.start_time = time.time()

        self._lock = RLock()

        logger.info("stats_aggregator_initialized", time_windows=time_windows)

    def record_event(self, event: Event) -> None:
        """
        Record an event in statistics.

        Args:
            event: Event to record
        """
        with self._lock:
            self.total_events += 1

            # Record in time windows
            timestamp = event.timestamp.timestamp()
            for window in self.time_windows.values():
                window.add_event(timestamp)

            # Event type breakdown
            self.events_by_type[event.event_type.value] += 1

            # IP tracking
            self.top_ips.add(str(event.src_ip))

            # GeoIP tracking
            if event.geoip and event.geoip.country_code:
                self.top_countries.add(event.geoip.country_code)

            # Event-specific tracking
            from ..core.models import CommandEvent, LoginEvent

            if isinstance(event, LoginEvent):
                self.top_usernames.add(event.username)
                if event.password:
                    self.top_passwords.add(event.password)
            elif isinstance(event, CommandEvent):
                self.top_commands.add(event.command[:100])  # Limit command length

    def record_session(self, session: Session) -> None:
        """
        Record a session in statistics.

        Args:
            session: Session to record
        """
        with self._lock:
            self.total_sessions += 1

            # Track active sessions
            if session.end_time is None:
                self.active_session_ids.add(session.session_id)
            else:
                self.active_session_ids.discard(session.session_id)

    def record_alert(self, alert: Alert) -> None:
        """
        Record an alert in statistics.

        Args:
            alert: Alert to record
        """
        with self._lock:
            self.total_alerts += 1

    def get_current_stats(self) -> Statistics:
        """
        Get current statistics snapshot.

        Returns:
            Statistics model with current data
        """
        with self._lock:
            # Calculate rates
            uptime_seconds = time.time() - self.start_time
            events_per_second = (
                self.total_events / uptime_seconds if uptime_seconds > 0 else 0.0
            )
            sessions_per_hour = (
                (self.total_sessions / uptime_seconds) * 3600 if uptime_seconds > 0 else 0.0
            )

            return Statistics(
                timestamp=datetime.now(),
                total_events=self.total_events,
                total_sessions=self.total_sessions,
                active_sessions=len(self.active_session_ids),
                total_alerts=self.total_alerts,
                events_by_type=dict(self.events_by_type),
                top_ips=self.top_ips.get_top_n(),
                top_countries=self.top_countries.get_top_n(),
                top_usernames=self.top_usernames.get_top_n(),
                top_passwords=self.top_passwords.get_top_n(),
                top_commands=self.top_commands.get_top_n(),
                events_per_second=events_per_second,
                sessions_per_hour=sessions_per_hour,
            )

    def get_window_stats(self, window_seconds: int) -> dict:
        """
        Get statistics for a specific time window.

        Args:
            window_seconds: Time window size

        Returns:
            Dictionary with window statistics
        """
        with self._lock:
            window = self.time_windows.get(window_seconds)
            if not window:
                return {"error": "Unknown time window"}

            count = window.get_count()
            rate = window.get_rate()

            return {
                "window_seconds": window_seconds,
                "event_count": count,
                "events_per_second": rate,
            }

    def reset(self) -> None:
        """Reset all statistics (useful for testing)."""
        with self._lock:
            self.total_events = 0
            self.total_sessions = 0
            self.total_alerts = 0
            self.events_by_type.clear()
            self.top_ips.clear()
            self.top_countries.clear()
            self.top_usernames.clear()
            self.top_passwords.clear()
            self.top_commands.clear()
            self.active_session_ids.clear()
            self.start_time = time.time()

            for window in self.time_windows.values():
                window._timestamps.clear()

            logger.info("stats_reset")
