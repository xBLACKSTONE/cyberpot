"""
In-memory storage using ring buffers for bounded memory usage.

Stores events, sessions, and alerts with efficient querying capabilities.
"""

import asyncio
from collections import deque
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from threading import RLock
from typing import Dict, Generic, List, Optional, TypeVar, Union

import structlog

from ..core.models import Alert, Event, Session

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class RingBuffer(Generic[T]):
    """
    Thread-safe ring buffer with fixed capacity.

    When capacity is reached, oldest items are automatically discarded.
    """

    def __init__(self, capacity: int):
        """
        Initialize ring buffer.

        Args:
            capacity: Maximum number of items to store
        """
        self.capacity = capacity
        self._buffer: deque[T] = deque(maxlen=capacity)
        self._lock = RLock()

    def append(self, item: T) -> None:
        """
        Add item to buffer.

        Args:
            item: Item to add
        """
        with self._lock:
            self._buffer.append(item)

    def extend(self, items: List[T]) -> None:
        """
        Add multiple items.

        Args:
            items: Items to add
        """
        with self._lock:
            self._buffer.extend(items)

    def get_all(self) -> List[T]:
        """
        Get all items (oldest to newest).

        Returns:
            List of all items in buffer
        """
        with self._lock:
            return list(self._buffer)

    def get_last_n(self, n: int) -> List[T]:
        """
        Get last N items.

        Args:
            n: Number of items to retrieve

        Returns:
            List of last N items
        """
        with self._lock:
            return list(self._buffer)[-n:] if n > 0 else []

    def get_first_n(self, n: int) -> List[T]:
        """
        Get first N items.

        Args:
            n: Number of items to retrieve

        Returns:
            List of first N items
        """
        with self._lock:
            return list(self._buffer)[:n] if n > 0 else []

    def clear(self) -> None:
        """Clear all items from buffer."""
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        """Get current buffer size."""
        with self._lock:
            return len(self._buffer)

    def __iter__(self):
        """Iterate over buffer items."""
        with self._lock:
            return iter(list(self._buffer))


class EventStore:
    """
    Store for events with time-series indexing and querying.
    """

    def __init__(self, max_events: int = 10000):
        """
        Initialize event store.

        Args:
            max_events: Maximum number of events to keep
        """
        self.max_events = max_events
        self._events = RingBuffer[Event](max_events)
        self._lock = RLock()

        # Indexes for efficient querying
        self._by_session: Dict[str, List[Event]] = {}
        self._by_ip: Dict[Union[IPv4Address, IPv6Address], List[Event]] = {}

        logger.info("event_store_initialized", max_events=max_events)

    async def add_event(self, event: Event) -> None:
        """
        Add event to store.

        Args:
            event: Event to add
        """
        with self._lock:
            self._events.append(event)

            # Update indexes
            if event.session_id not in self._by_session:
                self._by_session[event.session_id] = []
            self._by_session[event.session_id].append(event)

            if event.src_ip not in self._by_ip:
                self._by_ip[event.src_ip] = []
            self._by_ip[event.src_ip].append(event)

            # Trim indexes to prevent unbounded growth
            self._trim_indexes()

    def get_all(self) -> List[Event]:
        """Get all events."""
        return self._events.get_all()

    def get_recent(self, n: int = 100) -> List[Event]:
        """Get N most recent events."""
        return self._events.get_last_n(n)

    def get_by_session(self, session_id: str) -> List[Event]:
        """Get all events for a session."""
        with self._lock:
            return self._by_session.get(session_id, [])

    def get_by_ip(self, src_ip: Union[IPv4Address, IPv6Address, str]) -> List[Event]:
        """Get all events from an IP address."""
        if isinstance(src_ip, str):
            from ipaddress import ip_address

            src_ip = ip_address(src_ip)

        with self._lock:
            return self._by_ip.get(src_ip, [])

    def get_by_time_range(
        self, start_time: datetime, end_time: Optional[datetime] = None
    ) -> List[Event]:
        """Get events within time range."""
        end_time = end_time or datetime.now()
        return [e for e in self._events if start_time <= e.timestamp <= end_time]

    def _trim_indexes(self) -> None:
        """Trim indexes to prevent memory growth (keep last 1000 per index)."""
        max_per_index = 1000

        for session_id in list(self._by_session.keys()):
            if len(self._by_session[session_id]) > max_per_index:
                self._by_session[session_id] = self._by_session[session_id][-max_per_index:]

        for ip in list(self._by_ip.keys()):
            if len(self._by_ip[ip]) > max_per_index:
                self._by_ip[ip] = self._by_ip[ip][-max_per_index:]

    def __len__(self) -> int:
        """Get current event count."""
        return len(self._events)


class SessionStore:
    """
    Store for session tracking.
    """

    def __init__(self, max_sessions: int = 1000):
        """
        Initialize session store.

        Args:
            max_sessions: Maximum number of sessions to keep
        """
        self.max_sessions = max_sessions
        self._sessions: Dict[str, Session] = {}
        self._session_order: deque[str] = deque(maxlen=max_sessions)
        self._lock = RLock()

        logger.info("session_store_initialized", max_sessions=max_sessions)

    async def add_or_update_session(self, session: Session) -> None:
        """
        Add or update a session.

        Args:
            session: Session to add/update
        """
        with self._lock:
            self._sessions[session.session_id] = session

            # Update order tracking
            if session.session_id in self._session_order:
                self._session_order.remove(session.session_id)
            self._session_order.append(session.session_id)

            # Remove oldest if over capacity
            if len(self._sessions) > self.max_sessions:
                oldest_id = self._session_order[0]
                if oldest_id in self._sessions:
                    del self._sessions[oldest_id]

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        with self._lock:
            return self._sessions.get(session_id)

    def get_all(self) -> List[Session]:
        """Get all sessions."""
        with self._lock:
            return list(self._sessions.values())

    def get_active(self) -> List[Session]:
        """Get active sessions (no end_time)."""
        with self._lock:
            return [s for s in self._sessions.values() if s.end_time is None]

    def get_by_ip(self, src_ip: Union[IPv4Address, IPv6Address, str]) -> List[Session]:
        """Get sessions from an IP address."""
        if isinstance(src_ip, str):
            from ipaddress import ip_address

            src_ip = ip_address(src_ip)

        with self._lock:
            return [s for s in self._sessions.values() if s.src_ip == src_ip]

    def __len__(self) -> int:
        """Get current session count."""
        return len(self._sessions)


class AlertStore:
    """
    Store for alerts with deduplication.
    """

    def __init__(self, max_alerts: int = 5000):
        """
        Initialize alert store.

        Args:
            max_alerts: Maximum number of alerts to keep
        """
        self.max_alerts = max_alerts
        self._alerts = RingBuffer[Alert](max_alerts)
        self._lock = RLock()

        logger.info("alert_store_initialized", max_alerts=max_alerts)

    async def add_alert(self, alert: Alert) -> None:
        """
        Add alert to store.

        Args:
            alert: Alert to add
        """
        with self._lock:
            self._alerts.append(alert)

    def get_all(self) -> List[Alert]:
        """Get all alerts."""
        return self._alerts.get_all()

    def get_recent(self, n: int = 100) -> List[Alert]:
        """Get N most recent alerts."""
        return self._alerts.get_last_n(n)

    def get_unacknowledged(self) -> List[Alert]:
        """Get unacknowledged alerts."""
        return [a for a in self._alerts if not a.acknowledged]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Acknowledge an alert.

        Args:
            alert_id: ID of alert to acknowledge

        Returns:
            True if alert was found and acknowledged
        """
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    return True
            return False

    def __len__(self) -> int:
        """Get current alert count."""
        return len(self._alerts)


class MemoryStore:
    """
    Combined in-memory store for events, sessions, and alerts.
    """

    def __init__(
        self, max_events: int = 10000, max_sessions: int = 1000, max_alerts: int = 5000
    ):
        """
        Initialize memory store.

        Args:
            max_events: Maximum events to store
            max_sessions: Maximum sessions to store
            max_alerts: Maximum alerts to store
        """
        self.events = EventStore(max_events)
        self.sessions = SessionStore(max_sessions)
        self.alerts = AlertStore(max_alerts)

        logger.info(
            "memory_store_initialized",
            max_events=max_events,
            max_sessions=max_sessions,
            max_alerts=max_alerts,
        )

    async def add_event(self, event: Event) -> None:
        """Add event and update associated session."""
        await self.events.add_event(event)

        # Update session
        session = self.sessions.get_session(event.session_id)
        if not session:
            # Create new session
            session = Session(
                session_id=event.session_id,
                src_ip=event.src_ip,
                start_time=event.timestamp,
                geoip=event.geoip,
                threat_intel=event.threat_intel,
            )

        # Update session based on event type
        from ..core.models import CommandEvent, FileDownloadEvent, LoginEvent, SessionEvent

        if isinstance(event, LoginEvent):
            session.login_attempts += 1
            if event.success:
                session.successful_login = True
        elif isinstance(event, CommandEvent):
            if event.command not in session.commands:
                session.commands.append(event.command)
        elif isinstance(event, FileDownloadEvent):
            if event.url not in session.downloads:
                session.downloads.append(event.url)
        elif isinstance(event, SessionEvent):
            from ..core.models import EventType

            if event.event_type == EventType.SESSION_END:
                session.end_time = event.timestamp
                if session.start_time:
                    session.duration = (session.end_time - session.start_time).total_seconds()

        await self.sessions.add_or_update_session(session)

    async def add_alert(self, alert: Alert) -> None:
        """Add alert."""
        await self.alerts.add_alert(alert)

    def get_stats(self) -> dict:
        """Get storage statistics."""
        return {
            "events": len(self.events),
            "sessions": len(self.sessions),
            "active_sessions": len(self.sessions.get_active()),
            "alerts": len(self.alerts),
            "unacknowledged_alerts": len(self.alerts.get_unacknowledged()),
        }
