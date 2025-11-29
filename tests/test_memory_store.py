"""
Tests for in-memory storage.
"""

import pytest

from cyberpot.storage.memory_store import AlertStore, EventStore, MemoryStore, RingBuffer, SessionStore
from cyberpot.core.models import Alert, Severity


class TestRingBuffer:
    """Test RingBuffer functionality."""

    def test_append(self):
        """Test appending items to buffer."""
        buffer = RingBuffer[int](capacity=3)
        buffer.append(1)
        buffer.append(2)
        buffer.append(3)

        assert len(buffer) == 3
        assert buffer.get_all() == [1, 2, 3]

    def test_capacity_overflow(self):
        """Test that oldest items are discarded when capacity is reached."""
        buffer = RingBuffer[int](capacity=3)
        buffer.append(1)
        buffer.append(2)
        buffer.append(3)
        buffer.append(4)  # Should discard 1

        assert len(buffer) == 3
        assert buffer.get_all() == [2, 3, 4]

    def test_extend(self):
        """Test extending buffer with multiple items."""
        buffer = RingBuffer[int](capacity=5)
        buffer.extend([1, 2, 3])

        assert len(buffer) == 3
        assert buffer.get_all() == [1, 2, 3]

    def test_get_last_n(self):
        """Test getting last N items."""
        buffer = RingBuffer[int](capacity=10)
        buffer.extend([1, 2, 3, 4, 5])

        assert buffer.get_last_n(3) == [3, 4, 5]
        assert buffer.get_last_n(10) == [1, 2, 3, 4, 5]

    def test_get_first_n(self):
        """Test getting first N items."""
        buffer = RingBuffer[int](capacity=10)
        buffer.extend([1, 2, 3, 4, 5])

        assert buffer.get_first_n(3) == [1, 2, 3]

    def test_clear(self):
        """Test clearing buffer."""
        buffer = RingBuffer[int](capacity=10)
        buffer.extend([1, 2, 3])
        buffer.clear()

        assert len(buffer) == 0


class TestEventStore:
    """Test EventStore functionality."""

    @pytest.mark.asyncio
    async def test_add_event(self, sample_login_event):
        """Test adding event to store."""
        store = EventStore(max_events=100)
        await store.add_event(sample_login_event)

        assert len(store) == 1
        assert sample_login_event in store.get_all()

    @pytest.mark.asyncio
    async def test_get_by_session(self, sample_login_event, sample_command_event):
        """Test retrieving events by session ID."""
        store = EventStore(max_events=100)
        await store.add_event(sample_login_event)
        await store.add_event(sample_command_event)

        events = store.get_by_session("test_session_123")
        assert len(events) == 2

    @pytest.mark.asyncio
    async def test_get_by_ip(self, sample_login_event, sample_ip):
        """Test retrieving events by IP address."""
        store = EventStore(max_events=100)
        await store.add_event(sample_login_event)

        events = store.get_by_ip(sample_ip)
        assert len(events) == 1
        assert events[0] == sample_login_event

    @pytest.mark.asyncio
    async def test_get_recent(self, sample_login_event):
        """Test retrieving recent events."""
        store = EventStore(max_events=100)
        for _ in range(10):
            await store.add_event(sample_login_event)

        recent = store.get_recent(5)
        assert len(recent) == 5


class TestSessionStore:
    """Test SessionStore functionality."""

    @pytest.mark.asyncio
    async def test_add_session(self):
        """Test adding session to store."""
        from datetime import datetime
        from cyberpot.core.models import Session

        store = SessionStore(max_sessions=100)
        session = Session(
            session_id="test_123",
            src_ip="192.168.1.100",
            start_time=datetime.now(),
        )

        await store.add_or_update_session(session)

        assert len(store) == 1
        assert store.get_session("test_123") == session

    @pytest.mark.asyncio
    async def test_update_session(self):
        """Test updating existing session."""
        from datetime import datetime
        from cyberpot.core.models import Session

        store = SessionStore(max_sessions=100)
        session = Session(
            session_id="test_123",
            src_ip="192.168.1.100",
            start_time=datetime.now(),
            login_attempts=0,
        )

        await store.add_or_update_session(session)

        # Update session
        session.login_attempts = 5
        await store.add_or_update_session(session)

        updated = store.get_session("test_123")
        assert updated.login_attempts == 5

    @pytest.mark.asyncio
    async def test_get_active_sessions(self):
        """Test retrieving active sessions."""
        from datetime import datetime
        from cyberpot.core.models import Session

        store = SessionStore(max_sessions=100)

        # Active session
        active = Session(
            session_id="active",
            src_ip="192.168.1.100",
            start_time=datetime.now(),
        )
        await store.add_or_update_session(active)

        # Ended session
        ended = Session(
            session_id="ended",
            src_ip="192.168.1.101",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
        await store.add_or_update_session(ended)

        active_sessions = store.get_active()
        assert len(active_sessions) == 1
        assert active_sessions[0].session_id == "active"


class TestAlertStore:
    """Test AlertStore functionality."""

    @pytest.mark.asyncio
    async def test_add_alert(self):
        """Test adding alert to store."""
        from datetime import datetime

        store = AlertStore(max_alerts=100)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test_rule",
            severity=Severity.HIGH,
            title="Test Alert",
            description="Test description",
        )

        await store.add_alert(alert)

        assert len(store) == 1

    @pytest.mark.asyncio
    async def test_get_unacknowledged(self):
        """Test retrieving unacknowledged alerts."""
        from datetime import datetime

        store = AlertStore(max_alerts=100)

        # Unacknowledged alert
        alert1 = Alert(
            timestamp=datetime.now(),
            rule_name="test1",
            severity=Severity.HIGH,
            title="Alert 1",
            description="Description 1",
        )
        await store.add_alert(alert1)

        # Acknowledged alert
        alert2 = Alert(
            timestamp=datetime.now(),
            rule_name="test2",
            severity=Severity.MEDIUM,
            title="Alert 2",
            description="Description 2",
            acknowledged=True,
        )
        await store.add_alert(alert2)

        unacked = store.get_unacknowledged()
        assert len(unacked) == 1
        assert unacked[0] == alert1

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self):
        """Test acknowledging alerts."""
        from datetime import datetime

        store = AlertStore(max_alerts=100)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="Test Alert",
            description="Test description",
        )
        await store.add_alert(alert)

        result = store.acknowledge_alert(alert.id)
        assert result is True

        unacked = store.get_unacknowledged()
        assert len(unacked) == 0


class TestMemoryStore:
    """Test combined MemoryStore functionality."""

    @pytest.mark.asyncio
    async def test_add_event_creates_session(self, sample_login_event):
        """Test that adding event creates associated session."""
        store = MemoryStore()
        await store.add_event(sample_login_event)

        session = store.sessions.get_session(sample_login_event.session_id)
        assert session is not None
        assert session.src_ip == sample_login_event.src_ip

    @pytest.mark.asyncio
    async def test_add_event_updates_session_stats(self, sample_login_event):
        """Test that events update session statistics."""
        store = MemoryStore()

        # Add multiple login attempts
        for _ in range(3):
            await store.add_event(sample_login_event)

        session = store.sessions.get_session(sample_login_event.session_id)
        assert session.login_attempts == 3

    def test_get_stats(self):
        """Test getting store statistics."""
        store = MemoryStore()
        stats = store.get_stats()

        assert "events" in stats
        assert "sessions" in stats
        assert "alerts" in stats
        assert stats["events"] == 0
