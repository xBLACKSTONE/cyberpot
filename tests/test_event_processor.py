"""
Tests for event processor and EventBus.
"""

import pytest

from cyberpot.core.event_processor import EventBus, EventProcessor
from cyberpot.core.models import EventType


class TestEventBus:
    """Test EventBus functionality."""

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, sample_login_event):
        """Test subscribing and publishing events."""
        bus = EventBus()
        received_events = []

        async def callback(event):
            received_events.append(event)

        bus.subscribe(EventType.LOGIN_FAILED.value, callback)
        await bus.publish(sample_login_event)

        assert len(received_events) == 1
        assert received_events[0] == sample_login_event

    @pytest.mark.asyncio
    async def test_wildcard_subscription(self, sample_login_event, sample_command_event):
        """Test wildcard subscription receives all events."""
        bus = EventBus()
        received_events = []

        async def callback(event):
            received_events.append(event)

        bus.subscribe("*", callback)
        await bus.publish(sample_login_event)
        await bus.publish(sample_command_event)

        assert len(received_events) == 2

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, sample_login_event):
        """Test multiple subscribers receive same event."""
        bus = EventBus()
        received_count = [0]

        async def callback1(event):
            received_count[0] += 1

        async def callback2(event):
            received_count[0] += 1

        bus.subscribe(EventType.LOGIN_FAILED.value, callback1)
        bus.subscribe(EventType.LOGIN_FAILED.value, callback2)
        await bus.publish(sample_login_event)

        assert received_count[0] == 2

    @pytest.mark.asyncio
    async def test_unsubscribe(self, sample_login_event):
        """Test unsubscribing from events."""
        bus = EventBus()
        received_events = []

        async def callback(event):
            received_events.append(event)

        bus.subscribe(EventType.LOGIN_FAILED.value, callback)
        bus.unsubscribe(EventType.LOGIN_FAILED.value, callback)
        await bus.publish(sample_login_event)

        assert len(received_events) == 0

    @pytest.mark.asyncio
    async def test_callback_error_handling(self, sample_login_event):
        """Test that callback errors don't crash the bus."""
        bus = EventBus()
        received_events = []

        async def failing_callback(event):
            raise ValueError("Test error")

        async def working_callback(event):
            received_events.append(event)

        bus.subscribe(EventType.LOGIN_FAILED.value, failing_callback)
        bus.subscribe(EventType.LOGIN_FAILED.value, working_callback)
        await bus.publish(sample_login_event)

        # Working callback should still receive event
        assert len(received_events) == 1

    def test_get_stats(self, sample_login_event):
        """Test event bus statistics."""
        bus = EventBus()

        async def callback(event):
            pass

        bus.subscribe(EventType.LOGIN_FAILED.value, callback)
        bus.subscribe("*", callback)

        stats = bus.get_stats()
        assert stats["total_events"] == 0
        assert len(stats["subscribers"]) == 2


class TestEventProcessor:
    """Test EventProcessor functionality."""

    @pytest.mark.asyncio
    async def test_process_event(self, sample_login_event):
        """Test processing single event."""
        bus = EventBus()
        processor = EventProcessor(bus)

        await processor.process_event(sample_login_event)

        assert processor.processed_count == 1
        assert processor.error_count == 0

    @pytest.mark.asyncio
    async def test_process_batch(self, sample_login_event, sample_command_event):
        """Test processing batch of events."""
        bus = EventBus()
        processor = EventProcessor(bus)

        events = [sample_login_event, sample_command_event]
        await processor.process_batch(events)

        assert processor.processed_count == 2

    @pytest.mark.asyncio
    async def test_event_distribution(self, sample_login_event):
        """Test that processed events are distributed via EventBus."""
        bus = EventBus()
        processor = EventProcessor(bus)
        received_events = []

        async def callback(event):
            received_events.append(event)

        bus.subscribe("*", callback)
        await processor.process_event(sample_login_event)

        assert len(received_events) == 1
        assert received_events[0] == sample_login_event

    def test_get_stats(self):
        """Test processor statistics."""
        bus = EventBus()
        processor = EventProcessor(bus)

        stats = processor.get_stats()
        assert stats["processed_count"] == 0
        assert stats["error_count"] == 0
        assert stats["success_rate"] == 0.0
