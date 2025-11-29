"""
Event processing pipeline and EventBus for distributing events.

The EventBus provides pub/sub functionality for loose coupling between components.
The EventProcessor orchestrates the enrichment, analysis, and distribution pipeline.
"""

import asyncio
from collections import defaultdict
from typing import Callable, Dict, List, Optional

import structlog

from .models import Event, EventType

logger = structlog.get_logger(__name__)


class EventBus:
    """
    Publish-subscribe event bus for distributing events to subscribers.

    Supports both specific event type subscriptions and wildcard ('*') subscriptions.
    """

    def __init__(self):
        """Initialize the event bus."""
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._event_count = 0

    def subscribe(self, event_type: str, callback: Callable) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: Event type to subscribe to, or '*' for all events
            callback: Async or sync function to call when event occurs
        """
        self._subscribers[event_type].append(callback)
        logger.debug("subscriber_added", event_type=event_type, callback=callback.__name__)

    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """
        Unsubscribe from an event type.

        Args:
            event_type: Event type to unsubscribe from
            callback: Previously registered callback function
        """
        if event_type in self._subscribers:
            try:
                self._subscribers[event_type].remove(callback)
                logger.debug("subscriber_removed", event_type=event_type, callback=callback.__name__)
            except ValueError:
                logger.warning("subscriber_not_found", event_type=event_type)

    async def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: Event to publish
        """
        self._event_count += 1
        event_type = event.event_type.value

        # Collect all relevant subscribers
        subscribers = []
        subscribers.extend(self._subscribers.get(event_type, []))
        subscribers.extend(self._subscribers.get("*", []))

        if not subscribers:
            logger.debug("no_subscribers", event_type=event_type)
            return

        # Call all subscribers concurrently
        await asyncio.gather(*[self._safe_call(callback, event) for callback in subscribers])

    async def _safe_call(self, callback: Callable, event: Event) -> None:
        """
        Call a callback safely, catching and logging exceptions.

        Args:
            callback: Callback function to call
            event: Event to pass to callback
        """
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(event)
            else:
                callback(event)
        except Exception as e:
            logger.error(
                "subscriber_error",
                callback=callback.__name__,
                event_type=event.event_type.value,
                error=str(e),
                exc_info=True,
            )

    def get_stats(self) -> dict:
        """Get event bus statistics."""
        return {
            "total_events": self._event_count,
            "subscribers": {
                event_type: len(callbacks) for event_type, callbacks in self._subscribers.items()
            },
        }


class EventProcessor:
    """
    Process events through enrichment, analysis, and distribution pipeline.

    Stages:
    1. Enrichment (GeoIP, threat intel)
    2. Session association
    3. Pattern detection
    4. Alert evaluation
    5. Storage
    6. Distribution via EventBus
    """

    def __init__(
        self,
        event_bus: EventBus,
        enrichment_engine: Optional["EnrichmentEngine"] = None,  # Forward reference
        alert_manager: Optional["AlertManager"] = None,  # Forward reference
        memory_store: Optional["MemoryStore"] = None,  # Forward reference
    ):
        """
        Initialize event processor.

        Args:
            event_bus: EventBus for distributing processed events
            enrichment_engine: Optional enrichment engine
            alert_manager: Optional alert manager
            memory_store: Optional memory store for persistence
        """
        self.event_bus = event_bus
        self.enrichment_engine = enrichment_engine
        self.alert_manager = alert_manager
        self.memory_store = memory_store

        self.processed_count = 0
        self.error_count = 0

        logger.info("event_processor_initialized")

    async def process_event(self, event: Event) -> None:
        """
        Process a single event through the pipeline.

        Args:
            event: Event to process
        """
        try:
            # Stage 1: Enrichment
            if self.enrichment_engine:
                await self.enrichment_engine.enrich(event)

            # Stage 2: Session association (handled by memory store)
            if self.memory_store:
                await self.memory_store.add_event(event)

            # Stage 3: Alert evaluation
            if self.alert_manager:
                await self.alert_manager.evaluate(event)

            # Stage 4: Distribution
            await self.event_bus.publish(event)

            self.processed_count += 1

        except Exception as e:
            self.error_count += 1
            logger.error(
                "process_event_error",
                event_id=event.id,
                event_type=event.event_type.value,
                error=str(e),
                exc_info=True,
            )

    async def process_batch(self, events: List[Event]) -> None:
        """
        Process a batch of events concurrently.

        Args:
            events: List of events to process
        """
        await asyncio.gather(*[self.process_event(event) for event in events])

    def get_stats(self) -> dict:
        """Get processor statistics."""
        return {
            "processed_count": self.processed_count,
            "error_count": self.error_count,
            "success_rate": (
                self.processed_count / (self.processed_count + self.error_count)
                if (self.processed_count + self.error_count) > 0
                else 0.0
            ),
        }


class EventPipeline:
    """
    Complete event processing pipeline from log lines to distributed events.

    Coordinates LogParser → EventProcessor → EventBus
    """

    def __init__(
        self,
        log_parser: "CowrieLogParser",  # Forward reference
        event_processor: EventProcessor,
    ):
        """
        Initialize event pipeline.

        Args:
            log_parser: Cowrie log parser
            event_processor: Event processor
        """
        self.log_parser = log_parser
        self.event_processor = event_processor
        self._running = False

        logger.info("event_pipeline_initialized")

    async def process_lines(self, lines: List[str]) -> None:
        """
        Process a batch of log lines through the complete pipeline.

        Args:
            lines: Raw JSON log lines from Cowrie
        """
        # Parse lines to events
        events = self.log_parser.parse_batch(lines)

        if not events:
            logger.debug("no_events_parsed", line_count=len(lines))
            return

        # Process events
        await self.event_processor.process_batch(events)

        logger.debug("batch_processed", event_count=len(events), line_count=len(lines))

    async def start(self, log_tailer: "LogTailer") -> None:  # Forward reference
        """
        Start the pipeline with a log tailer.

        Args:
            log_tailer: Log tailer to read from
        """
        self._running = True
        logger.info("event_pipeline_started")

        try:
            async for batch in log_tailer.start():
                if not self._running:
                    break

                await self.process_lines(batch)
        except asyncio.CancelledError:
            logger.info("event_pipeline_cancelled")
            raise
        except Exception as e:
            logger.error("event_pipeline_error", error=str(e), exc_info=True)
            raise
        finally:
            self._running = False
            logger.info("event_pipeline_stopped")

    def stop(self) -> None:
        """Stop the pipeline."""
        self._running = False
        logger.info("event_pipeline_stop_requested")

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        return {
            "parser": self.log_parser.get_stats(),
            "processor": self.event_processor.get_stats(),
            "event_bus": self.event_processor.event_bus.get_stats(),
        }
