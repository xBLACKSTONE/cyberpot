"""
Main dashboard screen for CyberPot TUI.

Displays live event feed, statistics, world map, and alert panel.
"""

import asyncio

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static

from ...core.event_processor import EventBus
from ...core.models import Alert, Event
from ...storage.memory_store import MemoryStore
from ...storage.statistics import StatsAggregator
from ..widgets.alert_panel import AlertPanel, AlertSummary
from ..widgets.event_feed import EventFeed
from ..widgets.statistics import (
    EventTypeBreakdown,
    StatsOverview,
    TopCommandsWidget,
    TopCountriesWidget,
    TopCredentialsWidget,
    TopIPsWidget,
)
from ..widgets.world_map import WorldMap


class DashboardScreen(Screen):
    """
    Main dashboard screen showing real-time honeypot activity.
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("c", "clear_events", "Clear Events"),
    ]

    def __init__(
        self,
        event_bus: EventBus,
        memory_store: MemoryStore,
        stats_aggregator: StatsAggregator,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize dashboard screen.

        Args:
            event_bus: EventBus for subscribing to events
            memory_store: Memory store for querying data
            stats_aggregator: Statistics aggregator
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.event_bus = event_bus
        self.memory_store = memory_store
        self.stats_aggregator = stats_aggregator

        self._update_task: asyncio.Task | None = None

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield Header()

        with Container(id="dashboard-container"):
            with Horizontal(id="main-content"):
                # Left panel: Event feed
                with Vertical(id="left-panel", classes="panel"):
                    yield Static("Live Events", classes="panel-title")
                    yield EventFeed(max_events=100, id="event-feed")

                # Right panel: Statistics and visualizations
                with Vertical(id="right-panel", classes="panel"):
                    # Stats overview
                    yield Static("Statistics", classes="panel-title")
                    yield StatsOverview(id="stats-overview")

                    # World map
                    yield Static("Attack Origins", classes="panel-title")
                    yield WorldMap(id="world-map")

                    # Top attackers
                    yield TopIPsWidget(id="top-ips")

            # Bottom panel: Alerts and additional stats
            with Horizontal(id="bottom-content"):
                with Vertical(id="bottom-left", classes="panel"):
                    yield Static("Recent Alerts", classes="panel-title")
                    yield AlertPanel(max_alerts=10, id="alert-panel")

                with Vertical(id="bottom-right", classes="panel"):
                    yield TopCountriesWidget(id="top-countries")
                    yield TopCredentialsWidget(id="top-credentials")
                    yield EventTypeBreakdown(id="event-breakdown")

        yield Footer()

    async def on_mount(self) -> None:
        """Called when screen is mounted."""
        # Subscribe to events
        self.event_bus.subscribe("*", self._handle_event)

        # Subscribe to alerts
        # Note: In full implementation, alert manager would publish alerts
        # For now, we'll update from memory store

        # Start periodic stats update
        self._update_task = asyncio.create_task(self._update_stats_loop())

        # Load initial data
        await self._load_initial_data()

    async def on_unmount(self) -> None:
        """Called when screen is unmounted."""
        # Cancel update task
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass

    async def _load_initial_data(self) -> None:
        """Load initial data from memory store."""
        # Load recent events
        recent_events = self.memory_store.events.get_recent(50)
        event_feed = self.query_one("#event-feed", EventFeed)

        for event in recent_events:
            event_feed.add_event(event)

        # Load recent alerts
        recent_alerts = self.memory_store.alerts.get_recent(10)
        alert_panel = self.query_one("#alert-panel", AlertPanel)

        for alert in recent_alerts:
            alert_panel.add_alert(alert)

        # Update stats
        await self._update_stats()

    async def _handle_event(self, event: Event) -> None:
        """
        Handle incoming event.

        Args:
            event: Event to handle
        """
        # Update event feed
        event_feed = self.query_one("#event-feed", EventFeed)
        event_feed.add_event(event)

    async def _handle_alert(self, alert: Alert) -> None:
        """
        Handle incoming alert.

        Args:
            alert: Alert to handle
        """
        # Update alert panel
        alert_panel = self.query_one("#alert-panel", AlertPanel)
        alert_panel.add_alert(alert)

    async def _update_stats_loop(self) -> None:
        """Periodically update statistics displays."""
        while True:
            try:
                await asyncio.sleep(1.0)  # Update every second
                await self._update_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                pass

    async def _update_stats(self) -> None:
        """Update all statistics widgets."""
        stats = self.stats_aggregator.get_current_stats()

        # Update all stats widgets
        self.query_one("#stats-overview", StatsOverview).stats = stats
        self.query_one("#world-map", WorldMap).stats = stats
        self.query_one("#top-ips", TopIPsWidget).stats = stats
        self.query_one("#top-countries", TopCountriesWidget).stats = stats
        self.query_one("#top-credentials", TopCredentialsWidget).stats = stats
        self.query_one("#event-breakdown", EventTypeBreakdown).stats = stats

    def action_refresh(self) -> None:
        """Refresh the dashboard."""
        # Trigger stats update
        asyncio.create_task(self._update_stats())

    def action_clear_events(self) -> None:
        """Clear event feed."""
        event_feed = self.query_one("#event-feed", EventFeed)
        event_feed.clear_events()
