"""
Main Textual application for CyberPot TUI.

Provides real-time monitoring interface with multiple screens for different views.
"""

from typing import Optional

import structlog
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.driver import Driver
from textual.widgets import Footer, Header

from ..core.event_processor import EventBus
from ..storage.memory_store import MemoryStore
from ..storage.statistics import StatsAggregator
from .screens.dashboard import DashboardScreen

logger = structlog.get_logger(__name__)


class CyberPotApp(App):
    """
    Main CyberPot TUI application.

    Provides real-time monitoring of honeypot activity with multiple screens.
    """

    CSS_PATH = "styles.css"
    TITLE = "CyberPot - Honeypot Monitoring"

    BINDINGS = [
        Binding("f1", "switch_screen('dashboard')", "Dashboard", show=True, priority=True),
        Binding("f2", "switch_screen('sessions')", "Sessions", show=True, priority=True),
        Binding("f3", "switch_screen('search')", "Search", show=True, priority=True),
        Binding("f4", "switch_screen('alerts')", "Alerts", show=True, priority=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("?", "help", "Help", show=False),
    ]

    def __init__(
        self,
        event_bus: EventBus,
        memory_store: MemoryStore,
        stats_aggregator: StatsAggregator,
        driver_class: Optional[Driver] = None,
        css_path: Optional[str] = None,
        watch_css: bool = False,
    ):
        """
        Initialize CyberPot app.

        Args:
            event_bus: EventBus for subscribing to events
            memory_store: Memory store for querying data
            stats_aggregator: Statistics aggregator
            driver_class: Optional Textual driver class
            css_path: Optional CSS file path
            watch_css: Whether to watch CSS for changes
        """
        super().__init__(driver_class=driver_class, css_path=css_path, watch_css=watch_css)

        self.event_bus = event_bus
        self.memory_store = memory_store
        self.stats_aggregator = stats_aggregator

        # Screen registry
        self._screens_installed = False

        logger.info("cyberpot_tui_initialized")

    def on_mount(self) -> None:
        """Called when app is mounted."""
        # Install screens
        if not self._screens_installed:
            self._install_screens()
            self._screens_installed = True

        # Start on dashboard
        self.push_screen("dashboard")

        logger.info("cyberpot_tui_mounted")

    def _install_screens(self) -> None:
        """Install all application screens."""
        # Import screens here to avoid circular imports
        from .screens.dashboard import DashboardScreen
        from .screens.session_detail import SessionListScreen
        from .screens.search import SearchScreen
        from .screens.alerts import AlertsScreen

        # Install screens
        self.install_screen(
            DashboardScreen(
                self.event_bus,
                self.memory_store,
                self.stats_aggregator,
            ),
            name="dashboard",
        )

        self.install_screen(
            SessionListScreen(
                self.memory_store,
                self.stats_aggregator,
            ),
            name="sessions",
        )

        self.install_screen(
            SearchScreen(
                self.memory_store,
            ),
            name="search",
        )

        self.install_screen(
            AlertsScreen(
                self.memory_store,
            ),
            name="alerts",
        )

        logger.info("tui_screens_installed", screen_count=4)

    def action_switch_screen(self, screen_name: str) -> None:
        """
        Switch to a different screen.

        Args:
            screen_name: Name of screen to switch to
        """
        try:
            self.switch_screen(screen_name)
            logger.debug("screen_switched", screen=screen_name)
        except Exception as e:
            logger.error("screen_switch_error", screen=screen_name, error=str(e))

    def action_refresh(self) -> None:
        """Refresh current screen."""
        logger.debug("refresh_requested")
        # Current screen will handle refresh via reactive updates

    def action_help(self) -> None:
        """Show help screen."""
        # TODO: Implement help screen in future
        logger.debug("help_requested")

    def action_quit(self) -> None:
        """Quit the application."""
        logger.info("cyberpot_tui_quit_requested")
        self.exit()


async def run_tui(
    event_bus: EventBus,
    memory_store: MemoryStore,
    stats_aggregator: StatsAggregator,
) -> None:
    """
    Run the CyberPot TUI application.

    Args:
        event_bus: EventBus for subscribing to events
        memory_store: Memory store for querying data
        stats_aggregator: Statistics aggregator
    """
    app = CyberPotApp(
        event_bus=event_bus,
        memory_store=memory_store,
        stats_aggregator=stats_aggregator,
    )

    logger.info("starting_tui")

    try:
        await app.run_async()
    except Exception as e:
        logger.error("tui_error", error=str(e), exc_info=True)
        raise
    finally:
        logger.info("tui_stopped")
