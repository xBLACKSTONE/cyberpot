"""
Session list and detail screens.

Shows list of sessions and detailed information about individual sessions.
"""

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable

from ...storage.memory_store import MemoryStore
from ...storage.statistics import StatsAggregator


class SessionListScreen(Screen):
    """
    Screen showing list of honeypot sessions.
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("a", "show_active", "Active Only"),
    ]

    def __init__(
        self,
        memory_store: MemoryStore,
        stats_aggregator: StatsAggregator,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize session list screen.

        Args:
            memory_store: Memory store for querying sessions
            stats_aggregator: Statistics aggregator
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.memory_store = memory_store
        self.stats_aggregator = stats_aggregator
        self._show_active_only = False

    def compose(self) -> ComposeResult:
        """Compose the session list layout."""
        yield Header()

        with Container(id="session-container"):
            yield Static("Honeypot Sessions", classes="screen-title")

            # Session statistics
            with Horizontal(id="session-stats"):
                yield Static(id="total-sessions")
                yield Static(id="active-sessions")

            # Session table
            yield DataTable(id="session-table")

        yield Footer()

    def on_mount(self) -> None:
        """Called when screen is mounted."""
        # Setup table
        table = self.query_one("#session-table", DataTable)
        table.add_columns(
            "Session ID",
            "Source IP",
            "Country",
            "Start Time",
            "Duration",
            "Logins",
            "Commands",
            "Status",
        )

        # Load sessions
        self.action_refresh()

    def action_refresh(self) -> None:
        """Refresh session list."""
        # Get sessions
        if self._show_active_only:
            sessions = self.memory_store.sessions.get_active()
        else:
            sessions = self.memory_store.sessions.get_all()

        # Sort by start time (newest first)
        sessions.sort(key=lambda s: s.start_time, reverse=True)

        # Update table
        table = self.query_one("#session-table", DataTable)
        table.clear()

        for session in sessions[:100]:  # Limit to 100 sessions
            duration = f"{session.duration:.1f}s" if session.duration else "active"
            country = session.geoip.country_code if session.geoip else "??"
            status = "active" if session.end_time is None else "ended"

            table.add_row(
                session.session_id[:12],
                str(session.src_ip),
                country,
                session.start_time.strftime("%H:%M:%S"),
                duration,
                str(session.login_attempts),
                str(len(session.commands)),
                status,
            )

        # Update stats
        stats = self.stats_aggregator.get_current_stats()
        self.query_one("#total-sessions", Static).update(f"Total: {stats.total_sessions}")
        self.query_one("#active-sessions", Static).update(
            f"Active: {stats.active_sessions}"
        )

    def action_show_active(self) -> None:
        """Toggle showing active sessions only."""
        self._show_active_only = not self._show_active_only
        self.action_refresh()
