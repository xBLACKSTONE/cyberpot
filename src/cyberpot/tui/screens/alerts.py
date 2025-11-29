"""
Alert management screen.
"""

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable

from ...core.models import Severity
from ...storage.memory_store import MemoryStore


class AlertsScreen(Screen):
    """
    Screen for managing and viewing alerts.
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("u", "show_unacked", "Unacknowledged Only"),
        ("a", "ack_selected", "Acknowledge"),
    ]

    def __init__(
        self,
        memory_store: MemoryStore,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize alerts screen.

        Args:
            memory_store: Memory store for querying alerts
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.memory_store = memory_store
        self._show_unacked_only = False

    def compose(self) -> ComposeResult:
        """Compose the alerts layout."""
        yield Header()

        with Container(id="alerts-container"):
            yield Static("Alert Management", classes="screen-title")

            # Alert statistics
            yield Static(id="alert-stats")

            # Alerts table
            yield DataTable(id="alerts-table")

        yield Footer()

    def on_mount(self) -> None:
        """Called when screen is mounted."""
        # Setup table
        table = self.query_one("#alerts-table", DataTable)
        table.add_columns(
            "Severity",
            "Time",
            "Rule",
            "Title",
            "Source IP",
            "Status",
        )

        # Load alerts
        self.action_refresh()

    def action_refresh(self) -> None:
        """Refresh alerts list."""
        # Get alerts
        if self._show_unacked_only:
            alerts = self.memory_store.alerts.get_unacknowledged()
        else:
            alerts = self.memory_store.alerts.get_all()

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        # Update table
        table = self.query_one("#alerts-table", DataTable)
        table.clear()

        for alert in alerts[:100]:  # Limit to 100 alerts
            severity_icon = {
                Severity.INFO: "ℹ",
                Severity.LOW: "🔵",
                Severity.MEDIUM: "🟡",
                Severity.HIGH: "🔴",
                Severity.CRITICAL: "🚨",
            }[alert.severity]

            status = "✓ Acked" if alert.acknowledged else "Pending"

            table.add_row(
                f"{severity_icon} {alert.severity.value}",
                alert.timestamp.strftime("%H:%M:%S"),
                alert.rule_name,
                alert.title[:40],
                str(alert.src_ip) if alert.src_ip else "N/A",
                status,
            )

        # Update stats
        total = len(self.memory_store.alerts.get_all())
        unacked = len(self.memory_store.alerts.get_unacknowledged())
        self.query_one("#alert-stats", Static).update(
            f"Total: {total} | Unacknowledged: {unacked}"
        )

    def action_show_unacked(self) -> None:
        """Toggle showing unacknowledged alerts only."""
        self._show_unacked_only = not self._show_unacked_only
        self.action_refresh()

    def action_ack_selected(self) -> None:
        """Acknowledge selected alert."""
        # TODO: Implement alert acknowledgment
        pass
