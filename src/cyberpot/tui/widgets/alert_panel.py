"""
Alert panel widget for displaying recent alerts.

Shows a list of recent alerts with severity indicators and acknowledgment status.
"""

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static, ListView, ListItem, Label
from textual.containers import ScrollableContainer

from ...core.models import Alert, Severity


class AlertListItem(ListItem):
    """Individual alert list item with formatting."""

    def __init__(self, alert: Alert):
        """
        Initialize alert list item.

        Args:
            alert: Alert to display
        """
        self.alert = alert
        super().__init__()

    def compose(self):
        """Compose the list item."""
        yield Label(self._format_alert())

    def _format_alert(self) -> Text:
        """Format alert as rich text with colors."""
        text = Text()

        # Timestamp
        time_str = self.alert.timestamp.strftime("%H:%M:%S")
        text.append(f"[{time_str}] ", style="dim")

        # Severity icon and color
        icon, color = self._get_severity_style()
        text.append(f"{icon} ", style=color)
        text.append(f"{self.alert.severity.value:8s}", style=color)

        # Title
        text.append(f" {self.alert.title}", style="bold white")

        # Source IP if available
        if self.alert.src_ip:
            text.append(f" ({self.alert.src_ip})", style="cyan")

        # Acknowledged indicator
        if self.alert.acknowledged:
            text.append(" ✓", style="green")

        return text

    def _get_severity_style(self) -> tuple[str, str]:
        """Get icon and color for severity level."""
        styles = {
            Severity.INFO: ("ℹ", "blue"),
            Severity.LOW: ("🔵", "cyan"),
            Severity.MEDIUM: ("🟡", "yellow"),
            Severity.HIGH: ("🔴", "red"),
            Severity.CRITICAL: ("🚨", "red bold"),
        }
        return styles.get(self.alert.severity, ("•", "white"))


class AlertPanel(ScrollableContainer):
    """
    Alert panel widget showing recent alerts.
    """

    def __init__(
        self,
        max_alerts: int = 50,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize alert panel.

        Args:
            max_alerts: Maximum number of alerts to display
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.max_alerts = max_alerts
        self._alert_items: list[AlertListItem] = []

    def compose(self):
        """Compose the alert panel."""
        yield Label("No alerts yet", id="no-alerts-label")

    def add_alert(self, alert: Alert) -> None:
        """
        Add alert to panel.

        Args:
            alert: Alert to add
        """
        # Remove "no alerts" label if present
        try:
            self.query_one("#no-alerts-label").remove()
        except:
            pass

        # Create list item
        item = AlertListItem(alert)

        # Add to top of container (most recent first)
        if self._alert_items:
            self.mount(item, before=self._alert_items[0])
            self._alert_items.insert(0, item)
        else:
            self.mount(item)
            self._alert_items.append(item)

        # Trim old alerts
        if len(self._alert_items) > self.max_alerts:
            old_item = self._alert_items.pop()
            old_item.remove()

    def clear_alerts(self) -> None:
        """Clear all alerts from panel."""
        for item in self._alert_items:
            item.remove()
        self._alert_items.clear()

        # Show "no alerts" label
        self.mount(Label("No alerts", id="no-alerts-label"))

    def get_alert_count(self) -> int:
        """Get current alert count."""
        return len(self._alert_items)


class AlertSummary(Static):
    """
    Summary statistics for alerts.
    """

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize alert summary."""
        super().__init__(name=name, id=id, classes=classes)
        self._total = 0
        self._by_severity = {s: 0 for s in Severity}

    def add_alert(self, alert: Alert) -> None:
        """Record an alert."""
        self._total += 1
        self._by_severity[alert.severity] += 1
        self.update(self._render_summary())

    def _render_summary(self) -> Text:
        """Render alert summary."""
        text = Text("Alert Summary\n", style="bold underline")
        text.append(f"Total: {self._total}\n", style="white")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = self._by_severity[severity]
            if count > 0:
                icon = {
                    Severity.CRITICAL: "🚨",
                    Severity.HIGH: "🔴",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                    Severity.INFO: "ℹ",
                }[severity]

                color = {
                    Severity.CRITICAL: "red bold",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "cyan",
                    Severity.INFO: "blue",
                }[severity]

                text.append(f"{icon} {severity.value}: ", style=color)
                text.append(f"{count}\n", style="white")

        return text
