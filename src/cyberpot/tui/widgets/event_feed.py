"""
Event feed widget for displaying live honeypot events.

Shows a scrollable list of recent events with color coding by type and severity.
"""

from datetime import datetime
from typing import List

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import ListView, ListItem, Label
from textual.containers import ScrollableContainer

from ...core.models import (
    CommandEvent,
    Event,
    EventType,
    FileDownloadEvent,
    LoginEvent,
)


class EventListItem(ListItem):
    """Individual event list item with formatting."""

    def __init__(self, event: Event):
        """
        Initialize event list item.

        Args:
            event: Event to display
        """
        self.event = event
        super().__init__()

    def compose(self):
        """Compose the list item."""
        yield Label(self._format_event())

    def _format_event(self) -> Text:
        """Format event as rich text with colors."""
        text = Text()

        # Timestamp
        time_str = self.event.timestamp.strftime("%H:%M:%S")
        text.append(f"[{time_str}] ", style="dim")

        # Event type icon and color
        icon, color = self._get_event_style()
        text.append(f"{icon} ", style=color)

        # Source IP
        text.append(f"{self.event.src_ip}", style="cyan")

        # GeoIP info
        if self.event.geoip and self.event.geoip.country_code:
            text.append(f" ({self.event.geoip.country_code})", style="dim cyan")

        text.append(" - ", style="dim")

        # Event-specific details
        if isinstance(self.event, LoginEvent):
            status = "✓" if self.event.success else "✗"
            style = "green" if self.event.success else "red"
            text.append(f"{status} ", style=style)
            text.append(f"{self.event.username}:", style="yellow")
            text.append(f"{self.event.password or '***'}", style="dim yellow")

        elif isinstance(self.event, CommandEvent):
            marker = "⚠" if self.event.is_suspicious else "$"
            style = "red" if self.event.is_suspicious else "white"
            text.append(f"{marker} ", style=style)

            if self.event.command_category:
                text.append(f"[{self.event.command_category}] ", style="magenta")

            # Truncate long commands
            cmd = self.event.command[:80]
            if len(self.event.command) > 80:
                cmd += "..."
            text.append(cmd, style=style)

        elif isinstance(self.event, FileDownloadEvent):
            marker = "⚠ MALWARE" if self.event.is_malware else "📥 FILE"
            style = "red bold" if self.event.is_malware else "blue"
            text.append(marker, style=style)
            text.append(f": {self.event.url[:60]}", style="blue")

        else:
            text.append(self.event.event_type.value, style="white")

        # Threat intel indicator
        if self.event.threat_intel and self.event.threat_intel.is_malicious:
            text.append(" 🚨", style="red bold")

        return text

    def _get_event_style(self) -> tuple[str, str]:
        """Get icon and color for event type."""
        styles = {
            EventType.LOGIN_SUCCESS: ("🔓", "green"),
            EventType.LOGIN_FAILED: ("🔒", "red"),
            EventType.COMMAND_EXECUTION: ("$", "yellow"),
            EventType.FILE_DOWNLOAD: ("📥", "blue"),
            EventType.SESSION_START: ("🔌", "green"),
            EventType.SESSION_END: ("🔌", "dim"),
            EventType.CLIENT_INFO: ("ℹ", "cyan"),
            EventType.PORT_FORWARD: ("🔀", "magenta"),
        }
        return styles.get(self.event.event_type, ("•", "white"))


class EventFeed(ScrollableContainer):
    """
    Scrollable event feed widget.

    Displays live stream of honeypot events with auto-scroll.
    """

    events: reactive[List[Event]] = reactive(list, init=False)
    auto_scroll: reactive[bool] = reactive(True)

    def __init__(
        self,
        max_events: int = 100,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize event feed.

        Args:
            max_events: Maximum number of events to display
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.max_events = max_events
        self._event_items: List[EventListItem] = []

    def compose(self):
        """Compose the event feed."""
        # Events will be added dynamically
        yield Label("Waiting for events...", id="no-events-label")

    def add_event(self, event: Event) -> None:
        """
        Add event to feed.

        Args:
            event: Event to add
        """
        # Remove "no events" label if present
        try:
            self.query_one("#no-events-label").remove()
        except:
            pass

        # Create list item
        item = EventListItem(event)

        # Add to container
        self.mount(item)
        self._event_items.append(item)

        # Trim old events
        if len(self._event_items) > self.max_events:
            old_item = self._event_items.pop(0)
            old_item.remove()

        # Auto-scroll to bottom
        if self.auto_scroll:
            self.scroll_end(animate=False)

    def clear_events(self) -> None:
        """Clear all events from feed."""
        for item in self._event_items:
            item.remove()
        self._event_items.clear()

        # Show "no events" label
        self.mount(Label("No events", id="no-events-label"))

    def toggle_auto_scroll(self) -> None:
        """Toggle auto-scroll."""
        self.auto_scroll = not self.auto_scroll

    def get_event_count(self) -> int:
        """Get current event count."""
        return len(self._event_items)
