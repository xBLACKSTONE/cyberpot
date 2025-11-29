"""
Statistics display widgets for the TUI.

Shows real-time statistics including counters, rates, and top-N lists.
"""

from rich.table import Table
from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from ...core.models import Statistics


class StatsOverview(Static):
    """
    Overview statistics widget showing key metrics.
    """

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize stats overview."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_stats(stats))

    def _render_stats(self, stats: Statistics) -> Table:
        """Render statistics as a table."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white")

        table.add_row("Total Events", f"{stats.total_events:,}")
        table.add_row("Total Sessions", f"{stats.total_sessions:,}")
        table.add_row("Active Sessions", f"{stats.active_sessions:,}", style="green")
        table.add_row("Total Alerts", f"{stats.total_alerts:,}")
        table.add_row("")
        table.add_row("Events/sec", f"{stats.events_per_second:.2f}")
        table.add_row("Sessions/hour", f"{stats.sessions_per_hour:.1f}")

        return table


class TopIPsWidget(Static):
    """Widget showing top attacker IPs."""

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize top IPs widget."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_top_ips(stats))

    def _render_top_ips(self, stats: Statistics) -> Table:
        """Render top IPs as a table."""
        table = Table(title="Top Attackers", box=None, padding=(0, 1))
        table.add_column("#", style="dim", width=3)
        table.add_column("IP Address", style="cyan")
        table.add_column("Count", justify="right", style="yellow")

        if not stats.top_ips:
            table.add_row("", "No data yet", "")
        else:
            for i, (ip, count) in enumerate(stats.top_ips[:10], 1):
                table.add_row(str(i), ip, str(count))

        return table


class TopCountriesWidget(Static):
    """Widget showing top source countries."""

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize top countries widget."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_top_countries(stats))

    def _render_top_countries(self, stats: Statistics) -> Table:
        """Render top countries as a table."""
        table = Table(title="Top Countries", box=None, padding=(0, 1))
        table.add_column("#", style="dim", width=3)
        table.add_column("Country", style="cyan")
        table.add_column("Count", justify="right", style="yellow")

        if not stats.top_countries:
            table.add_row("", "No data yet", "")
        else:
            for i, (country, count) in enumerate(stats.top_countries[:10], 1):
                # Add flag emoji if possible
                flag = self._get_flag_emoji(country)
                country_display = f"{flag} {country}" if flag else country
                table.add_row(str(i), country_display, str(count))

        return table

    def _get_flag_emoji(self, country_code: str) -> str:
        """Get flag emoji for country code."""
        # Unicode regional indicator symbols
        if len(country_code) != 2:
            return ""

        try:
            # Convert country code to flag emoji
            # A = U+1F1E6, B = U+1F1E7, etc.
            code_points = [ord(c) - ord('A') + 0x1F1E6 for c in country_code.upper()]
            return ''.join(chr(c) for c in code_points)
        except:
            return ""


class TopCredentialsWidget(Static):
    """Widget showing top attempted credentials."""

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize top credentials widget."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_credentials(stats))

    def _render_credentials(self, stats: Statistics) -> Table:
        """Render top credentials as a table."""
        table = Table(title="Top Credentials", box=None, padding=(0, 1))
        table.add_column("Username", style="yellow", width=15)
        table.add_column("Password", style="dim yellow", width=15)
        table.add_column("Count", justify="right", style="cyan", width=6)

        if not stats.top_usernames:
            table.add_row("No data yet", "", "")
        else:
            # Show top 5 usernames and passwords
            for i in range(min(5, len(stats.top_usernames))):
                username, u_count = stats.top_usernames[i] if i < len(stats.top_usernames) else ("", 0)
                password, p_count = stats.top_passwords[i] if i < len(stats.top_passwords) else ("", 0)

                # Truncate long values
                username = username[:15] if username else ""
                password = password[:15] if password else ""

                count = max(u_count, p_count)
                table.add_row(username, password, str(count))

        return table


class TopCommandsWidget(Static):
    """Widget showing top executed commands."""

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize top commands widget."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_commands(stats))

    def _render_commands(self, stats: Statistics) -> Table:
        """Render top commands as a table."""
        table = Table(title="Top Commands", box=None, padding=(0, 1))
        table.add_column("Command", style="green", no_wrap=False)
        table.add_column("Count", justify="right", style="yellow", width=6)

        if not stats.top_commands:
            table.add_row("No data yet", "")
        else:
            for command, count in stats.top_commands[:10]:
                # Truncate long commands
                cmd_display = command[:50]
                if len(command) > 50:
                    cmd_display += "..."

                table.add_row(cmd_display, str(count))

        return table


class EventTypeBreakdown(Static):
    """Widget showing breakdown of events by type."""

    stats: reactive[Statistics | None] = reactive(None)

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize event type breakdown widget."""
        super().__init__(name=name, id=id, classes=classes)

    def watch_stats(self, stats: Statistics | None) -> None:
        """Update display when stats change."""
        if stats:
            self.update(self._render_breakdown(stats))

    def _render_breakdown(self, stats: Statistics) -> Table:
        """Render event breakdown as a table."""
        table = Table(title="Event Types", box=None, padding=(0, 1))
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Bar", style="blue")

        if not stats.events_by_type:
            table.add_row("No data yet", "", "")
        else:
            # Calculate max for bar chart
            max_count = max(stats.events_by_type.values()) if stats.events_by_type else 1

            for event_type, count in sorted(
                stats.events_by_type.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                # Create simple bar chart
                bar_length = int((count / max_count) * 20)
                bar = "█" * bar_length

                # Shorten event type name
                type_name = event_type.replace("_", " ").title()

                table.add_row(type_name, str(count), bar)

        return table
