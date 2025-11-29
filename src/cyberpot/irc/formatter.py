"""
IRC message formatter for alerts.

Formats alerts with IRC color codes, emojis, and length constraints.
"""

from typing import List

import structlog

from ..core.models import Alert, CommandEvent, LoginEvent, Severity

logger = structlog.get_logger(__name__)


class IRCFormatter:
    """
    Format alerts for IRC with colors, emojis, and length constraints.

    Uses IRC color codes and mIRC-compatible formatting.
    """

    # IRC color codes
    COLORS = {
        "white": "00",
        "black": "01",
        "blue": "02",
        "green": "03",
        "red": "04",
        "brown": "05",
        "purple": "06",
        "orange": "07",
        "yellow": "08",
        "light_green": "09",
        "cyan": "10",
        "light_cyan": "11",
        "light_blue": "12",
        "pink": "13",
        "grey": "14",
        "light_grey": "15",
    }

    # IRC formatting codes
    BOLD = "\x02"
    ITALIC = "\x1D"
    UNDERLINE = "\x1F"
    RESET = "\x0F"

    # Emoji mappings
    SEVERITY_EMOJI = {
        Severity.INFO: "ℹ️",
        Severity.LOW: "🔵",
        Severity.MEDIUM: "🟡",
        Severity.HIGH: "🔴",
        Severity.CRITICAL: "🚨",
    }

    def __init__(
        self,
        use_colors: bool = True,
        use_emoji: bool = True,
        max_length: int = 400,
    ):
        """
        Initialize formatter.

        Args:
            use_colors: Enable IRC color codes
            use_emoji: Enable emoji in messages
            max_length: Maximum message length (IRC limit is typically 512)
        """
        self.use_colors = use_colors
        self.use_emoji = use_emoji
        self.max_length = max_length

    def format_alert(self, alert: Alert) -> str:
        """
        Format alert for IRC.

        Args:
            alert: Alert to format

        Returns:
            Formatted IRC message
        """
        parts = []

        # Severity indicator
        if self.use_emoji:
            emoji = self.SEVERITY_EMOJI.get(alert.severity, "•")
            parts.append(emoji)

        # Severity text with color
        severity_text = alert.severity.value
        if self.use_colors:
            color = self._get_severity_color(alert.severity)
            severity_text = self._colorize(severity_text, color, bold=True)
        else:
            severity_text = f"{self.BOLD}{severity_text}{self.RESET}"

        parts.append(severity_text)

        # Title
        parts.append(f"- {alert.title}")

        # Source IP with color
        if alert.src_ip:
            ip_text = str(alert.src_ip)
            if self.use_colors:
                ip_text = self._colorize(ip_text, "cyan")
            parts.append(f"| IP: {ip_text}")

        # GeoIP info if available
        if hasattr(alert, "_event") and alert._event and hasattr(alert._event, "geoip"):
            geoip = alert._event.geoip
            if geoip and geoip.country_code:
                location = f"{geoip.country_code}"
                if geoip.city:
                    location += f", {geoip.city}"
                parts.append(f"({location})")

        # Event count for aggregated alerts
        if len(alert.event_ids) > 1:
            parts.append(f"| {len(alert.event_ids)} events")

        # Additional context based on alert type
        context = self._get_alert_context(alert)
        if context:
            parts.append(f"| {context}")

        # Threat intel indicator
        if hasattr(alert, "_event") and alert._event and hasattr(alert._event, "threat_intel"):
            threat = alert._event.threat_intel
            if threat and threat.is_malicious:
                if self.use_emoji:
                    parts.append("🚨")
                parts.append("Known Threat")

        # Construct message
        message = " ".join(parts)

        # Truncate if too long
        if len(message) > self.max_length:
            message = message[: self.max_length - 3] + "..."

        return message

    def format_aggregated_alerts(self, alerts: List[Alert]) -> str:
        """
        Format aggregated alerts summary.

        Args:
            alerts: List of alerts to aggregate

        Returns:
            Formatted summary message
        """
        if not alerts:
            return ""

        # Count by severity
        severity_counts = {s: 0 for s in Severity}
        for alert in alerts:
            severity_counts[alert.severity] += 1

        parts = []

        # Header
        if self.use_emoji:
            parts.append("📊")

        header = f"Alert Summary - {len(alerts)} alerts aggregated:"
        if self.use_colors:
            header = self._colorize(header, "orange", bold=True)
        else:
            header = f"{self.BOLD}{header}{self.RESET}"
        parts.append(header)

        # Severity breakdown
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[severity]
            if count > 0:
                if self.use_emoji:
                    emoji = self.SEVERITY_EMOJI.get(severity, "•")
                    parts.append(f"{emoji} {count}")
                else:
                    parts.append(f"{severity.value}: {count}")

        message = " ".join(parts)

        # Truncate if needed
        if len(message) > self.max_length:
            message = message[: self.max_length - 3] + "..."

        return message

    def _get_alert_context(self, alert: Alert) -> str:
        """
        Get additional context based on alert type.

        Args:
            alert: Alert to get context for

        Returns:
            Context string
        """
        # Try to get associated event
        if not hasattr(alert, "_event") or not alert._event:
            return ""

        event = alert._event

        # Login events
        if isinstance(event, LoginEvent):
            context = f"User: {event.username}"
            if event.password:
                context += f"/{event.password}"
            return context

        # Command events
        if isinstance(event, CommandEvent):
            cmd = event.command[:50]
            if len(event.command) > 50:
                cmd += "..."
            return f"Cmd: {cmd}"

        return ""

    def _get_severity_color(self, severity: Severity) -> str:
        """
        Get IRC color for severity level.

        Args:
            severity: Severity level

        Returns:
            IRC color name
        """
        color_map = {
            Severity.INFO: "blue",
            Severity.LOW: "cyan",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "orange",
            Severity.CRITICAL: "red",
        }
        return color_map.get(severity, "white")

    def _colorize(self, text: str, color: str, bold: bool = False) -> str:
        """
        Apply IRC color codes to text.

        Args:
            text: Text to colorize
            color: Color name
            bold: Apply bold formatting

        Returns:
            Colorized text with IRC codes
        """
        color_code = self.COLORS.get(color, "00")
        formatted = f"\x03{color_code}{text}{self.RESET}"

        if bold:
            formatted = f"{self.BOLD}{formatted}"

        return formatted

    def format_stats_response(self, stats: dict) -> str:
        """
        Format statistics for IRC command response.

        Args:
            stats: Statistics dictionary

        Returns:
            Formatted stats message
        """
        parts = []

        if self.use_emoji:
            parts.append("📊")

        parts.append("Stats:")

        for key, value in stats.items():
            if isinstance(value, (int, float)):
                parts.append(f"{key}: {value}")

        message = " | ".join(parts)

        if len(message) > self.max_length:
            message = message[: self.max_length - 3] + "..."

        return message

    def strip_formatting(self, text: str) -> str:
        """
        Strip all IRC formatting codes from text.

        Args:
            text: Text with formatting

        Returns:
            Plain text
        """
        import re

        result = text

        # Remove color codes with numbers first (format: \x03NN or \x03NN,NN)
        result = re.sub(r"\x03\d{1,2}(,\d{1,2})?", "", result)

        # Remove remaining formatting codes
        for code in [self.BOLD, self.ITALIC, self.UNDERLINE, self.RESET, "\x03"]:
            result = result.replace(code, "")

        return result
