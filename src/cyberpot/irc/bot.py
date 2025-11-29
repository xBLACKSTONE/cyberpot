"""
IRC bot for sending honeypot alerts to IRC channels.

Uses miniirc for IRC protocol handling with automatic reconnection.
"""

import asyncio
from typing import Dict, List, Optional

import miniirc
import structlog

from ..config import IRCConfig
from ..core.models import Alert
from .formatter import IRCFormatter
from .rate_limiter import RateLimiter
from .severity_filter import SeverityFilter

logger = structlog.get_logger(__name__)


class CyberPotIRCBot:
    """
    IRC bot for sending honeypot alerts.

    Features:
    - Automatic connection and reconnection
    - Rate limiting to prevent flooding
    - Severity filtering
    - Channel management
    - IRC commands (!stats, !sessions, !alerts)
    """

    def __init__(self, config: IRCConfig):
        """
        Initialize IRC bot.

        Args:
            config: IRC configuration
        """
        self.config = config
        self.irc: Optional[miniirc.IRC] = None
        self.connected = False
        self.joined_channels: set[str] = set()

        # Components
        self.formatter = IRCFormatter(
            use_colors=config.alerts.use_colors,
            use_emoji=config.alerts.use_emoji,
            max_length=config.alerts.max_length,
        )

        self.rate_limiter = RateLimiter(
            max_per_minute=config.alerts.rate_limit.max_per_minute,
            burst=config.alerts.rate_limit.burst,
            aggregation_window=config.alerts.rate_limit.aggregation_window,
        )

        self.severity_filter = SeverityFilter(
            min_severity=config.alerts.severity_filter.min_severity,
            enabled=config.alerts.severity_filter.enabled,
        )

        # Statistics
        self.messages_sent = 0
        self.alerts_filtered = 0
        self.rate_limited_count = 0

        # Command handlers (for future expansion)
        self._command_handlers: Dict[str, callable] = {}

        logger.info(
            "irc_bot_initialized",
            server=config.server,
            port=config.port,
            channels=config.channels,
        )

    async def connect(self) -> None:
        """Connect to IRC server."""
        try:
            # Create IRC connection
            self.irc = miniirc.IRC(
                ip=self.config.server,
                port=self.config.port,
                nick=self.config.nickname,
                ident=self.config.username,
                realname=self.config.realname,
                ssl=self.config.use_ssl,
                persist=True,  # Auto-reconnect
                debug=False,
            )

            # Register event handlers
            @self.irc.Handler("001")  # RPL_WELCOME
            def handle_welcome(irc, hostmask, args):
                self.connected = True
                logger.info("irc_connected", server=self.config.server)

                # Authenticate if configured
                if self.config.auth.method == "nickserv" and self.config.auth.password:
                    irc.msg("NickServ", f"IDENTIFY {self.config.auth.password}")
                    logger.info("irc_auth_sent", method="nickserv")

                # Join channels
                for channel in self.config.channels:
                    irc.join(channel)
                    logger.info("irc_joining_channel", channel=channel)

            @self.irc.Handler("JOIN")
            def handle_join(irc, hostmask, args):
                channel = args[0]
                nick = hostmask[0]

                if nick == self.config.nickname:
                    self.joined_channels.add(channel)
                    logger.info("irc_channel_joined", channel=channel)

            @self.irc.Handler("PRIVMSG")
            def handle_privmsg(irc, hostmask, args):
                channel = args[0]
                message = args[1]

                # Handle commands (if message starts with !)
                if message.startswith("!"):
                    asyncio.create_task(self._handle_command(channel, message, hostmask[0]))

            @self.irc.Handler("DISCONNECT")
            def handle_disconnect(irc, *args):
                self.connected = False
                self.joined_channels.clear()
                logger.warning("irc_disconnected", server=self.config.server)

            logger.info("irc_connecting", server=self.config.server, port=self.config.port)

        except Exception as e:
            logger.error("irc_connect_error", error=str(e), exc_info=True)
            raise

    async def disconnect(self) -> None:
        """Disconnect from IRC server."""
        if self.irc:
            try:
                self.irc.disconnect()
                logger.info("irc_disconnect_requested")
            except Exception as e:
                logger.error("irc_disconnect_error", error=str(e))

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert to IRC channels.

        Args:
            alert: Alert to send

        Returns:
            True if alert was sent, False if filtered or rate limited
        """
        # Check severity filter
        if not self.severity_filter.should_send(alert):
            self.alerts_filtered += 1
            logger.debug("alert_filtered_by_severity", severity=alert.severity.value)
            return False

        # Check rate limiter
        if not await self.rate_limiter.acquire():
            self.rate_limited_count += 1
            # Queue for aggregation
            self.rate_limiter.queue_alert(alert)
            logger.debug("alert_rate_limited", rule=alert.rule_name)
            return False

        # Format alert message
        message = self.formatter.format_alert(alert)

        # Send to all channels
        success = await self._send_to_channels(message)

        if success:
            self.messages_sent += 1
            # Mark alert as sent to IRC
            alert.sent_to_irc = True

        return success

    async def send_aggregated_alerts(self) -> None:
        """Send aggregated alerts summary."""
        queued_alerts = self.rate_limiter.get_queued_alerts()

        if not queued_alerts:
            return

        # Format aggregated message
        message = self.formatter.format_aggregated_alerts(queued_alerts)

        # Send to channels
        await self._send_to_channels(message)
        self.messages_sent += 1

        logger.info("aggregated_alerts_sent", count=len(queued_alerts))

    async def _send_to_channels(self, message: str) -> bool:
        """
        Send message to all configured channels.

        Args:
            message: Message to send

        Returns:
            True if sent successfully
        """
        if not self.connected or not self.irc:
            logger.warning("irc_not_connected_skipping_message")
            return False

        try:
            for channel in self.config.channels:
                if channel in self.joined_channels:
                    self.irc.msg(channel, message)
                    logger.debug("irc_message_sent", channel=channel)
                else:
                    logger.warning("irc_channel_not_joined", channel=channel)

            return True

        except Exception as e:
            logger.error("irc_send_error", error=str(e), exc_info=True)
            return False

    async def _handle_command(self, channel: str, message: str, sender: str) -> None:
        """
        Handle IRC commands.

        Args:
            channel: Channel where command was issued
            message: Command message
            sender: User who sent command
        """
        parts = message.split()
        command = parts[0].lower()

        logger.info("irc_command_received", command=command, sender=sender, channel=channel)

        # Built-in commands
        if command == "!help":
            response = (
                "CyberPot Commands: !help, !stats, !status - "
                "For more info: https://github.com/cyberpot"
            )
            self.irc.msg(channel, response)

        elif command == "!stats":
            response = self._get_stats_summary()
            self.irc.msg(channel, response)

        elif command == "!status":
            response = f"Bot Status: Connected to {self.config.server} | " \
                      f"Messages sent: {self.messages_sent} | " \
                      f"Rate limited: {self.rate_limited_count}"
            self.irc.msg(channel, response)

        else:
            # Check custom command handlers
            handler = self._command_handlers.get(command)
            if handler:
                try:
                    response = await handler(parts[1:] if len(parts) > 1 else [])
                    if response:
                        self.irc.msg(channel, response)
                except Exception as e:
                    logger.error("command_handler_error", command=command, error=str(e))

    def register_command(self, command: str, handler: callable) -> None:
        """
        Register custom command handler.

        Args:
            command: Command name (e.g., "!custom")
            handler: Async function that returns response string
        """
        self._command_handlers[command] = handler
        logger.info("command_registered", command=command)

    def _get_stats_summary(self) -> str:
        """Get bot statistics summary."""
        return (
            f"IRC Bot Stats: "
            f"{self.messages_sent} messages sent | "
            f"{self.alerts_filtered} alerts filtered | "
            f"{self.rate_limited_count} rate limited"
        )

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "connected": self.connected,
            "channels_joined": len(self.joined_channels),
            "messages_sent": self.messages_sent,
            "alerts_filtered": self.alerts_filtered,
            "rate_limited_count": self.rate_limited_count,
            "rate_limiter": self.rate_limiter.get_stats(),
        }


async def run_irc_bot(config: IRCConfig, alert_callback_register: callable) -> CyberPotIRCBot:
    """
    Run IRC bot and register it for alert callbacks.

    Args:
        config: IRC configuration
        alert_callback_register: Function to register alert callback

    Returns:
        Running IRC bot instance
    """
    bot = CyberPotIRCBot(config)

    # Connect to IRC
    await bot.connect()

    # Register for alert callbacks
    async def handle_alert(alert: Alert) -> None:
        await bot.send_alert(alert)

    alert_callback_register(handle_alert)

    # Start aggregation loop
    asyncio.create_task(_aggregation_loop(bot))

    logger.info("irc_bot_running")

    return bot


async def _aggregation_loop(bot: CyberPotIRCBot) -> None:
    """Background task to send aggregated alerts periodically."""
    while True:
        try:
            await asyncio.sleep(bot.config.alerts.rate_limit.aggregation_window)
            await bot.send_aggregated_alerts()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("aggregation_loop_error", error=str(e), exc_info=True)
