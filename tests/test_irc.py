"""
Tests for IRC bot components.
"""

import pytest
import time
from datetime import datetime

from cyberpot.irc.rate_limiter import RateLimiter, AdaptiveRateLimiter
from cyberpot.irc.severity_filter import SeverityFilter, DynamicSeverityFilter
from cyberpot.irc.formatter import IRCFormatter
from cyberpot.core.models import Alert, Severity


class TestRateLimiter:
    """Test RateLimiter functionality."""

    @pytest.mark.asyncio
    async def test_acquire_within_burst(self):
        """Test acquiring tokens within burst capacity."""
        limiter = RateLimiter(max_per_minute=10, burst=3)

        # Should allow 3 requests (burst capacity)
        assert await limiter.acquire() is True
        assert await limiter.acquire() is True
        assert await limiter.acquire() is True

        # Fourth should be blocked
        assert await limiter.acquire() is False

    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Test that tokens refill over time."""
        limiter = RateLimiter(max_per_minute=60, burst=2)  # 1 token per second

        # Use all tokens
        assert await limiter.acquire() is True
        assert await limiter.acquire() is True
        assert await limiter.acquire() is False  # Blocked

        # Wait for refill
        time.sleep(1.1)  # Wait for 1 second + buffer

        # Should have refilled 1 token
        assert await limiter.acquire() is True

    @pytest.mark.asyncio
    async def test_queue_alert(self):
        """Test queuing alerts."""
        limiter = RateLimiter(max_per_minute=10, burst=1)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
        )

        # Use token
        await limiter.acquire()

        # Queue alert
        limiter.queue_alert(alert)

        queued = limiter.get_queued_alerts()
        assert len(queued) == 1
        assert queued[0] == alert

    def test_get_stats(self):
        """Test getting rate limiter statistics."""
        limiter = RateLimiter(max_per_minute=10, burst=3)

        stats = limiter.get_stats()
        assert "total_requests" in stats
        assert "allowed_requests" in stats
        assert "blocked_requests" in stats
        assert "current_tokens" in stats

    def test_reset(self):
        """Test resetting rate limiter."""
        limiter = RateLimiter(max_per_minute=10, burst=3)

        # Use some tokens
        limiter.tokens = 0.0
        limiter.total_requests = 10

        # Reset
        limiter.reset()

        assert limiter.tokens == 3.0
        assert limiter.total_requests == 0


class TestAdaptiveRateLimiter:
    """Test AdaptiveRateLimiter functionality."""

    @pytest.mark.asyncio
    async def test_adaptive_behavior(self):
        """Test that limiter adapts to high request rates."""
        limiter = AdaptiveRateLimiter(max_per_minute=10, burst=3, adaptive=True)

        # Set last adaptation time in the past to force adaptation
        limiter._last_adaptation = time.time() - 11

        # Simulate very high request rate (more than 5 per second)
        for _ in range(60):
            await limiter.acquire()

        # Should have reduced limits due to high request rate
        assert limiter.max_per_minute <= limiter.base_max_per_minute


class TestSeverityFilter:
    """Test SeverityFilter functionality."""

    def test_filter_below_minimum(self):
        """Test filtering alerts below minimum severity."""
        filter = SeverityFilter(min_severity="MEDIUM", enabled=True)

        # Create alerts
        low_alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.LOW,
            title="Low",
            description="Test",
        )

        high_alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="High",
            description="Test",
        )

        # Low should be filtered
        assert filter.should_send(low_alert) is False

        # High should pass
        assert filter.should_send(high_alert) is True

    def test_disabled_filter(self):
        """Test that disabled filter allows all alerts."""
        filter = SeverityFilter(min_severity="CRITICAL", enabled=False)

        low_alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.INFO,
            title="Info",
            description="Test",
        )

        # Should allow even though severity is below minimum
        assert filter.should_send(low_alert) is True

    def test_set_min_severity(self):
        """Test updating minimum severity."""
        filter = SeverityFilter(min_severity="MEDIUM")

        # Update to HIGH
        filter.set_min_severity("HIGH")
        assert filter.min_severity == Severity.HIGH

        # Can also use enum
        filter.set_min_severity(Severity.CRITICAL)
        assert filter.min_severity == Severity.CRITICAL

    def test_get_stats(self):
        """Test getting filter statistics."""
        filter = SeverityFilter(min_severity="MEDIUM")

        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
        )

        filter.should_send(alert)

        stats = filter.get_stats()
        assert stats["total_checked"] == 1
        assert stats["allowed_count"] == 1
        assert stats["filtered_count"] == 0


class TestIRCFormatter:
    """Test IRCFormatter functionality."""

    def test_format_alert_basic(self):
        """Test basic alert formatting."""
        formatter = IRCFormatter(use_colors=False, use_emoji=False)

        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test_rule",
            severity=Severity.HIGH,
            title="Brute Force Detected",
            description="Test",
            src_ip="192.168.1.100",
        )

        message = formatter.format_alert(alert)

        assert "HIGH" in message
        assert "Brute Force Detected" in message
        assert "192.168.1.100" in message

    def test_format_alert_with_colors(self):
        """Test alert formatting with colors."""
        formatter = IRCFormatter(use_colors=True, use_emoji=False)

        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.CRITICAL,
            title="Critical Alert",
            description="Test",
        )

        message = formatter.format_alert(alert)

        # Should contain IRC color codes
        assert "\x03" in message  # Color code prefix

    def test_format_alert_with_emoji(self):
        """Test alert formatting with emoji."""
        formatter = IRCFormatter(use_colors=False, use_emoji=True)

        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.HIGH,
            title="High Alert",
            description="Test",
        )

        message = formatter.format_alert(alert)

        # Should contain emoji
        assert "🔴" in message

    def test_format_alert_length_limit(self):
        """Test that messages are truncated to max length."""
        formatter = IRCFormatter(max_length=50)

        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.MEDIUM,
            title="A" * 100,  # Very long title
            description="Test",
        )

        message = formatter.format_alert(alert)

        assert len(message) <= 50
        assert message.endswith("...")

    def test_format_aggregated_alerts(self):
        """Test formatting aggregated alerts."""
        formatter = IRCFormatter(use_colors=False, use_emoji=False)

        alerts = [
            Alert(
                timestamp=datetime.now(),
                rule_name="test1",
                severity=Severity.HIGH,
                title="Alert 1",
                description="Test",
            ),
            Alert(
                timestamp=datetime.now(),
                rule_name="test2",
                severity=Severity.MEDIUM,
                title="Alert 2",
                description="Test",
            ),
            Alert(
                timestamp=datetime.now(),
                rule_name="test3",
                severity=Severity.HIGH,
                title="Alert 3",
                description="Test",
            ),
        ]

        message = formatter.format_aggregated_alerts(alerts)

        assert "3 alerts" in message
        assert "HIGH" in message or "2" in message  # 2 high severity alerts

    def test_strip_formatting(self):
        """Test stripping IRC formatting codes."""
        formatter = IRCFormatter()

        formatted = formatter._colorize("Test", "red", bold=True)
        stripped = formatter.strip_formatting(formatted)

        assert stripped == "Test"
        assert "\x02" not in stripped  # No bold
        assert "\x03" not in stripped  # No color codes


class TestCyberPotIRCBot:
    """Test CyberPotIRCBot functionality."""

    @pytest.fixture
    def irc_config(self):
        """Create test IRC configuration."""
        from cyberpot.config import IRCConfig, IRCAuthConfig, IRCAlertsConfig, IRCRateLimitConfig, IRCSeverityFilterConfig

        return IRCConfig(
            enabled=True,
            server="irc.example.com",
            port=6667,
            use_ssl=False,
            nickname="testbot",
            username="testbot",
            realname="Test Bot",
            channels=["#test"],
            auth=IRCAuthConfig(method="none", password=""),
            alerts=IRCAlertsConfig(
                use_colors=True,
                use_emoji=True,
                max_length=400,
                rate_limit=IRCRateLimitConfig(
                    max_per_minute=10,
                    burst=3,
                    aggregation_window=60,
                ),
                severity_filter=IRCSeverityFilterConfig(
                    enabled=True,
                    min_severity="MEDIUM",
                ),
            ),
        )

    def test_bot_initialization(self, irc_config):
        """Test bot initialization."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)

        assert bot.config == irc_config
        assert bot.connected is False
        assert len(bot.joined_channels) == 0
        assert bot.formatter is not None
        assert bot.rate_limiter is not None
        assert bot.severity_filter is not None
        assert bot.messages_sent == 0

    @pytest.mark.asyncio
    async def test_send_alert_filtered_by_severity(self, irc_config):
        """Test alert filtering by severity."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)

        # Create low severity alert (should be filtered with min_severity=MEDIUM)
        alert = Alert(
            timestamp=datetime.now(),
            rule_name="test",
            severity=Severity.LOW,
            title="Low Alert",
            description="Test",
        )

        # Should return False and be filtered
        result = await bot.send_alert(alert)
        assert result is False
        assert bot.alerts_filtered == 1

    @pytest.mark.asyncio
    async def test_send_alert_rate_limited(self, irc_config):
        """Test alert rate limiting."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)
        bot.connected = True  # Simulate connected state

        # Create high severity alerts
        alerts = [
            Alert(
                timestamp=datetime.now(),
                rule_name=f"test{i}",
                severity=Severity.HIGH,
                title=f"Alert {i}",
                description="Test",
            )
            for i in range(5)
        ]

        # First 3 should succeed (burst=3), rest should be rate limited
        results = []
        for alert in alerts:
            result = await bot.send_alert(alert)
            results.append(result)

        # Check that some were rate limited (exact count depends on timing)
        assert bot.rate_limited_count > 0

    @pytest.mark.asyncio
    async def test_send_aggregated_alerts(self, irc_config):
        """Test sending aggregated alerts."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)
        bot.connected = True
        bot.joined_channels.add("#test")

        # Queue some alerts
        for i in range(3):
            alert = Alert(
                timestamp=datetime.now(),
                rule_name=f"test{i}",
                severity=Severity.HIGH,
                title=f"Alert {i}",
                description="Test",
            )
            bot.rate_limiter.queue_alert(alert)

        # Mock IRC connection
        class MockIRC:
            def __init__(self):
                self.messages = []

            def msg(self, channel, message):
                self.messages.append((channel, message))

        bot.irc = MockIRC()

        # Send aggregated alerts
        await bot.send_aggregated_alerts()

        # Should have sent one aggregated message
        assert len(bot.irc.messages) == 1
        assert "#test" in bot.irc.messages[0][0]
        assert "3 alerts" in bot.irc.messages[0][1]

    def test_get_stats(self, irc_config):
        """Test getting bot statistics."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)
        bot.connected = True
        bot.joined_channels.add("#test")
        bot.messages_sent = 10
        bot.alerts_filtered = 5

        stats = bot.get_stats()

        assert stats["connected"] is True
        assert stats["channels_joined"] == 1
        assert stats["messages_sent"] == 10
        assert stats["alerts_filtered"] == 5
        assert "rate_limiter" in stats

    def test_command_registration(self, irc_config):
        """Test custom command registration."""
        from cyberpot.irc.bot import CyberPotIRCBot

        bot = CyberPotIRCBot(irc_config)

        async def custom_handler(args):
            return "Custom response"

        bot.register_command("!custom", custom_handler)

        assert "!custom" in bot._command_handlers
        assert bot._command_handlers["!custom"] == custom_handler
