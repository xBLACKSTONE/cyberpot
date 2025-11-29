"""
Rate limiter for IRC messages using token bucket algorithm.

Prevents flooding IRC channels with too many messages.
"""

import asyncio
import time
from collections import deque
from typing import List

import structlog

from ..core.models import Alert

logger = structlog.get_logger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter for IRC messages.

    Implements a token bucket algorithm to limit message rate while allowing bursts.
    Queues excess alerts for aggregation.
    """

    def __init__(
        self,
        max_per_minute: int = 10,
        burst: int = 3,
        aggregation_window: int = 60,
    ):
        """
        Initialize rate limiter.

        Args:
            max_per_minute: Maximum messages per minute
            burst: Maximum burst capacity (tokens available initially)
            aggregation_window: Time window for aggregating queued alerts (seconds)
        """
        self.max_per_minute = max_per_minute
        self.burst = burst
        self.aggregation_window = aggregation_window

        # Token bucket
        self.tokens = float(burst)
        self.last_refill = time.time()

        # Queued alerts waiting for aggregation
        self._queued_alerts: deque[Alert] = deque()

        # Statistics
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0

        logger.info(
            "rate_limiter_initialized",
            max_per_minute=max_per_minute,
            burst=burst,
        )

    async def acquire(self) -> bool:
        """
        Attempt to acquire a token for sending a message.

        Returns:
            True if token acquired (message can be sent), False if rate limited
        """
        self.total_requests += 1
        self._refill_tokens()

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.allowed_requests += 1
            logger.debug("rate_limit_token_acquired", remaining_tokens=self.tokens)
            return True
        else:
            self.blocked_requests += 1
            logger.debug("rate_limit_blocked", tokens=self.tokens)
            return False

    def queue_alert(self, alert: Alert) -> None:
        """
        Queue alert for later aggregation.

        Args:
            alert: Alert to queue
        """
        self._queued_alerts.append(alert)
        logger.debug("alert_queued_for_aggregation", rule=alert.rule_name)

    def get_queued_alerts(self) -> List[Alert]:
        """
        Get and clear queued alerts.

        Returns:
            List of queued alerts
        """
        alerts = list(self._queued_alerts)
        self._queued_alerts.clear()
        return alerts

    def _refill_tokens(self) -> None:
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self.last_refill

        # Refill rate: max_per_minute / 60 tokens per second
        refill_rate = self.max_per_minute / 60.0
        refill_amount = refill_rate * elapsed

        # Add tokens, cap at burst capacity
        self.tokens = min(self.burst, self.tokens + refill_amount)

        self.last_refill = now

        logger.debug("tokens_refilled", tokens=self.tokens, elapsed=elapsed)

    def get_tokens_available(self) -> float:
        """
        Get current number of available tokens.

        Returns:
            Number of tokens available
        """
        self._refill_tokens()
        return self.tokens

    def reset(self) -> None:
        """Reset rate limiter state."""
        self.tokens = float(self.burst)
        self.last_refill = time.time()
        self._queued_alerts.clear()
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0

        logger.info("rate_limiter_reset")

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "allowed_requests": self.allowed_requests,
            "blocked_requests": self.blocked_requests,
            "current_tokens": self.get_tokens_available(),
            "queued_alerts": len(self._queued_alerts),
            "allow_rate": (
                self.allowed_requests / self.total_requests
                if self.total_requests > 0
                else 1.0
            ),
        }


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts based on alert patterns.

    Reduces rate limit during high-volume periods to prevent flooding.
    """

    def __init__(
        self,
        max_per_minute: int = 10,
        burst: int = 3,
        aggregation_window: int = 60,
        adaptive: bool = True,
    ):
        """
        Initialize adaptive rate limiter.

        Args:
            max_per_minute: Base maximum messages per minute
            burst: Base burst capacity
            aggregation_window: Aggregation window
            adaptive: Enable adaptive behavior
        """
        super().__init__(max_per_minute, burst, aggregation_window)
        self.adaptive = adaptive
        self.base_max_per_minute = max_per_minute
        self.base_burst = burst

        # Adaptive state
        self._recent_requests: deque[float] = deque(maxlen=100)
        self._last_adaptation = time.time()

    async def acquire(self) -> bool:
        """Acquire with adaptive behavior."""
        # Record request
        self._recent_requests.append(time.time())

        # Adapt rate if enabled
        if self.adaptive and time.time() - self._last_adaptation > 10:
            self._adapt_rate()
            self._last_adaptation = time.time()

        return await super().acquire()

    def _adapt_rate(self) -> None:
        """Adapt rate limit based on recent request patterns."""
        if len(self._recent_requests) < 10:
            return

        # Calculate recent request rate
        time_span = self._recent_requests[-1] - self._recent_requests[0]
        if time_span == 0:
            return

        requests_per_second = len(self._recent_requests) / time_span

        # If request rate is very high, reduce limits temporarily
        if requests_per_second > 5:  # More than 5 requests per second
            self.max_per_minute = max(5, self.base_max_per_minute // 2)
            self.burst = max(2, self.base_burst // 2)
            logger.info(
                "rate_limit_reduced",
                new_max_per_minute=self.max_per_minute,
                request_rate=requests_per_second,
            )
        else:
            # Restore to base limits
            self.max_per_minute = self.base_max_per_minute
            self.burst = self.base_burst
