"""
Severity-based alert filter for IRC.

Filters alerts based on minimum severity level to reduce noise.
"""

import structlog

from ..core.models import Alert, Severity

logger = structlog.get_logger(__name__)


class SeverityFilter:
    """
    Filter alerts based on severity level.

    Only allows alerts at or above the configured minimum severity.
    """

    def __init__(self, min_severity: str = "MEDIUM", enabled: bool = True):
        """
        Initialize severity filter.

        Args:
            min_severity: Minimum severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
            enabled: Enable filtering
        """
        self.enabled = enabled

        # Parse minimum severity
        try:
            self.min_severity = Severity(min_severity.upper())
        except ValueError:
            logger.warning(
                "invalid_min_severity",
                min_severity=min_severity,
                defaulting_to="MEDIUM",
            )
            self.min_severity = Severity.MEDIUM

        # Statistics
        self.total_checked = 0
        self.allowed_count = 0
        self.filtered_count = 0

        logger.info(
            "severity_filter_initialized",
            min_severity=self.min_severity.value,
            enabled=enabled,
        )

    def should_send(self, alert: Alert) -> bool:
        """
        Check if alert should be sent based on severity.

        Args:
            alert: Alert to check

        Returns:
            True if alert should be sent, False if filtered
        """
        self.total_checked += 1

        # If filtering is disabled, allow all
        if not self.enabled:
            self.allowed_count += 1
            return True

        # Check severity level
        if alert.severity >= self.min_severity:
            self.allowed_count += 1
            logger.debug(
                "alert_allowed_by_severity",
                severity=alert.severity.value,
                rule=alert.rule_name,
            )
            return True
        else:
            self.filtered_count += 1
            logger.debug(
                "alert_filtered_by_severity",
                severity=alert.severity.value,
                min_severity=self.min_severity.value,
                rule=alert.rule_name,
            )
            return False

    def set_min_severity(self, severity: str | Severity) -> None:
        """
        Update minimum severity level.

        Args:
            severity: New minimum severity
        """
        if isinstance(severity, str):
            try:
                self.min_severity = Severity(severity.upper())
            except ValueError:
                logger.error("invalid_severity", severity=severity)
                return
        else:
            self.min_severity = severity

        logger.info("min_severity_updated", new_min=self.min_severity.value)

    def enable(self) -> None:
        """Enable severity filtering."""
        self.enabled = True
        logger.info("severity_filter_enabled")

    def disable(self) -> None:
        """Disable severity filtering (allow all)."""
        self.enabled = False
        logger.info("severity_filter_disabled")

    def reset_stats(self) -> None:
        """Reset filter statistics."""
        self.total_checked = 0
        self.allowed_count = 0
        self.filtered_count = 0
        logger.info("severity_filter_stats_reset")

    def get_stats(self) -> dict:
        """
        Get filter statistics.

        Returns:
            Dictionary with filter statistics
        """
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity.value,
            "total_checked": self.total_checked,
            "allowed_count": self.allowed_count,
            "filtered_count": self.filtered_count,
            "allow_rate": (
                self.allowed_count / self.total_checked if self.total_checked > 0 else 1.0
            ),
        }


class DynamicSeverityFilter(SeverityFilter):
    """
    Dynamic severity filter that adjusts based on alert volume.

    Automatically raises minimum severity during high-volume periods.
    """

    def __init__(
        self,
        base_min_severity: str = "MEDIUM",
        enabled: bool = True,
        adaptive: bool = True,
    ):
        """
        Initialize dynamic severity filter.

        Args:
            base_min_severity: Base minimum severity level
            enabled: Enable filtering
            adaptive: Enable adaptive behavior
        """
        super().__init__(base_min_severity, enabled)
        self.adaptive = adaptive
        self.base_min_severity = self.min_severity

        # Adaptive state
        self._recent_alerts: list[float] = []
        self._last_adaptation = 0.0

        logger.info(
            "dynamic_severity_filter_initialized",
            base_min_severity=base_min_severity,
            adaptive=adaptive,
        )

    def should_send(self, alert: Alert) -> bool:
        """Check if alert should be sent with adaptive behavior."""
        import time

        # Record alert
        current_time = time.time()
        self._recent_alerts.append(current_time)

        # Clean old alerts (keep last 5 minutes)
        cutoff = current_time - 300
        self._recent_alerts = [t for t in self._recent_alerts if t > cutoff]

        # Adapt severity if needed
        if self.adaptive and current_time - self._last_adaptation > 60:
            self._adapt_severity()
            self._last_adaptation = current_time

        return super().should_send(alert)

    def _adapt_severity(self) -> None:
        """Adapt minimum severity based on recent alert volume."""
        alert_count = len(self._recent_alerts)

        # High volume: increase minimum severity
        if alert_count > 50:  # More than 50 alerts in 5 minutes
            if self.min_severity < Severity.HIGH:
                self.min_severity = Severity.HIGH
                logger.info(
                    "severity_increased_high_volume",
                    alert_count=alert_count,
                    new_min=self.min_severity.value,
                )

        # Very high volume: only critical alerts
        elif alert_count > 100:
            if self.min_severity < Severity.CRITICAL:
                self.min_severity = Severity.CRITICAL
                logger.warning(
                    "severity_increased_critical",
                    alert_count=alert_count,
                    new_min=self.min_severity.value,
                )

        # Low volume: restore base severity
        elif alert_count < 20:
            if self.min_severity != self.base_min_severity:
                self.min_severity = self.base_min_severity
                logger.info(
                    "severity_restored_to_base",
                    alert_count=alert_count,
                    new_min=self.min_severity.value,
                )
