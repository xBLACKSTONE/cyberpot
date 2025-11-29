"""
Event enrichment engine that orchestrates GeoIP and threat intelligence lookups.

Enriches events with geographic and threat data for better analysis and alerting.
"""

from typing import Optional

import structlog

from ..analysis.geoip import CombinedGeoIPProvider
from ..analysis.threat_intel import CombinedThreatIntelProvider
from .models import CommandEvent, Event

logger = structlog.get_logger(__name__)


class EnrichmentEngine:
    """
    Orchestrates enrichment of events with GeoIP and threat intelligence data.

    Applies enrichment pipeline:
    1. GeoIP lookup for geographic data
    2. Threat intelligence lookup for reputation
    3. Command classification (for command events)
    """

    def __init__(
        self,
        geoip_provider: Optional[CombinedGeoIPProvider] = None,
        threat_intel_provider: Optional[CombinedThreatIntelProvider] = None,
    ):
        """
        Initialize enrichment engine.

        Args:
            geoip_provider: GeoIP lookup provider
            threat_intel_provider: Threat intelligence provider
        """
        self.geoip_provider = geoip_provider
        self.threat_intel_provider = threat_intel_provider

        self.enriched_count = 0
        self.geoip_hits = 0
        self.threat_intel_hits = 0

        logger.info(
            "enrichment_engine_initialized",
            geoip_enabled=geoip_provider is not None,
            threat_intel_enabled=threat_intel_provider is not None,
        )

    async def enrich(self, event: Event) -> None:
        """
        Enrich event with all available data.

        Modifies event in-place by adding GeoIP and threat intel data.

        Args:
            event: Event to enrich
        """
        try:
            # GeoIP enrichment
            if self.geoip_provider:
                geoip_data = self.geoip_provider.lookup(event.src_ip)
                if geoip_data:
                    event.geoip = geoip_data
                    self.geoip_hits += 1

            # Threat intelligence enrichment
            if self.threat_intel_provider:
                threat_data = await self.threat_intel_provider.lookup(event.src_ip)
                if threat_data:
                    event.threat_intel = threat_data
                    self.threat_intel_hits += 1

            # Command classification (for command events)
            if isinstance(event, CommandEvent):
                self._classify_command(event)

            self.enriched_count += 1

        except Exception as e:
            logger.error(
                "enrichment_error",
                event_id=event.id,
                event_type=event.event_type.value,
                error=str(e),
                exc_info=True,
            )

    def _classify_command(self, event: CommandEvent) -> None:
        """
        Classify command by intent and mark suspicious commands.

        Args:
            event: CommandEvent to classify
        """
        command = event.command.lower()

        # Reconnaissance commands
        recon_keywords = [
            "whoami",
            "uname",
            "hostname",
            "ifconfig",
            "ip addr",
            "cat /etc",
            "ls ",
            "pwd",
            "id",
            "ps ",
        ]

        # Exploit/malware download commands
        exploit_keywords = [
            "wget",
            "curl",
            "tftp",
            "nc ",
            "netcat",
            "/dev/tcp",
            "bash -i",
            "sh -i",
            "python -c",
            "perl -e",
            "ruby -e",
        ]

        # System modification
        modify_keywords = [
            "chmod",
            "chown",
            "useradd",
            "adduser",
            "passwd",
            "sudo ",
            "su ",
            "iptables",
            "systemctl",
            "service ",
        ]

        # Persistence
        persistence_keywords = [
            "crontab",
            "rc.local",
            "/etc/init",
            ".bashrc",
            ".ssh/authorized_keys",
            "systemd",
        ]

        # Categorize
        if any(keyword in command for keyword in exploit_keywords):
            event.command_category = "exploit"
            event.is_suspicious = True
        elif any(keyword in command for keyword in persistence_keywords):
            event.command_category = "persistence"
            event.is_suspicious = True
        elif any(keyword in command for keyword in modify_keywords):
            event.command_category = "modification"
            event.is_suspicious = True
        elif any(keyword in command for keyword in recon_keywords):
            event.command_category = "recon"
            event.is_suspicious = False  # Recon is expected in honeypots
        else:
            event.command_category = "other"
            event.is_suspicious = False

        # Additional suspicious patterns
        suspicious_patterns = [
            "base64 -d",
            "eval(",
            "exec(",
            "<(",
            ">()",
            "; bash",
            "&& bash",
            "| bash",
        ]

        if any(pattern in command for pattern in suspicious_patterns):
            event.is_suspicious = True

        logger.debug(
            "command_classified",
            command=command[:50],
            category=event.command_category,
            suspicious=event.is_suspicious,
        )

    def get_stats(self) -> dict:
        """Get enrichment statistics."""
        return {
            "enriched_count": self.enriched_count,
            "geoip_hits": self.geoip_hits,
            "threat_intel_hits": self.threat_intel_hits,
            "geoip_hit_rate": (
                self.geoip_hits / self.enriched_count if self.enriched_count > 0 else 0.0
            ),
            "threat_intel_hit_rate": (
                self.threat_intel_hits / self.enriched_count if self.enriched_count > 0 else 0.0
            ),
        }
