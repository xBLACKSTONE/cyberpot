"""
Threat intelligence providers for IP reputation and threat detection.

Supports built-in IP blocklists and GreyNoise Community API.
"""

import time
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import List, Optional, Set, Union

import httpx
import structlog

from ..core.models import ThreatIntelData

logger = structlog.get_logger(__name__)


class BlocklistProvider:
    """
    IP blocklist provider that loads and checks against text-based blocklists.

    Supports multiple blocklist files with automatic merging.
    """

    def __init__(self, blocklist_paths: Optional[List[Path]] = None):
        """
        Initialize blocklist provider.

        Args:
            blocklist_paths: List of paths to blocklist files (one IP per line)
        """
        self.blocklist_paths = blocklist_paths or []
        self._blocklist: Set[str] = set()
        self._loaded = False

        if self.blocklist_paths:
            self.load_blocklists()

    def load_blocklists(self) -> None:
        """Load all blocklist files into memory."""
        self._blocklist.clear()
        loaded_count = 0

        for path in self.blocklist_paths:
            if not path.exists():
                logger.warning("blocklist_not_found", path=str(path))
                continue

            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith("#"):
                            # Extract IP if line has additional data
                            ip = line.split()[0]
                            self._blocklist.add(ip)
                            loaded_count += 1

                logger.info("blocklist_loaded", path=str(path), entries=loaded_count)
            except Exception as e:
                logger.error("blocklist_load_error", path=str(path), error=str(e))

        self._loaded = True
        logger.info("blocklists_initialized", total_entries=len(self._blocklist))

    def check(self, ip: Union[IPv4Address, IPv6Address, str]) -> bool:
        """
        Check if IP is in blocklist.

        Args:
            ip: IP address to check

        Returns:
            True if IP is in blocklist
        """
        if not self._loaded:
            return False

        return str(ip) in self._blocklist

    def add_ip(self, ip: str) -> None:
        """
        Add IP to blocklist.

        Args:
            ip: IP address to add
        """
        self._blocklist.add(ip)

    def remove_ip(self, ip: str) -> bool:
        """
        Remove IP from blocklist.

        Args:
            ip: IP address to remove

        Returns:
            True if IP was removed
        """
        try:
            self._blocklist.remove(ip)
            return True
        except KeyError:
            return False

    def get_stats(self) -> dict:
        """Get blocklist statistics."""
        return {
            "loaded": self._loaded,
            "total_ips": len(self._blocklist),
            "blocklist_count": len(self.blocklist_paths),
        }


class GreyNoiseProvider:
    """
    GreyNoise Community API provider for mass scanner identification.

    Free tier provides basic reputation data without API limits.
    """

    API_BASE = "https://api.greynoise.io/v3/community/"

    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 86400):
        """
        Initialize GreyNoise provider.

        Args:
            api_key: Optional API key (Community API is free without key)
            cache_ttl: Cache TTL in seconds (default: 24 hours)
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[Optional[ThreatIntelData], float]] = {}
        self._enabled = True  # Community API is always available

        logger.info("greynoise_provider_initialized", has_api_key=bool(api_key))

    async def lookup(self, ip: Union[IPv4Address, IPv6Address, str]) -> Optional[ThreatIntelData]:
        """
        Look up IP reputation in GreyNoise.

        Args:
            ip: IP address to look up

        Returns:
            ThreatIntelData or None if lookup failed
        """
        if not self._enabled:
            return None

        ip_str = str(ip)

        # Check cache
        if ip_str in self._cache:
            data, timestamp = self._cache[ip_str]
            if time.time() - timestamp < self.cache_ttl:
                return data

        # Perform lookup
        try:
            headers = {}
            if self.api_key:
                headers["key"] = self.api_key

            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.API_BASE}{ip_str}", headers=headers)

                if response.status_code == 404:
                    # IP not found in GreyNoise (likely not a mass scanner)
                    logger.debug("greynoise_ip_not_found", ip=ip_str)
                    result = None
                elif response.status_code == 200:
                    data = response.json()

                    # Parse GreyNoise response
                    noise = data.get("noise", False)
                    riot = data.get("riot", False)
                    classification = data.get("classification", "unknown")
                    name = data.get("name", "")

                    # Determine if malicious
                    is_malicious = noise and classification == "malicious"

                    categories = []
                    if noise:
                        categories.append("mass_scanner")
                    if riot:
                        categories.append("common_business_service")
                    if classification:
                        categories.append(classification)

                    result = ThreatIntelData(
                        is_malicious=is_malicious,
                        confidence_score=0.8 if is_malicious else 0.3,
                        categories=categories,
                        reports=1 if noise else 0,
                        sources=["greynoise"],
                    )

                    logger.debug(
                        "greynoise_lookup_success",
                        ip=ip_str,
                        noise=noise,
                        classification=classification,
                    )
                else:
                    logger.warning("greynoise_api_error", ip=ip_str, status=response.status_code)
                    result = None

                # Cache result
                self._cache[ip_str] = (result, time.time())
                return result

        except httpx.TimeoutException:
            logger.warning("greynoise_timeout", ip=ip_str)
            return None
        except Exception as e:
            logger.error("greynoise_lookup_error", ip=ip_str, error=str(e))
            return None

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._cache.clear()
        logger.info("greynoise_cache_cleared")

    def get_stats(self) -> dict:
        """Get GreyNoise provider statistics."""
        return {
            "enabled": self._enabled,
            "cache_size": len(self._cache),
            "has_api_key": bool(self.api_key),
        }


class CombinedThreatIntelProvider:
    """
    Combined threat intelligence provider that aggregates multiple sources.

    Checks blocklists first (fast), then queries GreyNoise if enabled.
    """

    def __init__(
        self,
        blocklist_paths: Optional[List[Path]] = None,
        greynoise_api_key: Optional[str] = None,
        greynoise_enabled: bool = True,
    ):
        """
        Initialize combined provider.

        Args:
            blocklist_paths: Paths to IP blocklist files
            greynoise_api_key: Optional GreyNoise API key
            greynoise_enabled: Enable GreyNoise lookups
        """
        self.blocklist = BlocklistProvider(blocklist_paths)
        self.greynoise = GreyNoiseProvider(greynoise_api_key) if greynoise_enabled else None

        logger.info(
            "combined_threat_intel_initialized",
            blocklists_enabled=bool(blocklist_paths),
            greynoise_enabled=greynoise_enabled,
        )

    async def lookup(self, ip: Union[IPv4Address, IPv6Address, str]) -> Optional[ThreatIntelData]:
        """
        Look up IP in all threat intelligence sources.

        Args:
            ip: IP address to look up

        Returns:
            Aggregated ThreatIntelData
        """
        ip_str = str(ip)
        sources = []
        categories = []
        is_malicious = False
        confidence = 0.0
        reports = 0

        # Check blocklist first (fast)
        if self.blocklist.check(ip):
            is_malicious = True
            confidence = 0.9  # High confidence for known blocklists
            categories.append("blocklisted")
            sources.append("blocklist")
            reports += 1

            logger.debug("threat_intel_blocklist_hit", ip=ip_str)

        # Check GreyNoise (if enabled and not already malicious)
        if self.greynoise:
            greynoise_data = await self.greynoise.lookup(ip)
            if greynoise_data:
                if greynoise_data.is_malicious:
                    is_malicious = True
                    confidence = max(confidence, greynoise_data.confidence_score or 0.0)

                categories.extend(greynoise_data.categories)
                sources.extend(greynoise_data.sources)
                reports += greynoise_data.reports

        # Return None if no threat intelligence found
        if not sources:
            return None

        return ThreatIntelData(
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(set(categories)),  # Deduplicate
            reports=reports,
            sources=list(set(sources)),  # Deduplicate
        )

    def clear_cache(self) -> None:
        """Clear all caches."""
        if self.greynoise:
            self.greynoise.clear_cache()

    def get_stats(self) -> dict:
        """Get statistics from all providers."""
        stats = {
            "blocklist": self.blocklist.get_stats(),
        }

        if self.greynoise:
            stats["greynoise"] = self.greynoise.get_stats()

        return stats
