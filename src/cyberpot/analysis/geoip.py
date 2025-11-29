"""
GeoIP lookup functionality using MaxMind GeoIP2 databases.

Provides geographic enrichment for IP addresses including country, city, and ASN data.
"""

from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Optional, Union

import geoip2.database
import geoip2.errors
import structlog

from ..core.models import GeoIPData

logger = structlog.get_logger(__name__)


class GeoIPProvider:
    """
    GeoIP lookup provider using MaxMind GeoLite2 database.

    Caches lookups to minimize database queries.
    """

    def __init__(self, database_path: Optional[Path] = None):
        """
        Initialize GeoIP provider.

        Args:
            database_path: Path to MaxMind GeoLite2-City.mmdb database
        """
        self.database_path = database_path
        self._reader: Optional[geoip2.database.Reader] = None
        self._cache: dict[str, Optional[GeoIPData]] = {}
        self._enabled = False

        if database_path and database_path.exists():
            try:
                self._reader = geoip2.database.Reader(str(database_path))
                self._enabled = True
                logger.info("geoip_provider_initialized", database_path=str(database_path))
            except Exception as e:
                logger.error(
                    "geoip_database_load_failed",
                    database_path=str(database_path),
                    error=str(e),
                    exc_info=True,
                )
        else:
            logger.warning(
                "geoip_database_not_found",
                database_path=str(database_path) if database_path else "None",
            )

    def lookup(self, ip: Union[IPv4Address, IPv6Address, str]) -> Optional[GeoIPData]:
        """
        Look up geographic information for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            GeoIPData object or None if lookup failed
        """
        if not self._enabled:
            return None

        ip_str = str(ip)

        # Check cache
        if ip_str in self._cache:
            return self._cache[ip_str]

        # Perform lookup
        try:
            response = self._reader.city(ip_str)

            geoip_data = GeoIPData(
                country_code=response.country.iso_code,
                country_name=response.country.name,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                asn=None,  # ASN requires separate database
                asn_org=None,
            )

            # Cache result
            self._cache[ip_str] = geoip_data

            logger.debug(
                "geoip_lookup_success",
                ip=ip_str,
                country=geoip_data.country_code,
                city=geoip_data.city,
            )

            return geoip_data

        except geoip2.errors.AddressNotFoundError:
            logger.debug("geoip_address_not_found", ip=ip_str)
            self._cache[ip_str] = None
            return None
        except Exception as e:
            logger.error("geoip_lookup_error", ip=ip_str, error=str(e))
            return None

    def close(self) -> None:
        """Close the GeoIP database reader."""
        if self._reader:
            self._reader.close()
            logger.info("geoip_provider_closed")

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._cache.clear()
        logger.info("geoip_cache_cleared")

    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "cache_size": len(self._cache),
            "enabled": self._enabled,
        }


class ASNProvider:
    """
    ASN (Autonomous System Number) lookup provider.

    Uses MaxMind GeoLite2-ASN database for ASN and organization lookups.
    """

    def __init__(self, database_path: Optional[Path] = None):
        """
        Initialize ASN provider.

        Args:
            database_path: Path to MaxMind GeoLite2-ASN.mmdb database
        """
        self.database_path = database_path
        self._reader: Optional[geoip2.database.Reader] = None
        self._cache: dict[str, tuple[Optional[int], Optional[str]]] = {}
        self._enabled = False

        if database_path and database_path.exists():
            try:
                self._reader = geoip2.database.Reader(str(database_path))
                self._enabled = True
                logger.info("asn_provider_initialized", database_path=str(database_path))
            except Exception as e:
                logger.error(
                    "asn_database_load_failed",
                    database_path=str(database_path),
                    error=str(e),
                    exc_info=True,
                )
        else:
            logger.debug(
                "asn_database_not_found",
                database_path=str(database_path) if database_path else "None",
            )

    def lookup(self, ip: Union[IPv4Address, IPv6Address, str]) -> tuple[Optional[int], Optional[str]]:
        """
        Look up ASN information for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            Tuple of (asn, organization) or (None, None) if lookup failed
        """
        if not self._enabled:
            return None, None

        ip_str = str(ip)

        # Check cache
        if ip_str in self._cache:
            return self._cache[ip_str]

        # Perform lookup
        try:
            response = self._reader.asn(ip_str)

            asn = response.autonomous_system_number
            org = response.autonomous_system_organization

            # Cache result
            self._cache[ip_str] = (asn, org)

            logger.debug("asn_lookup_success", ip=ip_str, asn=asn, org=org)

            return asn, org

        except geoip2.errors.AddressNotFoundError:
            logger.debug("asn_address_not_found", ip=ip_str)
            self._cache[ip_str] = (None, None)
            return None, None
        except Exception as e:
            logger.error("asn_lookup_error", ip=ip_str, error=str(e))
            return None, None

    def close(self) -> None:
        """Close the ASN database reader."""
        if self._reader:
            self._reader.close()
            logger.info("asn_provider_closed")

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._cache.clear()
        logger.info("asn_cache_cleared")


class CombinedGeoIPProvider:
    """
    Combined GeoIP and ASN provider for complete geographic enrichment.
    """

    def __init__(
        self,
        city_database_path: Optional[Path] = None,
        asn_database_path: Optional[Path] = None,
    ):
        """
        Initialize combined provider.

        Args:
            city_database_path: Path to GeoLite2-City database
            asn_database_path: Path to GeoLite2-ASN database
        """
        self.geoip = GeoIPProvider(city_database_path)
        self.asn = ASNProvider(asn_database_path)

        logger.info("combined_geoip_provider_initialized")

    def lookup(self, ip: Union[IPv4Address, IPv6Address, str]) -> Optional[GeoIPData]:
        """
        Look up complete geographic information including ASN.

        Args:
            ip: IP address to look up

        Returns:
            GeoIPData with all available information
        """
        # Get basic GeoIP data
        geoip_data = self.geoip.lookup(ip)

        if not geoip_data:
            return None

        # Enrich with ASN data
        asn, asn_org = self.asn.lookup(ip)
        if asn:
            geoip_data.asn = asn
            geoip_data.asn_org = asn_org

        return geoip_data

    def close(self) -> None:
        """Close all database readers."""
        self.geoip.close()
        self.asn.close()

    def clear_cache(self) -> None:
        """Clear all caches."""
        self.geoip.clear_cache()
        self.asn.clear_cache()

    def get_stats(self) -> dict:
        """Get statistics from all providers."""
        return {
            "geoip": self.geoip.get_cache_stats(),
            "asn": {
                "cache_size": len(self.asn._cache),
                "enabled": self.asn._enabled,
            },
        }
