"""
Configuration management for CyberPot.

Loads and validates configuration from YAML files using Pydantic.
"""

from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, validator

import structlog

logger = structlog.get_logger(__name__)


class CowrieConfig(BaseModel):
    """Cowrie honeypot configuration."""

    deployment: str = "docker"  # docker, local
    container_name: str = "cowrie"
    log_file: Path
    downloads_dir: Optional[Path] = None
    tty_dir: Optional[Path] = None


class CoreConfig(BaseModel):
    """Core processing configuration."""

    watch_interval: float = 0.1  # seconds
    batch_size: int = 100
    parse_queue_size: int = 1000
    process_queue_size: int = 1000


class StorageConfig(BaseModel):
    """Storage configuration."""

    max_events: int = 10000
    max_sessions: int = 1000
    max_alerts: int = 5000
    stats_windows: List[int] = Field(default_factory=lambda: [3600, 86400, 604800])  # 1h, 1d, 1w


class GeoIPConfig(BaseModel):
    """GeoIP configuration."""

    enabled: bool = True
    database_path: Optional[Path] = None
    asn_database_path: Optional[Path] = None


class ThreatIntelProviderConfig(BaseModel):
    """Individual threat intel provider config."""

    enabled: bool = False
    api_key: str = ""


class ThreatIntelConfig(BaseModel):
    """Threat intelligence configuration."""

    enabled: bool = True
    cache_ttl: int = 3600  # seconds
    blocklists: List[Path] = Field(default_factory=list)
    providers: Dict[str, ThreatIntelProviderConfig] = Field(default_factory=dict)


class EnrichmentConfig(BaseModel):
    """Enrichment configuration."""

    geoip: GeoIPConfig = Field(default_factory=GeoIPConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)


class AlertsConfig(BaseModel):
    """Alerts configuration."""

    rules_file: Optional[Path] = None
    deduplication_window: int = 300  # seconds

    @validator("rules_file")
    def validate_rules_file(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate rules file exists if specified."""
        if v and not v.exists():
            logger.warning("alert_rules_file_not_found", path=str(v))
        return v


class TUIConfig(BaseModel):
    """TUI configuration."""

    enabled: bool = True
    theme: str = "dark"
    update_interval: float = 1.0  # seconds
    event_feed_size: int = 100


class IRCRateLimitConfig(BaseModel):
    """IRC rate limiting configuration."""

    enabled: bool = True
    max_per_minute: int = 10
    burst: int = 3
    aggregation_window: int = 60  # seconds


class IRCSeverityFilterConfig(BaseModel):
    """IRC severity filter configuration."""

    enabled: bool = True
    min_severity: str = "MEDIUM"  # INFO, LOW, MEDIUM, HIGH, CRITICAL


class IRCAuthConfig(BaseModel):
    """IRC authentication configuration."""

    method: str = "none"  # none, nickserv, sasl
    password: str = ""


class IRCAlertsConfig(BaseModel):
    """IRC alert settings."""

    rate_limit: IRCRateLimitConfig = Field(default_factory=IRCRateLimitConfig)
    severity_filter: IRCSeverityFilterConfig = Field(default_factory=IRCSeverityFilterConfig)
    use_colors: bool = True
    use_emoji: bool = True
    max_length: int = 400


class IRCConfig(BaseModel):
    """IRC bot configuration."""

    enabled: bool = False
    server: str = "irc.example.com"
    port: int = 6667
    use_ssl: bool = False
    nickname: str = "CyberPot"
    username: str = "cyberpot"
    realname: str = "CyberPot Honeypot Monitor"
    channels: List[str] = Field(default_factory=list)
    auth: IRCAuthConfig = Field(default_factory=IRCAuthConfig)
    alerts: IRCAlertsConfig = Field(default_factory=IRCAlertsConfig)


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"  # json, text
    file: Optional[Path] = None
    max_size: str = "100MB"
    backup_count: int = 5


class CyberPotConfig(BaseModel):
    """Main CyberPot configuration."""

    cowrie: CowrieConfig
    core: CoreConfig = Field(default_factory=CoreConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    tui: TUIConfig = Field(default_factory=TUIConfig)
    irc: IRCConfig = Field(default_factory=IRCConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @validator("cowrie")
    def validate_cowrie_log_file(cls, v: CowrieConfig) -> CowrieConfig:
        """Validate Cowrie log file path."""
        if not v.log_file.exists():
            logger.warning("cowrie_log_file_not_found", path=str(v.log_file))
        return v


def load_config(config_path: Path) -> CyberPotConfig:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Validated CyberPotConfig

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    logger.info("loading_config", path=str(config_path))

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    # Convert relative paths to absolute based on config file location
    config_dir = config_path.parent

    def resolve_paths(obj: dict) -> dict:
        """Recursively resolve relative paths."""
        for key, value in obj.items():
            if isinstance(value, str) and (key.endswith("_path") or key.endswith("_file") or key.endswith("_dir")):
                path = Path(value)
                if not path.is_absolute():
                    obj[key] = str(config_dir / path)
            elif key == "blocklists" and isinstance(value, list):
                obj[key] = [
                    str(config_dir / Path(p)) if not Path(p).is_absolute() else p
                    for p in value
                ]
            elif isinstance(value, dict):
                resolve_paths(value)
        return obj

    data = resolve_paths(data)

    try:
        config = CyberPotConfig(**data)
        logger.info("config_loaded_successfully")
        return config
    except Exception as e:
        logger.error("config_validation_error", error=str(e), exc_info=True)
        raise ValueError(f"Invalid configuration: {e}")


def load_alert_rules(rules_path: Path) -> List:
    """
    Load alert rules from YAML file.

    Args:
        rules_path: Path to alert rules file

    Returns:
        List of AlertRule objects

    Raises:
        FileNotFoundError: If rules file doesn't exist
    """
    from .core.models import AlertRule, EventType, Severity

    if not rules_path.exists():
        raise FileNotFoundError(f"Alert rules file not found: {rules_path}")

    logger.info("loading_alert_rules", path=str(rules_path))

    with open(rules_path, "r") as f:
        data = yaml.safe_load(f)

    rules = []
    for rule_data in data.get("rules", []):
        try:
            # Convert event_type string to enum
            if "event_type" in rule_data:
                rule_data["event_type"] = EventType(rule_data["event_type"])

            # Convert severity string to enum
            if "severity" in rule_data:
                rule_data["severity"] = Severity(rule_data["severity"])

            rule = AlertRule(**rule_data)
            rules.append(rule)
            logger.debug("alert_rule_loaded", rule_name=rule.name)
        except Exception as e:
            logger.error("alert_rule_load_error", rule_data=rule_data, error=str(e))

    logger.info("alert_rules_loaded", count=len(rules))
    return rules
