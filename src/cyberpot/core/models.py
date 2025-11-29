"""
Core data models for CyberPot using Pydantic for validation and type safety.

These models represent events from Cowrie, enrichment data, sessions, and alerts.
"""

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Event type enumeration for Cowrie events"""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    COMMAND_EXECUTION = "command_execution"
    FILE_DOWNLOAD = "file_download"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    CLIENT_INFO = "client_info"
    PORT_FORWARD = "port_forward"


class Severity(str, Enum):
    """Alert severity levels"""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "Severity") -> bool:
        """Allow severity comparison"""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self < other or self == other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class GeoIPData(BaseModel):
    """Geographic information from GeoIP lookup"""

    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None

    def __str__(self) -> str:
        """Human-readable representation"""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country_code:
            parts.append(self.country_code)
        if self.asn_org:
            parts.append(f"AS{self.asn}: {self.asn_org}")
        return ", ".join(parts) if parts else "Unknown"


class ThreatIntelData(BaseModel):
    """Threat intelligence data from various sources"""

    is_malicious: bool = False
    confidence_score: Optional[float] = None
    categories: List[str] = Field(default_factory=list)
    last_seen: Optional[datetime] = None
    reports: int = 0
    sources: List[str] = Field(default_factory=list)  # Which TI sources flagged this

    def __str__(self) -> str:
        """Human-readable representation"""
        if not self.is_malicious:
            return "Clean"
        confidence = f"{self.confidence_score:.0%}" if self.confidence_score else "Unknown"
        cats = ", ".join(self.categories[:3]) if self.categories else "Malicious"
        return f"{cats} (confidence: {confidence}, {self.reports} reports)"


class Event(BaseModel):
    """Base event model for all Cowrie events"""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    event_type: EventType
    session_id: str
    src_ip: Union[IPv4Address, IPv6Address]
    src_port: int

    # Enrichment data (populated by enrichment pipeline)
    geoip: Optional[GeoIPData] = None
    threat_intel: Optional[ThreatIntelData] = None

    # Raw Cowrie data for debugging/analysis
    raw_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration"""

        use_enum_values = False
        arbitrary_types_allowed = True


class LoginEvent(Event):
    """Login attempt event (success or failure)"""

    username: str
    password: Optional[str] = None
    success: bool

    def __str__(self) -> str:
        status = "✓" if self.success else "✗"
        return f"{status} {self.username}:{self.password or '***'}"


class CommandEvent(Event):
    """Command execution event"""

    command: str
    input_data: Optional[str] = None

    # Classification (populated by analysis)
    command_category: Optional[str] = None  # recon, exploit, malware, etc.
    is_suspicious: bool = False

    def __str__(self) -> str:
        marker = "!" if self.is_suspicious else "$"
        category = f"[{self.command_category}] " if self.command_category else ""
        return f"{marker} {category}{self.command[:80]}"


class FileDownloadEvent(Event):
    """File download event"""

    url: str
    outfile: str
    shasum: Optional[str] = None

    # Malware analysis (populated by analysis)
    is_malware: bool = False
    malware_family: Optional[str] = None

    def __str__(self) -> str:
        status = "⚠ MALWARE" if self.is_malware else "FILE"
        family = f" ({self.malware_family})" if self.malware_family else ""
        return f"{status}{family}: {self.url}"


class SessionEvent(Event):
    """Session start/end event"""

    pass  # Base event fields are sufficient


class ClientInfoEvent(Event):
    """Client information event"""

    client_version: str
    client_name: Optional[str] = None


class PortForwardEvent(Event):
    """Port forwarding attempt event"""

    dst_ip: str
    dst_port: int


class Session(BaseModel):
    """Session tracking model"""

    session_id: str
    src_ip: Union[IPv4Address, IPv6Address]
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None  # seconds

    # Session data
    client_version: Optional[str] = None
    login_attempts: int = 0
    successful_login: bool = False
    commands: List[str] = Field(default_factory=list)
    downloads: List[str] = Field(default_factory=list)

    # Enrichment
    geoip: Optional[GeoIPData] = None
    threat_intel: Optional[ThreatIntelData] = None

    # Analysis
    attack_patterns: List[str] = Field(default_factory=list)
    risk_score: float = 0.0  # 0-100

    def __str__(self) -> str:
        """Human-readable representation"""
        duration_str = f"{self.duration:.1f}s" if self.duration else "active"
        location = str(self.geoip) if self.geoip else "Unknown"
        return f"{self.src_ip} [{location}] - {duration_str}"


class Alert(BaseModel):
    """Alert model"""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    rule_name: str
    severity: Severity
    title: str
    description: str

    # Associated data
    event_ids: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    src_ip: Optional[Union[IPv4Address, IPv6Address]] = None

    # Metadata
    acknowledged: bool = False
    sent_to_irc: bool = False

    def __str__(self) -> str:
        """Human-readable representation"""
        icon = {
            Severity.INFO: "ℹ",
            Severity.LOW: "🔵",
            Severity.MEDIUM: "🟡",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "🚨",
        }.get(self.severity, "•")
        return f"{icon} {self.severity.value}: {self.title}"


class AlertRule(BaseModel):
    """Alert rule configuration"""

    name: str
    description: str
    enabled: bool = True
    severity: Severity

    # Conditions
    event_type: Optional[EventType] = None
    count: Optional[int] = None  # Trigger after N occurrences
    time_window: Optional[int] = None  # Within N seconds
    group_by: Optional[str] = None  # Group by src_ip, username, etc.

    # Pattern matching
    command_pattern: Optional[str] = None  # Regex for command matching
    username_pattern: Optional[str] = None
    geoip_country: Optional[List[str]] = None  # List of country codes

    # Actions
    actions: List[str] = Field(default_factory=lambda: ["tui_alert"])


class Statistics(BaseModel):
    """Statistics snapshot"""

    timestamp: datetime = Field(default_factory=datetime.now)

    # Counters
    total_events: int = 0
    total_sessions: int = 0
    active_sessions: int = 0
    total_alerts: int = 0

    # Event breakdown
    events_by_type: Dict[str, int] = Field(default_factory=dict)

    # Top lists
    top_ips: List[tuple[str, int]] = Field(default_factory=list)
    top_countries: List[tuple[str, int]] = Field(default_factory=list)
    top_usernames: List[tuple[str, int]] = Field(default_factory=list)
    top_passwords: List[tuple[str, int]] = Field(default_factory=list)
    top_commands: List[tuple[str, int]] = Field(default_factory=list)

    # Rates
    events_per_second: float = 0.0
    sessions_per_hour: float = 0.0
