"""
Cowrie JSON log parser.

Parses Cowrie JSON log lines and converts them to CyberPot Event models.
Handles all Cowrie event types and validates against expected schema.
"""

import json
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Optional, Union

import structlog
from pydantic import ValidationError

from .models import (
    ClientInfoEvent,
    CommandEvent,
    Event,
    EventType,
    FileDownloadEvent,
    LoginEvent,
    PortForwardEvent,
    SessionEvent,
)

logger = structlog.get_logger(__name__)


class CowrieLogParser:
    """
    Parser for Cowrie JSON logs.

    Converts Cowrie event JSON to typed Event models.
    """

    # Mapping of Cowrie event IDs to our EventType enum
    EVENT_TYPE_MAP = {
        "cowrie.login.success": EventType.LOGIN_SUCCESS,
        "cowrie.login.failed": EventType.LOGIN_FAILED,
        "cowrie.command.input": EventType.COMMAND_EXECUTION,
        "cowrie.session.file_download": EventType.FILE_DOWNLOAD,
        "cowrie.session.connect": EventType.SESSION_START,
        "cowrie.session.closed": EventType.SESSION_END,
        "cowrie.client.version": EventType.CLIENT_INFO,
        "cowrie.direct-tcpip.request": EventType.PORT_FORWARD,
    }

    def __init__(self):
        """Initialize the parser."""
        self.parsed_count = 0
        self.error_count = 0

    def parse_line(self, line: str) -> Optional[Event]:
        """
        Parse a single JSON log line from Cowrie.

        Args:
            line: JSON string from Cowrie log

        Returns:
            Event object or None if parsing failed
        """
        try:
            data = json.loads(line)
            event = self.parse_event(data)

            if event:
                self.parsed_count += 1
            return event

        except json.JSONDecodeError as e:
            self.error_count += 1
            logger.warning("json_decode_error", line=line[:100], error=str(e))
            return None
        except Exception as e:
            self.error_count += 1
            logger.error("parse_line_error", line=line[:100], error=str(e), exc_info=True)
            return None

    def parse_batch(self, lines: list[str]) -> list[Event]:
        """
        Parse a batch of log lines.

        Args:
            lines: List of JSON strings

        Returns:
            List of Event objects (skips failed parses)
        """
        events = []
        for line in lines:
            event = self.parse_line(line)
            if event:
                events.append(event)
        return events

    def parse_event(self, data: dict) -> Optional[Event]:
        """
        Parse a Cowrie event dict into an Event model.

        Args:
            data: Parsed JSON dict from Cowrie

        Returns:
            Specific Event subclass or None if unknown/unsupported event type
        """
        try:
            # Get event type
            event_id = data.get("eventid")
            if not event_id:
                logger.warning("missing_eventid", data_keys=list(data.keys()))
                return None

            event_type = self.EVENT_TYPE_MAP.get(event_id)
            if not event_type:
                logger.debug("unsupported_event_type", event_id=event_id)
                return None

            # Extract common fields
            common_fields = self._extract_common_fields(data)
            if not common_fields:
                return None

            # Parse specific event type
            if event_type == EventType.LOGIN_SUCCESS:
                return self._parse_login_event(data, common_fields, success=True)
            elif event_type == EventType.LOGIN_FAILED:
                return self._parse_login_event(data, common_fields, success=False)
            elif event_type == EventType.COMMAND_EXECUTION:
                return self._parse_command_event(data, common_fields)
            elif event_type == EventType.FILE_DOWNLOAD:
                return self._parse_file_download_event(data, common_fields)
            elif event_type == EventType.SESSION_START:
                return self._parse_session_event(data, common_fields, EventType.SESSION_START)
            elif event_type == EventType.SESSION_END:
                return self._parse_session_event(data, common_fields, EventType.SESSION_END)
            elif event_type == EventType.CLIENT_INFO:
                return self._parse_client_info_event(data, common_fields)
            elif event_type == EventType.PORT_FORWARD:
                return self._parse_port_forward_event(data, common_fields)
            else:
                logger.warning("unhandled_event_type", event_type=event_type)
                return None

        except ValidationError as e:
            self.error_count += 1
            logger.warning("validation_error", error=str(e), data=data)
            return None
        except Exception as e:
            self.error_count += 1
            logger.error("parse_event_error", error=str(e), data=data, exc_info=True)
            return None

    def _extract_common_fields(self, data: dict) -> Optional[dict]:
        """Extract fields common to all events."""
        try:
            timestamp_str = data.get("timestamp")
            if not timestamp_str:
                logger.warning("missing_timestamp", data_keys=list(data.keys()))
                return None

            # Parse timestamp (Cowrie uses ISO 8601)
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

            # Extract IP and port
            src_ip_str = data.get("src_ip")
            if not src_ip_str:
                logger.warning("missing_src_ip", data_keys=list(data.keys()))
                return None

            src_ip = ip_address(src_ip_str)
            src_port = data.get("src_port", 0)

            # Session ID
            session_id = data.get("session", "unknown")

            return {
                "timestamp": timestamp,
                "session_id": session_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "raw_data": data,
            }

        except Exception as e:
            logger.error("extract_common_fields_error", error=str(e), data=data)
            return None

    def _parse_login_event(self, data: dict, common: dict, success: bool) -> LoginEvent:
        """Parse login event (success or failed)."""
        username = data.get("username", "unknown")
        password = data.get("password")  # May be None for public key auth

        return LoginEvent(
            event_type=EventType.LOGIN_SUCCESS if success else EventType.LOGIN_FAILED,
            username=username,
            password=password,
            success=success,
            **common,
        )

    def _parse_command_event(self, data: dict, common: dict) -> CommandEvent:
        """Parse command execution event."""
        command = data.get("input", "")
        input_data = data.get("message")  # Additional input data

        return CommandEvent(
            event_type=EventType.COMMAND_EXECUTION,
            command=command,
            input_data=input_data,
            **common,
        )

    def _parse_file_download_event(self, data: dict, common: dict) -> FileDownloadEvent:
        """Parse file download event."""
        url = data.get("url", "")
        outfile = data.get("outfile", "")
        shasum = data.get("shasum")

        return FileDownloadEvent(
            event_type=EventType.FILE_DOWNLOAD,
            url=url,
            outfile=outfile,
            shasum=shasum,
            **common,
        )

    def _parse_session_event(self, data: dict, common: dict, event_type: EventType) -> SessionEvent:
        """Parse session start/end event."""
        return SessionEvent(event_type=event_type, **common)

    def _parse_client_info_event(self, data: dict, common: dict) -> ClientInfoEvent:
        """Parse client version info event."""
        version = data.get("version", "unknown")

        # Try to extract client name from version string
        client_name = None
        if "OpenSSH" in version:
            client_name = "OpenSSH"
        elif "PuTTY" in version:
            client_name = "PuTTY"
        elif "libssh" in version:
            client_name = "libssh"

        return ClientInfoEvent(
            event_type=EventType.CLIENT_INFO,
            client_version=version,
            client_name=client_name,
            **common,
        )

    def _parse_port_forward_event(self, data: dict, common: dict) -> PortForwardEvent:
        """Parse port forwarding attempt event."""
        dst_ip = data.get("dst_ip", "unknown")
        dst_port = data.get("dst_port", 0)

        return PortForwardEvent(
            event_type=EventType.PORT_FORWARD,
            dst_ip=dst_ip,
            dst_port=dst_port,
            **common,
        )

    def get_stats(self) -> dict:
        """Get parser statistics."""
        return {
            "parsed_count": self.parsed_count,
            "error_count": self.error_count,
            "success_rate": (
                self.parsed_count / (self.parsed_count + self.error_count)
                if (self.parsed_count + self.error_count) > 0
                else 0.0
            ),
        }
