"""
Unified Log Model (ULM) - Pydantic V2 Schema

Defines the standardized schema for all normalized log entries across
different sources (nginx, auth, firewall, postgres, api).
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogSource(str, Enum):
    """Enumeration of supported log sources."""
    NGINX = "nginx"
    AUTH = "auth"
    FIREWALL = "firewall"
    POSTGRES = "postgres"
    API = "api"
    CICIDS2017 = "cicids2017"
    UNSW_NB15 = "unsw-nb15"
    SECRETPO_AUTH = "secrepo_auth"
    WEB_SCANNER = "web_scanner"


class NormalizedLog(BaseModel):
    """
    Unified Log Model for normalized log entries.
    
    Fields:
        log_id: SHA256 hash of raw line (64 hex chars, deterministic)
        timestamp: ISO8601 formatted timestamp
        source: Log source type (enum)
        ip: IP address (IPv4 or IPv6)
        user: Username (optional, may be masked/hashed)
        event_type: Event category (request, login_fail, block, etc.)
        raw: Original log line with PII masked
        metadata: Source-specific additional fields (validated dict)
    """
    
    log_id: str = Field(
        ...,
        description="SHA256 hash of raw line (deterministic, 64 hex chars)",
        min_length=64,
        max_length=64
    )
    
    timestamp: str = Field(
        ...,
        description="ISO8601 formatted timestamp (e.g., 2026-01-01T00:00:12+00:00)"
    )
    
    source: LogSource = Field(
        ...,
        description="Log source type"
    )
    
    ip: Optional[str] = Field(
        None,
        description="IP address (IPv4 or IPv6), null if not applicable"
    )
    
    user: Optional[str] = Field(
        None,
        description="Username (may be masked/hashed), null if not applicable"
    )
    
    event_type: str = Field(
        ...,
        description="Event category (e.g., request, login_fail, block, pass)"
    )
    
    raw: str = Field(
        ...,
        description="Original log line with PII masked"
    )
    
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific additional fields"
    )
    
    @field_validator("log_id")
    @classmethod
    def validate_log_id(cls, v: str) -> str:
        """Validate that log_id is a valid 64-character hex string."""
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("log_id must be a 64-character hexadecimal string")
        return v
    
    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate that timestamp is a valid ISO8601 format with timezone."""
        try:
            dt = datetime.fromisoformat(v)
            # Require timezone info for proper ISO8601
            if dt.tzinfo is None:
                raise ValueError("timestamp must include timezone")
        except ValueError:
            raise ValueError("timestamp must be in ISO8601 format with timezone")
        return v
    
    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate metadata contains only serializable values."""
        for key, value in v.items():
            # Reject complex types that could cause issues
            if callable(value):
                raise ValueError("metadata values cannot be callable")
        return v
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True
    )
