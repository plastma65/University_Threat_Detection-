"""
Base Class for Log Normalizers

Provides abstract template for all log normalizer implementations.
Ensures consistent interface and shared utility methods across all sources.
"""

import hashlib
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from .schemas import NormalizedLog


class LogNormalizer(ABC):
    """
    Abstract base class for all log normalizers.
    
    All source-specific normalizers (nginx, auth, firewall, postgres, api)
    must inherit from this class and implement the parse() method.
    
    CRITICAL: generate_log_id() uses SHA256 hash of raw line for idempotency.
    The same raw line will always produce the same log_id, regardless of
    when or how many times the pipeline runs.
    """
    
    def __init__(self):
        # STATIC_SALT from environment variable for PII masking
        self.salt = os.getenv("STATIC_SALT", "default_normalization_salt_2026")
        
    @abstractmethod
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse a raw log line into a NormalizedLog object.
        """
        raise NotImplementedError("Subclasses must implement parse()")
    
    def generate_log_id(self, raw_line: str) -> str:
        """
        Generate deterministic log_id using SHA256 hash of raw line.
        """
        if not raw_line:
            return ""
        return hashlib.sha256(raw_line.encode()).hexdigest()

    def _hash_value(self, value: str) -> str:
        """
        Internal helper to hash a sensitive value with salt.
        Truncates to 16 characters as per requirements.
        """
        if not value:
            return value
        salted = f"{value}{self.salt}".encode()
        return hashlib.sha256(salted).hexdigest()[:16]
    
    def mask_pii(self, raw_line: str) -> str:
        """
        Mask PII (Emails, usernames) in raw log line using SHA256.
        
        Regex Quét Raw: 
        1. Tìm và thay thế Email.
        2. Tìm và thay thế chuỗi sau keywords (user, for, login).
        """
        if not raw_line:
            return raw_line

        masked = raw_line
        
        # 1. Mask Emails: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        masked = re.sub(email_pattern, lambda m: self._hash_value(m.group()), masked)
        
        # 2. Mask strings after keywords: user, for, login
        # We look for user/for/login followed by whitespace, =, or : and a non-whitespace string
        kw_pattern = r'(?i)\b(user|for|login)[\s=:]+([^\s,;\[\]"\'\(\)]+)'
        masked = re.sub(kw_pattern, lambda m: f"{m.group(1)} {self._hash_value(m.group(2))}", masked)
        
        return masked

    def parse_timestamp(self, timestamp_str: str, format_hint: Optional[str] = None) -> str:
        """
        Parse timestamp from various formats to ISO8601.
        
        Args:
            timestamp_str: Timestamp string from log
            format_hint: Optional format string hint for parsing
            
        Returns:
            ISO8601 formatted timestamp string
            
        Raises:
            ValueError: If timestamp cannot be parsed
        """
        # Common log timestamp formats
        common_formats = [
            "%d/%b/%Y:%H:%M:%S %z",  # nginx: 01/Jan/2026:00:00:12 +0000
            "%b %d %H:%M:%S",        # syslog: Jan  1 00:00:00 (no year)
            "%Y-%m-%d %H:%M:%S",     # firewall: 2026-01-01 00:00:02
            "%Y-%m-%d %H:%M:%S %Z",  # postgres: 2026-01-01 00:00:12 UTC
            "%Y-%m-%dT%H:%M:%S%z",   # ISO8601 with timezone
            "%Y-%m-%dT%H:%M:%S",     # ISO8601 without timezone
            "%Y-%m-%d %H:%M:%S.%f",  # With microseconds
        ]
        
        if format_hint:
            formats = [format_hint] + common_formats
        else:
            formats = common_formats
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Handle syslog format without year - assume current year
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now().year)
                
                # Convert to ISO8601
                if dt.tzinfo is None:
                    # Assume UTC if no timezone info
                    return dt.isoformat() + "+00:00"
                return dt.isoformat()
            except ValueError:
                continue
        
        raise ValueError(f"Cannot parse timestamp: {timestamp_str}")
