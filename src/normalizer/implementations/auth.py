"""
Auth Log Normalizer (Step 4)

Parses Syslog/Auth.log format into Unified Log Model.
Detects authentication events like login_fail, login_success, etc.
"""

import re
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class AuthLogNormalizer(LogNormalizer):
    """
    Normalizer for Syslog/Auth logs.
    
    Format: Jan  1 00:00:12 hostname process[pid]: message
    Example: Jan  1 00:00:12 server-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
    """
    
    # Regex pattern for Syslog format
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )
    
    # Patterns for event detection
    EVENT_PATTERNS = {
        "login_fail": [
            r"Failed password",
            r"Invalid user",
            r"authentication failure"
        ],
        "login_success": [
            r"Accepted password",
            r"session opened"
        ],
        "session_close": [
            r"session closed"
        ]
    }
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse Auth raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw Auth log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency
        log_id = self.generate_log_id(raw_line)
        
        match = self.SYSLOG_PATTERN.match(raw_line)
        if not match:
            return None
            
        data = match.groupdict()
        message = data["message"]
        
        # Parse timestamp (handles missing year in syslog)
        try:
            timestamp = self.parse_timestamp(data["timestamp"])
        except ValueError:
            return None
            
        # Detect event_type and extract user/ip from message
        event_type = "auth_event"
        for et, patterns in self.EVENT_PATTERNS.items():
            if any(re.search(p, message) for p in patterns):
                event_type = et
                break
                
        # Extract IP from message (e.g., "from 1.2.3.4")
        ip_match = re.search(r'from\s+(?P<ip>[\d\.:a-fA-F]+)', message)
        ip = ip_match.group("ip") if ip_match else None
        
        # Extract user from message
        user = None
        user_match = re.search(r'(?:user|for)\s+(?P<user>\S+)', message)
        if user_match:
            user = user_match.group("user")
            # Cleanup common suffixes
            if user.endswith(":"): user = user[:-1]
            if user == "invalid": # Handle "invalid user name"
                name_match = re.search(r'user\s+(?P<user>\S+)', message[user_match.end():])
                if name_match: user = name_match.group("user")
            
            # Hash user for deterministic PII protection
            user = self._hash_value(user)
        
        # PII Masking placeholder
        masked_raw = self.mask_pii(raw_line)
        
        metadata = {
            "hostname": data["hostname"],
            "process": data["process"],
            "pid": int(data["pid"]) if data["pid"] else None,
            "message": message
        }
        
        return NormalizedLog(
            log_id=log_id,
            timestamp=timestamp,
            source=LogSource.AUTH,
            ip=ip,
            user=user,
            event_type=event_type,
            raw=masked_raw,
            metadata=metadata
        )
