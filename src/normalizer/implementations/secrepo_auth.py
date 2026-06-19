"""
Secrepo Auth Log Normalizer

Parses real-world SSH brute force logs from Secrepo dataset into Unified Log Model.
Format similar to syslog but with specific patterns for SSH attacks.
"""

import re
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class SecrepoAuthLogNormalizer(LogNormalizer):
    """
    Normalizer for Secrepo SSH authentication logs.
    
    Format: Nov 30 06:39:00 ip-172-31-27-153 CRON[21882]: pam_unix(cron:session): session closed for user root
    Example: Nov 30 08:42:04 ip-172-31-27-153 sshd[22182]: Invalid user admin from 187.12.249.74
    """
    
    # Regex pattern for Syslog format (same as auth.py)
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )
    
    # Patterns for event detection (specific to SSH attacks)
    EVENT_PATTERNS = {
        "login_fail": [
            r"Failed password",
            r"Invalid user",
            r"authentication failure",
            r"Did not receive identification string"
        ],
        "login_success": [
            r"Accepted password",
            r"session opened"
        ],
        "session_close": [
            r"session closed",
            r"Connection closed"
        ],
        "scan": [
            r"Did not receive identification string"
        ]
    }
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse Secrepo Auth raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw Secrepo Auth log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency (SHA256 of raw line)
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
            if user.endswith(":"): 
                user = user[:-1]
            if user == "invalid": # Handle "invalid user name"
                name_match = re.search(r'user\s+(?P<user>\S+)', message[user_match.end():])
                if name_match: 
                    user = name_match.group("user")
            
            # Hash user for deterministic PII protection (Phase 1 requirement)
            user = self._hash_value(user)
        
        # PII Masking: mask both raw field and user field (Phase 1 requirement)
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
            source=LogSource.SECRETPO_AUTH,
            ip=ip,
            user=user,
            event_type=event_type,
            raw=masked_raw,
            metadata=metadata
        )
