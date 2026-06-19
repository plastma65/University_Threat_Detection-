"""
Nginx Log Normalizer (Step 3)

Parses Nginx Combined Log Format (CLF) into Unified Log Model.
"""

import re
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class NginxLogNormalizer(LogNormalizer):
    """
    Normalizer for Nginx logs using Combined Log Format.
    
    Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    Example: 198.199.83.42 - - [01/Jan/2026:00:00:12 +0000] "POST /api/v1/login HTTP/1.1" 401 224 "-" "Mozilla/5.0..."
    """
    
    # Regex pattern for Nginx Combined Log Format
    NGINX_PATTERN = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>.*?)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+) '
        r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse Nginx raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw Nginx log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency
        log_id = self.generate_log_id(raw_line)
        
        match = self.NGINX_PATTERN.match(raw_line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp to ISO8601 with UTC offset
        try:
            timestamp = self.parse_timestamp(data["timestamp"])
        except ValueError:
            return None
            
        # PII Masking placeholder (currently returns raw_line as is)
        masked_raw = self.mask_pii(raw_line)
        
        # Map user (null if "-") and hash it
        user = data["user"] if data["user"] != "-" else None
        if user:
            user = self._hash_value(user)
        
        # Prepare metadata
        metadata = {
            "method": data["method"],
            "path": data["path"],
            "status": int(data["status"]),
            "bytes": int(data["bytes"]),
            "referer": data["referer"] if data["referer"] != "-" else None,
            "user_agent": data["user_agent"]
        }
        
        return NormalizedLog(
            log_id=log_id,
            timestamp=timestamp,
            source=LogSource.NGINX,
            ip=data["ip"],
            user=user,
            event_type="request",
            raw=masked_raw,
            metadata=metadata
        )
