"""
Web Scanner Log Normalizer

Parses web attack scanner logs (Acunetix, Netsparker, w3af) into Unified Log Model.
Format is Nginx Combined Log Format wrapped in quotes.
"""

import re
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class WebScannerLogNormalizer(LogNormalizer):
    """
    Normalizer for web attack scanner logs.
    
    Format: "$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""
    Example: "192.168.4.25 - - [22/Dec/2016:16:30:52 +0300] "POST /administrator/index.php HTTP/1.1" 303 382 "http://192.168.4.161/DVWA" "Mozilla/5.0...""
    """
    
    # Regex pattern for Nginx Combined Log Format (same as nginx.py)
    NGINX_PATTERN = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>.*?)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+) '
        r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse web scanner raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw web scanner log line (with quotes)
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # Remove surrounding quotes if present
        line = raw_line.strip()
        if line.startswith('"') and line.endswith('"'):
            line = line[1:-1]
        
        # MANDATORY: Generate log_id first for idempotency (SHA256 of raw line)
        log_id = self.generate_log_id(raw_line)
        
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp to ISO8601 with UTC offset
        try:
            timestamp = self.parse_timestamp(data["timestamp"])
        except ValueError:
            return None
            
        # PII Masking: mask both raw field and user field (Phase 1 requirement)
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
            source=LogSource.WEB_SCANNER,
            ip=data["ip"],
            user=user,
            event_type="scan",  # Web scanner traffic
            raw=masked_raw,
            metadata=metadata
        )
