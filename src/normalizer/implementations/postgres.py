"""
PostgreSQL Log Normalizer (Step 7)

Parses PostgreSQL logs (CSV or Text format) into Unified Log Model.
"""

import re
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class PostgresLogNormalizer(LogNormalizer):
    """
    Normalizer for PostgreSQL logs.
    
    Supports CSV and common Text log formats.
    Example: 2026-01-01 00:00:12 UTC [1234] alice@mydb LOG: statement: SELECT * FROM users;
    """
    
    # Regex for standard Postgres text log
    POSTGRES_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\s+\w+)?)\s+'
        r'\[(?P<pid>\d+)\]\s+'
        r'(?P<user_db>\S+)\s+'
        r'(?P<level>\w+):\s+'
        r'(?P<message>.*)'
    )
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse Postgres raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw Postgres log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency
        log_id = self.generate_log_id(raw_line)
        
        match = self.POSTGRES_PATTERN.match(raw_line)
        if not match:
            return None
            
        data = match.groupdict()
        message = data["message"]
        
        # Split user and database
        user_db = data["user_db"]
        if "@" in user_db:
            user, db = user_db.split("@", 1)
        else:
            user = user_db
            db = None
        
        # Hash user for deterministic PII protection
        if user:
            user = self._hash_value(user)
        
        # Parse timestamp
        try:
            timestamp = self.parse_timestamp(data["timestamp"])
        except ValueError:
            return None
            
        # Detect event_type from command tag or message
        event_type = "db_event"
        msg_lower = message.lower()
        if "select" in msg_lower: event_type = "select"
        elif "insert" in msg_lower: event_type = "insert"
        elif "update" in msg_lower: event_type = "update"
        elif "delete" in msg_lower: event_type = "delete"
        elif "connection received" in msg_lower: event_type = "connection"
        elif "error" in msg_lower or "fatal" in msg_lower: event_type = "error"
        
        # Try to extract IP from message (e.g., "connection received from 1.2.3.4")
        ip = None
        ip_match = re.search(r'from\s+(?P<ip>[\d\.:a-fA-F]+)', message)
        if ip_match:
            ip = ip_match.group("ip")
        
        # PII Masking placeholder
        masked_raw = self.mask_pii(raw_line)
        
        # Metadata
        metadata = {
            "pid": int(data["pid"]),
            "database": db,
            "level": data["level"],
            "message": message
        }
        
        return NormalizedLog(
            log_id=log_id,
            timestamp=timestamp,
            source=LogSource.POSTGRES,
            ip=ip,
            user=user,
            event_type=event_type,
            raw=masked_raw,
            metadata=metadata
        )
