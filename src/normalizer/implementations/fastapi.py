"""
FastAPI Log Normalizer (Step 6)

Parses FastAPI JSON application logs into Unified Log Model.
"""

import json
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class FastAPILogNormalizer(LogNormalizer):
    """
    Normalizer for FastAPI logs (JSON format).
    
    Format: JSON dictionary with standardized keys.
    Example: {"timestamp": "2026-01-01T00:00:12Z", "level": "INFO", "message": "Login request", "extra": {"client_ip": "1.2.3.4", "user_id": "alice", "method": "POST", "path": "/login", "status_code": 200}}
    """
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse FastAPI JSON log line into NormalizedLog.
        
        Args:
            raw_line: Raw JSON log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency
        log_id = self.generate_log_id(raw_line)
        
        if not raw_line or not raw_line.strip():
            return None
            
        try:
            log_data = json.loads(raw_line)
            
            # Basic validation
            if not isinstance(log_data, dict) or "timestamp" not in log_data or "message" not in log_data:
                return None
                
            # Parse timestamp (FastAPI usually uses ISO8601)
            timestamp = self.parse_timestamp(log_data["timestamp"])
            
            # Extract fields from 'extra' or root
            extra = log_data.get("extra", {})
            if not isinstance(extra, dict):
                extra = {}
            
            ip = extra.get("client_ip") or log_data.get("client_ip")
            user = str(extra.get("user_id") or log_data.get("user_id", "")) or None
            if user == "" or user == "None": user = None
            
            # Hash user for deterministic PII protection
            if user:
                user = self._hash_value(user)
            
            # Detect event_type from message or status_code
            message = str(log_data.get("message", "")).lower()
            status_code = extra.get("status_code")
            
            if "error" in message or (status_code and status_code >= 500):
                event_type = "error"
            elif "login" in message:
                event_type = "login_request"
            else:
                event_type = "request"
                
            # PII Masking placeholder
            masked_raw = self.mask_pii(raw_line)
            
            # Prepare metadata
            metadata = {
                "level": log_data.get("level"),
                "method": extra.get("method"),
                "path": extra.get("path"),
                "status": status_code,
                "duration_ms": extra.get("duration_ms"),
                "message": log_data.get("message")
            }
            
            return NormalizedLog(
                log_id=log_id,
                timestamp=timestamp,
                source=LogSource.API,
                ip=ip,
                user=user,
                event_type=event_type,
                raw=masked_raw,
                metadata=metadata
            )
            
        except (json.JSONDecodeError, ValueError):
            return None
