"""
Firewall Log Normalizer (Step 5)

Parses pfSense CSV format into Unified Log Model.
Maps specific CSV columns to standardized fields.
"""

import csv
import io
from typing import Optional

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class FirewallLogNormalizer(LogNormalizer):
    """
    Normalizer for Firewall logs (CSV format).
    
    Format: CSV with header row
    Example: timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,bytes
    2026-01-01 00:00:02,192.168.10.196,184.133.132.180,63633,5432,TCP,allow,36363
    
    Mappings:
    - Col 0: Timestamp (2026-01-01 00:00:02)
    - Col 1: Source IP
    - Col 2: Destination IP
    - Col 3: Source Port
    - Col 4: Destination Port
    - Col 5: Protocol
    - Col 6: Action (allow/deny -> event_type)
    - Col 7: Bytes
    - User: always null
    """
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse Firewall raw log line (CSV) into NormalizedLog.
        
        Args:
            raw_line: Raw Firewall log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency
        log_id = self.generate_log_id(raw_line)
        
        if not raw_line or not raw_line.strip():
            return None
        
        # Skip header if present
        if raw_line.startswith("timestamp,") or "src_ip" in raw_line:
            return None
            
        try:
            # Use csv module to handle potential quoting
            reader = csv.reader(io.StringIO(raw_line))
            cols = next(reader)
            
            # Ensure we have at least 8 columns
            if len(cols) < 8:
                return None
                
            # Parse timestamp
            try:
                timestamp = self.parse_timestamp(cols[0])
            except (ValueError, IndexError):
                return None
            
            # Map columns based on actual CSV format
            # timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,bytes
            try:
                ip = cols[1]
                action = cols[6]  # allow/deny
                protocol = cols[5]
                src_port = cols[3]
                dst_port = cols[4]
                dst_ip = cols[2]
                bytes_val = cols[7]
            except IndexError:
                return None
            
            # PII Masking
            masked_raw = self.mask_pii(raw_line)
            
            metadata = {
                "protocol": protocol,
                "src_port": int(src_port) if src_port.isdigit() else src_port,
                "dst_port": int(dst_port) if dst_port.isdigit() else dst_port,
                "dst_ip": dst_ip,
                "bytes": int(bytes_val) if bytes_val.isdigit() else bytes_val,
                "action": action
            }
            
            return NormalizedLog(
                log_id=log_id,
                timestamp=timestamp,
                source=LogSource.FIREWALL,
                ip=ip,
                user=None, # Firewall has no user context
                event_type=action,
                raw=masked_raw,
                metadata=metadata
            )
            
        except (StopIteration, ValueError, IndexError):
            return None
