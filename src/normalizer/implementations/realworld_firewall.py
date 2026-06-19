"""
Real-world Firewall Log Normalizer

Parses real-world firewall logs (log2.csv) into Unified Log Model.
Format differs from synthetic: no timestamp, no IP, only ports and action.
"""

import csv
from typing import Optional
from datetime import datetime, timezone

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class RealworldFirewallLogNormalizer(LogNormalizer):
    """
    Normalizer for real-world firewall logs (log2.csv).
    
    Format: Source Port,Destination Port,NAT Source Port,NAT Destination Port,Action,Bytes,Bytes Sent,Bytes Received,Packets,Elapsed Time (sec),pkts_sent,pkts_received
    Example: 57222,53,54587,53,allow,177,94,83,2,30,1,1
    
    Note: This format lacks timestamp and IP fields, which are required by ULM.
    We use default values for these fields.
    """
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse real-world firewall raw log line into NormalizedLog.
        
        Args:
            raw_line: Raw firewall CSV log line
            
        Returns:
            NormalizedLog if successful, None otherwise
        """
        # MANDATORY: Generate log_id first for idempotency (SHA256 of raw line)
        log_id = self.generate_log_id(raw_line)
        
        # Skip header line
        if raw_line.startswith("Source Port"):
            return None
        
        # Parse CSV line
        try:
            reader = csv.reader([raw_line])
            row = next(reader)
        except (csv.Error, StopIteration):
            return None
        
        # Validate row length
        if len(row) < 12:
            return None
        
        try:
            # Extract fields
            src_port = int(row[0])
            dst_port = int(row[1])
            nat_src_port = int(row[2])
            nat_dst_port = int(row[3])
            action = row[4].lower()
            bytes_total = int(row[5])
            bytes_sent = int(row[6])
            bytes_received = int(row[7])
            packets = int(row[8])
            elapsed_time = float(row[9])
            pkts_sent = int(row[10])
            pkts_received = int(row[11])
        except (ValueError, IndexError):
            return None
        
        # Use default timestamp (epoch) since not provided in log
        # This allows data to be processed while acknowledging limitation
        timestamp = "1970-01-01T00:00:00+00:00"
        
        # IP is null (not provided in this log format)
        ip = None
        
        # User is null (firewall logs don't have user context)
        user = None
        
        # Map action to event_type
        event_type = action if action in ["allow", "deny", "block"] else "unknown"
        
        # PII Masking: mask raw field (Phase 1 requirement)
        masked_raw = self.mask_pii(raw_line)
        
        # Prepare metadata
        metadata = {
            "src_port": src_port,
            "dst_port": dst_port,
            "nat_src_port": nat_src_port,
            "nat_dst_port": nat_dst_port,
            "action": action,
            "bytes_total": bytes_total,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets": packets,
            "elapsed_time": elapsed_time,
            "pkts_sent": pkts_sent,
            "pkts_received": pkts_received
        }
        
        return NormalizedLog(
            log_id=log_id,
            timestamp=timestamp,
            source=LogSource.FIREWALL,  # Use FIREWALL source (real-world data)
            ip=ip,
            user=user,
            event_type=event_type,
            raw=masked_raw,
            metadata=metadata
        )
