"""
UNSW-NB15 Benchmark Dataset Normalizer

Parses UNSW-NB15 parquet files into Unified Log Model.
UNSW-NB15 is a network traffic dataset with 36 features and attack labels.
Note: This dataset does not contain IP addresses (network flow features only).
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional

import pandas as pd
from tqdm import tqdm

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class UNSWNB15Normalizer(LogNormalizer):
    """
    Normalizer for UNSW-NB15 benchmark dataset.
    
    Format: Parquet file with 36 columns (dur, proto, service, state, spkts, dpkts, etc.)
    Note: No IP addresses in this dataset - network flow features only
    Attack categories: Normal, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms
    """
    
    # Mapping attack categories to event types
    ATTACK_CAT_MAPPING = {
        "Normal": "normal",
        "Analysis": "analysis",
        "Backdoor": "backdoor",
        "DoS": "dos",
        "Exploits": "exploit",
        "Fuzzers": "fuzzing",
        "Generic": "generic",
        "Reconnaissance": "recon",
        "Shellcode": "shellcode",
        "Worms": "worm",
        None: "unknown"
    }
    
    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse method (required by base class but not used for parquet files).
        
        UNSW-NB15 uses process_parquet() instead since data is in parquet format.
        
        Args:
            raw_line: Raw log line (not used)
            
        Returns:
            None (use process_parquet instead)
        """
        return None
    
    def process_parquet(self, filepath: str) -> List[NormalizedLog]:
        """
        Process UNSW-NB15 parquet file into NormalizedLog list.
        
        Args:
            filepath: Path to parquet file
            
        Returns:
            List of NormalizedLog objects
        """
        # Read parquet file
        df = pd.read_parquet(filepath)
        
        normalized_logs = []
        
        # Process each row with progress bar (update every 1000 rows for speed)
        with tqdm(total=len(df), desc="Processing UNSW-NB15", unit="rows") as pbar:
            for idx, row in df.iterrows():
                # Generate log_id: SHA256 hash of row (deterministic)
                row_dict = row.to_dict()
                row_str = json.dumps(row_dict, sort_keys=True)
                log_id = hashlib.sha256(row_str.encode()).hexdigest()
                
                # Use default timestamp (epoch) since no timestamp in UNSW-NB15
                timestamp = "1970-01-01T00:00:00+00:00"
                
                # IP is null (no IP addresses in this dataset)
                ip = None
                
                # User is null (network traffic logs don't have user context)
                user = None
                
                # Map attack category to event type
                attack_cat = row.get('attack_cat')
                event_type = self.ATTACK_CAT_MAPPING.get(attack_cat, "unknown")
                
                # Raw: JSON string of original row
                raw = json.dumps(row_dict)
                
                # Metadata: all columns
                metadata = row_dict.copy()
                # Remove fields that are already in main schema
                metadata.pop('attack_cat', None)
                metadata.pop('label', None)
                
                normalized_log = NormalizedLog(
                    log_id=log_id,
                    timestamp=timestamp,
                    source=LogSource.UNSW_NB15,
                    ip=ip,
                    user=user,
                    event_type=event_type,
                    raw=raw,
                    metadata=metadata
                )
                
                normalized_logs.append(normalized_log)
                
                # Update progress bar every 1000 rows for speed
                if (idx + 1) % 1000 == 0:
                    pbar.update(1000)
            
            # Update remaining rows
            remaining = len(df) % 1000
            if remaining > 0:
                pbar.update(remaining)
        
        return normalized_logs
