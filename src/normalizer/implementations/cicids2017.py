"""
CICIDS2017 Benchmark Dataset Normalizer

Parses CICIDS2017 parquet file into Unified Log Model.
CICIDS2017 is a network traffic dataset with 84 features and attack labels.
Note: This dataset contains IP addresses (source_ip, destination_ip).
"""

import hashlib
import orjson
import gc
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from tqdm import tqdm

from ..base import LogNormalizer
from ..schemas import NormalizedLog, LogSource


class CICIDS2017Normalizer(LogNormalizer):
    """
    Normalizer for CICIDS2017 benchmark dataset.

    Format: Parquet file with 84 columns (flow_id, source_ip, source_port, destination_ip, destination_port, protocol, Timestamp, etc.)
    Note: Contains IP addresses (source_ip, destination_ip) and timestamps
    Attack labels: BENIGN, DoS, DDoS, PortScan, Bot, etc.
    """

    # Mapping attack labels to event types
    ATTACK_LABEL_MAPPING = {
        "BENIGN": "normal",
        "DoS": "dos",
        "DDoS": "ddos",
        "PortScan": "port_scan",
        "Bot": "bot",
        "Infiltration": "infiltration",
        "Web Attack": "web_attack",
        "Brute Force": "brute_force",
        "Heartbleed": "heartbleed",
        None: "unknown"
    }

    # Mapping fields to metadata categories
    METADATA_CATEGORIES = {
        "Connection_Info": [
            "flow_id",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "Timestamp"
        ],
        "Flow_Traffic": [
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min"
        ],
        "Packet_Statistics": [
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Min Packet Length",
            "Max Packet Length",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "Average Packet Size",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size"
        ],
        "Flags_Security": [
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "Fwd URG Flags",
            "Bwd URG Flags",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "CWE Flag Count",
            "ECE Flag Count"
        ],
        "Window_Settings": [
            "Fwd Header Length",
            "Bwd Header Length",
            "Init_Win_bytes_forward",
            "Init_Win_bytes_backward",
            "min_seg_size_forward"
        ],
        "Bulk_Rate": [
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk",
            "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate"
        ],
        "Subflow": [
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes"
        ],
        "Timing": [
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min"
        ],
        "Other": [
            "Down/Up Ratio",
            "act_data_pkt_fwd"
        ],
        "Classification": [
            "attack_label"
        ]
    }

    def parse(self, raw_line: str) -> Optional[NormalizedLog]:
        """
        Parse method (required by base class but not used for parquet files).
        """
        return None

    def process_parquet(self, filepath: str, chunk_size: int = 200000) -> List[NormalizedLog]:
        """
        Process CICIDS2017 parquet file with streaming to avoid OOM.
        Uses iter_batches + ParquetWriter for incremental writing.
        
        Args:
            filepath: Path to parquet file
            chunk_size: Number of rows to process at a time (default: 200000)
            
        Returns:
            List of NormalizedLog objects (empty list - data written directly to disk)
        """
        parquet_file = pq.ParquetFile(filepath)
        total_rows = parquet_file.metadata.num_rows
        
        print(f"[INFO] Processing {total_rows} rows with streaming (chunk_size={chunk_size})")
        
        # Determine output path
        input_path = Path(filepath)
        output_path = input_path.parent / f"normalized_{input_path.name}"
        
        # Initialize ParquetWriter for incremental writing
        # Define schema based on NormalizedLog
        schema = pa.schema([
            ('log_id', pa.string()),
            ('timestamp', pa.string()),
            ('source', pa.string()),
            ('ip', pa.string()),
            ('user', pa.string()),
            ('event_type', pa.string()),
            ('raw', pa.string()),
            ('metadata', pa.string())  # Store metadata as JSON string
        ])
        
        writer = None
        processed_count = 0
        
        try:
            # Process using iter_batches for true streaming
            with tqdm(total=total_rows, desc="Processing CICIDS2017", unit="rows") as pbar:
                for batch in parquet_file.iter_batches(batch_size=chunk_size):
                    # Convert batch to pandas
                    df_chunk = batch.to_pandas()
                    chunk_data = df_chunk.to_dict('records')
                    
                    # Process batch
                    batch_records = []
                    for row_dict in chunk_data:
                        try:
                            # Generate log_id
                            clean_row = {k: v for k, v in row_dict.items() if v is not None and pd.notna(v)}
                            row_str = orjson.dumps(clean_row, option=orjson.OPT_SORT_KEYS)
                            log_id = hashlib.sha256(row_str).hexdigest()

                            # Xử lý Timestamp
                            timestamp = "1970-01-01T00:00:00+00:00"
                            raw_ts = row_dict.get('Timestamp')

                            if raw_ts and pd.notna(raw_ts):
                                try:
                                    if isinstance(raw_ts, (int, float)):
                                        dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
                                    else:
                                        dt = pd.to_datetime(raw_ts)
                                        if dt.tzinfo is None:
                                            dt = dt.tz_localize('UTC')
                                    timestamp = dt.isoformat()
                                except Exception:
                                    timestamp = "1970-01-01T00:00:00+00:00"

                            # Trích xuất thông tin IP
                            ip = str(row_dict.get('source_ip')) if row_dict.get('source_ip') and pd.notna(row_dict.get('source_ip')) else None

                            # Ánh xạ nhãn tấn công
                            attack_label = row_dict.get('attack_label')
                            event_type = self.ATTACK_LABEL_MAPPING.get(attack_label, "unknown")

                            # Raw data
                            raw = orjson.dumps(row_dict, default=str).decode('utf-8')

                            # Metadata (organize into nested categories)
                            metadata_nested = {}
                            for category, fields in self.METADATA_CATEGORIES.items():
                                category_data = {}
                                for field in fields:
                                    if field in row_dict and pd.notna(row_dict[field]):
                                        # Convert field name to snake_case for consistency
                                        field_key = field.replace(' ', '_').replace('/', '_')
                                        category_data[field_key] = row_dict[field]
                                if category_data:
                                    metadata_nested[category] = category_data
                            metadata = orjson.dumps(metadata_nested, default=str).decode('utf-8')

                            batch_records.append({
                                'log_id': log_id,
                                'timestamp': timestamp,
                                'source': str(LogSource.CICIDS2017),
                                'ip': ip,
                                'user': None,
                                'event_type': event_type,
                                'raw': raw,
                                'metadata': metadata
                            })
                        except Exception as e:
                            print(f"[ERROR] Failed to process row: {e}")
                    
                    # Convert batch to pyarrow table
                    if batch_records:
                        df_batch = pd.DataFrame(batch_records)
                        table = pa.Table.from_pandas(df_batch, schema=schema)
                        
                        # Initialize writer on first batch
                        if writer is None:
                            writer = pq.ParquetWriter(output_path, schema=schema)
                        
                        # Write batch immediately to disk
                        writer.write_table(table)
                        processed_count += len(batch_records)
                    
                    # Update progress bar
                    pbar.update(len(chunk_data))
                    
                    # Memory cleanup
                    del df_chunk, chunk_data, batch_records
                    if 'df_batch' in locals():
                        del df_batch
                    if 'table' in locals():
                        del table
                    gc.collect()
        
        finally:
            # Close writer
            if writer is not None:
                writer.close()
        
        print(f"[INFO] Completed processing {processed_count} rows to {output_path}")
        return []  # Return empty list since data is written directly to disk