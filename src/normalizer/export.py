"""
Parquet Export (Step 14)

Exports normalized logs to Parquet format using PyArrow streaming batch writing.
Batches of 10,000 records to optimize memory usage.
"""

import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path
from typing import List, Dict
from datetime import datetime

from .schemas import NormalizedLog


class ParquetExporter:
    """
    Exports normalized logs to Parquet files using PyArrow streaming.
    """
    
    BATCH_SIZE = 10000
    
    def __init__(self, output_dir: str):
        """
        Initialize exporter.
        
        Args:
            output_dir: Directory for output parquet files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _normalized_log_to_dict(self, log: NormalizedLog) -> Dict:
        """Convert NormalizedLog to dictionary for PyArrow."""
        # Handle both enum and string for source
        source_value = log.source.value if hasattr(log.source, 'value') else log.source
        
        return {
            "log_id": log.log_id or "",
            "timestamp": log.timestamp or "",
            "source": source_value or "",
            "ip": log.ip or "",
            "user": log.user or "",
            "event_type": log.event_type or "",
            "raw": log.raw or "",
            "metadata": str(log.metadata) if log.metadata else ""
        }
    
    def export(self, logs_by_source: Dict[str, List[NormalizedLog]]) -> Dict[str, str]:
        """
        Export logs to Parquet files by source.
        
        Args:
            logs_by_source: Dictionary mapping source to list of normalized logs
            
        Returns:
            Dictionary mapping source to output file path
        """
        output_files = {}
        
        for source, logs in logs_by_source.items():
            if not logs:
                print(f"No logs to export for {source}")
                continue
            
            output_path = self.output_dir / f"normalized_{source}.parquet"
            print(f"Exporting {len(logs)} {source} logs to {output_path}")
            
            # Define PyArrow schema with nullable fields
            schema = pa.schema([
                ("log_id", pa.string()),
                ("timestamp", pa.string()),
                ("source", pa.string()),
                ("ip", pa.string()),
                ("user", pa.string()),
                ("event_type", pa.string()),
                ("raw", pa.string()),
                ("metadata", pa.string())
            ])
            
            # Streaming write using PyArrow ParquetWriter
            with pq.ParquetWriter(output_path, schema) as writer:
                batch = []
                for log in logs:
                    batch.append(self._normalized_log_to_dict(log))
                    
                    # Write batch when reaching BATCH_SIZE
                    if len(batch) >= self.BATCH_SIZE:
                        table = pa.Table.from_pydict({
                            "log_id": [r["log_id"] for r in batch],
                            "timestamp": [r["timestamp"] for r in batch],
                            "source": [r["source"] for r in batch],
                            "ip": [r["ip"] for r in batch],
                            "user": [r["user"] for r in batch],
                            "event_type": [r["event_type"] for r in batch],
                            "raw": [r["raw"] for r in batch],
                            "metadata": [r["metadata"] for r in batch]
                        })
                        writer.write_table(table)
                        batch = []
                
                # Write remaining records
                if batch:
                    table = pa.Table.from_pydict({
                        "log_id": [r["log_id"] for r in batch],
                        "timestamp": [r["timestamp"] for r in batch],
                        "source": [r["source"] for r in batch],
                        "ip": [r["ip"] for r in batch],
                        "user": [r["user"] for r in batch],
                        "event_type": [r["event_type"] for r in batch],
                        "raw": [r["raw"] for r in batch],
                        "metadata": [r["metadata"] for r in batch]
                    })
                    writer.write_table(table)
            
            output_files[source] = str(output_path)
            print(f"  -> Exported {len(logs)} records")
        
        return output_files


def export_to_parquet(logs_by_source: Dict[str, List[NormalizedLog]], output_dir: str) -> Dict[str, str]:
    """
    Convenience function to export logs to Parquet.
    
    Args:
        logs_by_source: Dictionary mapping source to list of normalized logs
        output_dir: Directory for output parquet files
        
    Returns:
        Dictionary mapping source to output file path
    """
    exporter = ParquetExporter(output_dir)
    return exporter.export(logs_by_source)
