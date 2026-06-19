"""
Log Normalization Pipeline (Step 11)

Orchestrates the normalization flow with streaming processing to protect RAM.
Scans data/synthetic/ and processes all log files line-by-line.
Integrates PostgreSQL batch upsert after Parquet export.
"""

import os
import time
from pathlib import Path
from typing import List, Dict
from collections import defaultdict
from tqdm import tqdm

from .registry import get_registry
from .schemas import NormalizedLog
from .base import LogNormalizer
from .db import batch_upsert, get_log_count


class NormalizationPipeline:
    """
    Pipeline for normalizing log files with streaming processing.
    """
    
    def __init__(self, input_dir: str, output_dir: str):
        """
        Initialize pipeline.
        
        Args:
            input_dir: Directory containing raw log files
            output_dir: Directory for output parquet files
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.registry = get_registry()
        self.dead_letter_count = 0
        self.processed_counts = defaultdict(int)
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def detect_source(self, filename: str) -> str:
        """
        Detect log source from filename.
        
        Args:
            filename: Name of the log file
            
        Returns:
            Source identifier (nginx, auth, firewall, postgres, api, secrepo_auth, web_scanner, firewall_realworld, unsw-nb15, cicids2017)
        """
        filename_lower = filename.lower()
        if "nginx" in filename_lower and "attack" not in filename_lower:
            return "nginx"
        elif "secrepo" in filename_lower:
            return "secrepo_auth"
        elif "auth" in filename_lower and "secrepo" not in filename_lower:
            return "auth"
        elif "acunetix" in filename_lower or "netsparker" in filename_lower or "w3af" in filename_lower:
            return "web_scanner"
        elif "firewall" in filename_lower or "log2.csv" in filename_lower:
            # Check if it's real-world firewall (log2.csv in firewall-logs/Data/)
            if "log2" in filename_lower:
                return "firewall_realworld"
            return "firewall"
        elif "postgres" in filename_lower:
            return "postgres"
        elif "api" in filename_lower or "fastapi" in filename_lower:
            return "api"
        elif "unsw" in filename_lower or "nb15" in filename_lower:
            return "unsw-nb15"
        elif "cicids" in filename_lower:
            return "cicids2017"
        else:
            raise ValueError(f"Unknown source for file: {filename}")
    
    def process_file(self, filepath: Path) -> List[NormalizedLog]:
        """
        Process a single log file with streaming (line-by-line).
        
        Args:
            filepath: Path to the log file
            
        Returns:
            List of normalized logs
        """
        source = self.detect_source(filepath.name)
        normalizer = self.registry.get_normalizer(source)
        
        if not normalizer:
            raise ValueError(f"No normalizer registered for source: {source}")
        
        normalized_logs = []
        
        # Check if file is parquet (benchmark datasets)
        if filepath.suffix == '.parquet':
            return self._process_parquet_file(filepath, source, normalizer)
        
        # Streaming read - line by line to protect RAM
        # Use progress bar without counting lines first (faster)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            with tqdm(desc=f"Processing {filepath.name}", unit="lines") as pbar:
                for line_num, raw_line in enumerate(f, 1):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        pbar.update(1)
                        continue
                    
                    try:
                        log = normalizer.parse(raw_line)
                        if log:
                            normalized_logs.append(log)
                            self.processed_counts[source] += 1
                        else:
                            # Parse failed - add to dead letter
                            self.dead_letter_count += 1
                            self._write_dead_letter(source, filepath.name, line_num, raw_line)
                    except Exception as e:
                        # Unexpected error - add to dead letter
                        self.dead_letter_count += 1
                        self._write_dead_letter(source, filepath.name, line_num, raw_line, str(e))
                    
                    pbar.update(1)
        
        return normalized_logs
    
    def _process_parquet_file(self, filepath: Path, source: str, normalizer: LogNormalizer) -> List[NormalizedLog]:
        """
        Process parquet file (benchmark datasets).
        
        Args:
            filepath: Path to the parquet file
            source: Log source type
            normalizer: Normalizer instance
            
        Returns:
            List of normalized logs
        """
        try:
            # Use process_parquet method if available
            if hasattr(normalizer, 'process_parquet'):
                normalized_logs = normalizer.process_parquet(str(filepath))
                self.processed_counts[source] = len(normalized_logs)
                return normalized_logs
            else:
                raise ValueError(f"Normalizer for {source} does not support parquet files")
        except Exception as e:
            # Add to dead letter
            self.dead_letter_count += 1
            self._write_dead_letter(source, filepath.name, 0, f"Parquet processing error: {e}")
            return []
    
    def _write_dead_letter(self, source: str, filename: str, line_num: int, raw_line: str, error: str = "Parse failed"):
        """Write failed log line to dead_letter_logs.txt."""
        dead_letter_path = self.output_dir / "dead_letter_logs.txt"
        with open(dead_letter_path, 'a', encoding='utf-8') as f:
            f.write(f"[{source}] {filename}:{line_num} - {error}\n")
            f.write(f"{raw_line}\n\n")
    
    def dump_to_postgres(self, logs_by_source: Dict[str, List[NormalizedLog]], batch_size: int = 1000) -> int:
        """
        Dump normalized logs to PostgreSQL using batch upsert.
        
        Args:
            logs_by_source: Dictionary mapping source to list of normalized logs
            batch_size: Batch size for upsert (default 1000)
            
        Returns:
            Total number of records inserted
        """
        print("\nDumping to PostgreSQL...")
        
        # Flatten all logs from all sources
        all_logs = []
        for source, logs in logs_by_source.items():
            all_logs.extend(logs)
        
        if not all_logs:
            print("  -> No logs to dump")
            return 0
        
        try:
            inserted = batch_upsert(all_logs, batch_size=batch_size)
            print(f"  -> Inserted {inserted} records into PostgreSQL")
            return inserted
        except Exception as e:
            print(f"  -> ERROR dumping to PostgreSQL: {e}")
            # Log to dead letter
            dead_letter_path = self.output_dir / "dead_letter_logs.txt"
            with open(dead_letter_path, 'a', encoding='utf-8') as f:
                f.write(f"[POSTGRES] Database Error: {e}\n\n")
            return 0
    
    def run(self) -> Dict[str, List[NormalizedLog]]:
        """
        Run the full normalization pipeline on all files in input_dir.
        
        Returns:
            Dictionary mapping source to list of normalized logs
        """
        start_time = time.time()
        
        results = defaultdict(list)
        
        # Process all log files in input directory (recursive)
        for filepath in self.input_dir.glob("**/*"):
            if filepath.is_file() and not filepath.name.startswith('.'):
                try:
                    print(f"Processing {filepath.name}...")
                    logs = self.process_file(filepath)
                    source = self.detect_source(filepath.name)
                    results[source].extend(logs)
                    print(f"  -> Processed {len(logs)} logs from {source}")
                except ValueError as e:
                    print(f"  -> Skipping {filepath.name}: {e}")
        
        elapsed = time.time() - start_time
        print(f"\nPipeline completed in {elapsed:.2f} seconds")
        print(f"Total processed: {sum(self.processed_counts.values())}")
        print(f"Dead letters: {self.dead_letter_count}")
        
        return dict(results)


def run_normalization(input_dir: str, output_dir: str, dump_to_db: bool = True) -> Dict[str, List[NormalizedLog]]:
    """
    Convenience function to run the normalization pipeline.
    
    Args:
        input_dir: Directory containing raw log files
        output_dir: Directory for output files
        dump_to_db: Whether to dump to PostgreSQL (default True)
        
    Returns:
        Dictionary mapping source to list of normalized logs
    """
    pipeline = NormalizationPipeline(input_dir, output_dir)
    results = pipeline.run()
    
    if dump_to_db:
        pipeline.dump_to_postgres(results, batch_size=1000)
    
    return results
