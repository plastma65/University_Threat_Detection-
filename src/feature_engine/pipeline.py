"""End-to-end feature extraction pipeline."""

import json
import logging
import os
from typing import Dict, List

import pandas as pd

from .extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def run_feature_extraction(
    processed_dir: str,
    output_dir: str,
    window_sizes: List[int] = [5, 15],
) -> Dict[str, str]:
    """Load normalized parquet files, extract features, and write output parquets.

    Args:
        processed_dir: Directory containing normalized_nginx.parquet,
                        normalized_auth.parquet, normalized_firewall.parquet.
        output_dir: Destination directory for features_Nmin.parquet files.
        window_sizes: List of window widths in minutes to produce.

    Returns:
        Mapping of window label (e.g. "5min") to the output parquet path.
    """
    nginx_path = os.path.join(processed_dir, "normalized_nginx.parquet")
    auth_path = os.path.join(processed_dir, "normalized_auth.parquet")
    fw_path = os.path.join(processed_dir, "normalized_firewall.parquet")

    nginx_df = pd.read_parquet(nginx_path) if os.path.exists(nginx_path) else pd.DataFrame()
    auth_df = pd.read_parquet(auth_path) if os.path.exists(auth_path) else pd.DataFrame()
    fw_df = pd.read_parquet(fw_path) if os.path.exists(fw_path) else pd.DataFrame()

    logger.info(
        "Loaded %d nginx, %d auth, %d firewall records",
        len(nginx_df),
        len(auth_df),
        len(fw_df),
    )

    os.makedirs(output_dir, exist_ok=True)

    results: Dict[str, str] = {}
    for window_size in window_sizes:
        extractor = FeatureExtractor(window_minutes=window_size)

        nginx_features = extractor.extract_from_nginx(nginx_df) if not nginx_df.empty else []
        auth_features = extractor.extract_from_auth(auth_df) if not auth_df.empty else []
        fw_features = extractor.extract_from_firewall(fw_df) if not fw_df.empty else []

        merged = extractor.merge_features(nginx_features, auth_features, fw_features)
        logger.info("Window %dmin: %d feature windows produced", window_size, len(merged))

        rows = [fw.model_dump() for fw in merged]
        feature_df = pd.DataFrame(rows)

        # Serialize dict column to JSON string for parquet compatibility
        feature_df["endpoint_frequency"] = feature_df["endpoint_frequency"].apply(json.dumps)

        output_path = os.path.join(output_dir, f"features_{window_size}min.parquet")
        feature_df.to_parquet(output_path, index=False)
        results[f"{window_size}min"] = output_path
        logger.info("Saved → %s", output_path)

    return results
