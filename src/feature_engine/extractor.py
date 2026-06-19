"""Feature extraction from normalized log DataFrames."""

import ast
import json
from collections import Counter
from math import log2
from typing import Dict, List, Tuple
from uuid import uuid4

import pandas as pd

from .schemas import FeatureWindow


def shannon_entropy(counter: Counter) -> float:
    """Compute Shannon entropy (bits) from a frequency counter."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * log2(c / total) for c in counter.values() if c > 0)


def _parse_metadata(value) -> dict:
    """Return metadata as dict regardless of storage format (JSON string or Python dict string)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        # Try JSON first (handles null, true, false)
        try:
            result = json.loads(value)
            if isinstance(result, dict):
                return result
        except (ValueError, json.JSONDecodeError):
            pass
        # Fallback: Python dict literal (handles None, True, False)
        try:
            result = ast.literal_eval(value)
            if isinstance(result, dict):
                return result
        except (ValueError, SyntaxError):
            pass
    return {}


class FeatureExtractor:
    """Extract feature windows from normalized log DataFrames.

    Args:
        window_minutes: Width of each time bucket in minutes (e.g. 5 or 15).
    """

    def __init__(self, window_minutes: int) -> None:
        self.window_minutes = window_minutes

    # ------------------------------------------------------------------
    # Public extraction methods
    # ------------------------------------------------------------------

    def extract_from_nginx(self, df: pd.DataFrame) -> List[FeatureWindow]:
        """Extract features from a normalized nginx DataFrame.

        Expected columns: log_id, timestamp, ip, event_type, metadata.
        metadata fields used: path, bytes, user_agent.

        Returns one FeatureWindow per (ip, time_bucket) pair.
        """
        df = self._prepare(df)
        meta = df["metadata"].apply(_parse_metadata)
        df["_path"] = meta.apply(lambda m: str(m.get("path", "") or ""))
        df["_bytes"] = meta.apply(lambda m: float(m.get("bytes", 0) or 0))
        df["_ua"] = meta.apply(lambda m: str(m.get("user_agent", "") or ""))

        # ip_entropy is a window-level stat: entropy of all IPs in the same bucket
        bucket_ip_entropy: Dict[pd.Timestamp, float] = {}
        for bucket, bdf in df.groupby("_bucket"):
            bucket_ip_entropy[bucket] = shannon_entropy(Counter(bdf["ip"].dropna()))

        results: List[FeatureWindow] = []
        for (ip, bucket), grp in df.groupby(["ip", "_bucket"]):
            if not ip or pd.isna(ip):
                continue
            window_start, window_end = self._window_bounds(bucket)
            results.append(
                FeatureWindow(
                    feature_id=str(uuid4()),
                    window_start=window_start,
                    window_end=window_end,
                    window_size_min=self.window_minutes,
                    ip=str(ip),
                    request_rate=len(grp) / self.window_minutes,
                    login_fail_count=0,
                    ip_entropy=bucket_ip_entropy.get(bucket, 0.0),
                    endpoint_frequency=dict(Counter(grp["_path"].tolist()).most_common(10)),
                    unique_users=0,
                    user_agent_entropy=shannon_entropy(Counter(grp["_ua"].tolist())),
                    bytes_per_request=float(grp["_bytes"].mean()),
                    port_entropy=0.0,
                    source="nginx",
                    label=None,
                )
            )
        return results

    def extract_from_auth(self, df: pd.DataFrame) -> List[FeatureWindow]:
        """Extract features from a normalized auth DataFrame.

        Expected columns: timestamp, ip, user, event_type.
        event_type values: login_fail | login_success | auth_event | session_close.

        Returns one FeatureWindow per (ip, time_bucket) pair.
        """
        df = self._prepare(df)

        results: List[FeatureWindow] = []
        for (ip, bucket), grp in df.groupby(["ip", "_bucket"]):
            if not ip or pd.isna(ip):
                continue
            window_start, window_end = self._window_bounds(bucket)
            results.append(
                FeatureWindow(
                    feature_id=str(uuid4()),
                    window_start=window_start,
                    window_end=window_end,
                    window_size_min=self.window_minutes,
                    ip=str(ip),
                    request_rate=0.0,
                    login_fail_count=int((grp["event_type"] == "login_fail").sum()),
                    ip_entropy=0.0,
                    endpoint_frequency={},
                    unique_users=int(grp["user"].dropna().nunique()),
                    user_agent_entropy=0.0,
                    bytes_per_request=0.0,
                    port_entropy=0.0,
                    source="auth",
                    label=None,
                )
            )
        return results

    def extract_from_firewall(self, df: pd.DataFrame) -> List[FeatureWindow]:
        """Extract features from a normalized firewall DataFrame.

        Expected columns: timestamp, ip, metadata.
        metadata fields used: dst_port.

        Returns one FeatureWindow per (ip, time_bucket) pair.
        """
        df = self._prepare(df)
        meta = df["metadata"].apply(_parse_metadata)
        df["_dst_port"] = meta.apply(lambda m: str(m.get("dst_port", "") or ""))

        results: List[FeatureWindow] = []
        for (ip, bucket), grp in df.groupby(["ip", "_bucket"]):
            if not ip or pd.isna(ip):
                continue
            window_start, window_end = self._window_bounds(bucket)
            results.append(
                FeatureWindow(
                    feature_id=str(uuid4()),
                    window_start=window_start,
                    window_end=window_end,
                    window_size_min=self.window_minutes,
                    ip=str(ip),
                    request_rate=0.0,
                    login_fail_count=0,
                    ip_entropy=0.0,
                    endpoint_frequency={},
                    unique_users=0,
                    user_agent_entropy=0.0,
                    bytes_per_request=0.0,
                    port_entropy=shannon_entropy(Counter(grp["_dst_port"].tolist())),
                    source="firewall",
                    label=None,
                )
            )
        return results

    # Priority for selecting dominant source when multiple sources contribute
    # to the same (ip, window). Firewall first because firewall events are
    # the strongest single signal (port scans, blocks) per project domain.
    _SOURCE_PRIORITY = ("firewall", "auth", "nginx")

    def merge_features(
        self,
        nginx_features: List[FeatureWindow],
        auth_features: List[FeatureWindow],
        firewall_features: List[FeatureWindow],
    ) -> List[FeatureWindow]:
        """Merge feature windows from all sources via outer join on (ip, window_start).

        For each (ip, window_start) pair, fields from whichever source has data are
        combined. Missing numeric fields default to 0 / 0.0. The `source` field on
        the merged window is set to the highest-priority contributing source
        (firewall > auth > nginx) so downstream alerts can be attributed correctly.
        """
        merged: Dict[Tuple[str, str], dict] = {}
        contributing_sources: Dict[Tuple[str, str], set] = {}

        for fw_list in [nginx_features, auth_features, firewall_features]:
            for fw in fw_list:
                key = (fw.ip, fw.window_start)
                if key not in merged:
                    merged[key] = {
                        "feature_id": str(uuid4()),
                        "window_start": fw.window_start,
                        "window_end": fw.window_end,
                        "window_size_min": fw.window_size_min,
                        "ip": fw.ip,
                        "request_rate": 0.0,
                        "login_fail_count": 0,
                        "ip_entropy": 0.0,
                        "endpoint_frequency": {},
                        "unique_users": 0,
                        "user_agent_entropy": 0.0,
                        "bytes_per_request": 0.0,
                        "port_entropy": 0.0,
                        "source": None,
                        "label": None,
                    }
                    contributing_sources[key] = set()
                rec = merged[key]
                if fw.source:
                    contributing_sources[key].add(fw.source)
                if fw.request_rate > 0:
                    rec["request_rate"] = fw.request_rate
                if fw.login_fail_count > 0:
                    rec["login_fail_count"] = fw.login_fail_count
                if fw.ip_entropy > 0:
                    rec["ip_entropy"] = fw.ip_entropy
                if fw.endpoint_frequency:
                    rec["endpoint_frequency"] = fw.endpoint_frequency
                if fw.unique_users > 0:
                    rec["unique_users"] = fw.unique_users
                if fw.user_agent_entropy > 0:
                    rec["user_agent_entropy"] = fw.user_agent_entropy
                if fw.bytes_per_request > 0:
                    rec["bytes_per_request"] = fw.bytes_per_request
                if fw.port_entropy > 0:
                    rec["port_entropy"] = fw.port_entropy
                if fw.label is not None:
                    rec["label"] = fw.label

        for key, sources in contributing_sources.items():
            for candidate in self._SOURCE_PRIORITY:
                if candidate in sources:
                    merged[key]["source"] = candidate
                    break

        return [FeatureWindow(**data) for data in merged.values()]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _prepare(self, df: pd.DataFrame) -> pd.DataFrame:
        """Parse timestamps and compute time_bucket column in-place on a copy."""
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df["_bucket"] = df["timestamp"].dt.floor(f"{self.window_minutes}min")
        return df

    def _window_bounds(self, bucket: pd.Timestamp) -> Tuple[str, str]:
        """Return (window_start, window_end) as ISO8601 strings for a bucket."""
        window_end = bucket + pd.Timedelta(minutes=self.window_minutes)
        return bucket.isoformat(), window_end.isoformat()
