"""Unit tests for the feature extraction engine."""

from collections import Counter
from math import log2

import pandas as pd
import pytest

from src.feature_engine.extractor import FeatureExtractor, shannon_entropy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nginx_row(ts: str, ip: str, path: str, bytes_sent: int = 500, ua: str = "bot/1.0") -> dict:
    return {
        "log_id": f"{ip}-{ts}",
        "timestamp": ts,
        "source": "nginx",
        "ip": ip,
        "user": None,
        "event_type": "request",
        "raw": "",
        "metadata": str(
            {"method": "GET", "path": path, "status": 200, "bytes": bytes_sent, "user_agent": ua}
        ),
    }


def _auth_row(ts: str, ip: str, user: str, event_type: str = "login_fail") -> dict:
    return {
        "log_id": f"{ip}-{ts}-{user}",
        "timestamp": ts,
        "source": "auth",
        "ip": ip,
        "user": user,
        "event_type": event_type,
        "raw": "",
        "metadata": "{}",
    }


def _fw_row(ts: str, ip: str, dst_port: int) -> dict:
    return {
        "log_id": f"{ip}-{ts}",
        "timestamp": ts,
        "source": "firewall",
        "ip": ip,
        "user": None,
        "event_type": "allow",
        "raw": "",
        "metadata": str({"protocol": "TCP", "dst_port": dst_port, "action": "allow"}),
    }


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------


def test_shannon_entropy_uniform_four_items():
    """Uniform distribution over 4 items → entropy = log2(4) = 2.0."""
    c = Counter({"a": 1, "b": 1, "c": 1, "d": 1})
    assert abs(shannon_entropy(c) - log2(4)) < 1e-9


def test_shannon_entropy_single_item():
    """Single item → entropy = 0."""
    assert shannon_entropy(Counter({"x": 100})) == 0.0


def test_shannon_entropy_empty():
    """Empty counter → entropy = 0."""
    assert shannon_entropy(Counter()) == 0.0


# ---------------------------------------------------------------------------
# extract_from_nginx
# ---------------------------------------------------------------------------


def test_extract_from_nginx_request_rate():
    """request_rate = total_requests / window_minutes."""
    ts = "2026-01-01T00:01:00+00:00"
    rows = [_nginx_row(ts, "10.0.0.1", "/api") for _ in range(10)]
    df = pd.DataFrame(rows)

    extractor = FeatureExtractor(window_minutes=5)
    features = extractor.extract_from_nginx(df)

    assert len(features) == 1
    fw = features[0]
    assert fw.ip == "10.0.0.1"
    assert abs(fw.request_rate - 10 / 5) < 1e-9


def test_extract_from_nginx_endpoint_frequency_top10():
    """endpoint_frequency should contain only top-10 endpoints."""
    base = "2026-01-01T00:01:00+00:00"
    rows = [_nginx_row(base, "1.2.3.4", f"/path/{i % 15}") for i in range(15)]
    df = pd.DataFrame(rows)

    extractor = FeatureExtractor(window_minutes=5)
    features = extractor.extract_from_nginx(df)

    assert len(features[0].endpoint_frequency) <= 10


def test_extract_from_nginx_bytes_per_request():
    """bytes_per_request is the mean of bytes field across records."""
    ts = "2026-01-01T00:01:00+00:00"
    rows = [_nginx_row(ts, "1.1.1.1", "/", bytes_sent=b) for b in [100, 200, 300]]
    df = pd.DataFrame(rows)

    extractor = FeatureExtractor(window_minutes=5)
    fw = extractor.extract_from_nginx(df)[0]
    assert abs(fw.bytes_per_request - 200.0) < 1e-6


def test_extract_from_nginx_skips_null_ip():
    """Records where ip is None/NaN must be skipped."""
    ts = "2026-01-01T00:01:00+00:00"
    rows = [_nginx_row(ts, None, "/x")]  # type: ignore[arg-type]
    rows[0]["ip"] = None
    df = pd.DataFrame(rows)

    extractor = FeatureExtractor(window_minutes=5)
    features = extractor.extract_from_nginx(df)
    assert features == []


# ---------------------------------------------------------------------------
# extract_from_auth
# ---------------------------------------------------------------------------


def test_extract_from_auth_login_fail_count():
    """login_fail_count counts only event_type == 'login_fail'."""
    ts = "2026-01-01T00:01:00+00:00"
    rows = [
        _auth_row(ts, "10.0.0.2", "alice", "login_fail"),
        _auth_row(ts, "10.0.0.2", "bob", "login_fail"),
        _auth_row(ts, "10.0.0.2", "carol", "login_success"),
    ]
    df = pd.DataFrame(rows)

    extractor = FeatureExtractor(window_minutes=5)
    fw = extractor.extract_from_auth(df)[0]
    assert fw.login_fail_count == 2
    assert fw.unique_users == 3


def test_extract_from_auth_unique_users():
    """unique_users counts distinct user values including None handling."""
    ts = "2026-01-01T00:01:00+00:00"
    rows = [
        _auth_row(ts, "10.0.0.5", "alice"),
        _auth_row(ts, "10.0.0.5", "alice"),
        _auth_row(ts, "10.0.0.5", "bob"),
    ]
    df = pd.DataFrame(rows)
    extractor = FeatureExtractor(window_minutes=5)
    fw = extractor.extract_from_auth(df)[0]
    assert fw.unique_users == 2


# ---------------------------------------------------------------------------
# merge_features
# ---------------------------------------------------------------------------


def test_merge_features_missing_auth_fills_zero():
    """IP present in nginx but absent from auth → login_fail_count = 0."""
    ts = "2026-01-01T00:01:00+00:00"
    nginx_df = pd.DataFrame([_nginx_row(ts, "5.5.5.5", "/home")])
    auth_df = pd.DataFrame(columns=["log_id", "timestamp", "source", "ip", "user", "event_type", "raw", "metadata"])

    extractor = FeatureExtractor(window_minutes=5)
    nginx_features = extractor.extract_from_nginx(nginx_df)
    auth_features = extractor.extract_from_auth(auth_df)
    fw_features = extractor.extract_from_firewall(
        pd.DataFrame(columns=["log_id", "timestamp", "source", "ip", "user", "event_type", "raw", "metadata"])
    )

    merged = extractor.merge_features(nginx_features, auth_features, fw_features)
    assert len(merged) == 1
    fw = merged[0]
    assert fw.ip == "5.5.5.5"
    assert fw.login_fail_count == 0
    assert fw.request_rate > 0  # from nginx


def test_merge_features_fields_combined():
    """Same (ip, window) in nginx + auth → both fields populated."""
    ts = "2026-01-01T00:01:00+00:00"
    nginx_df = pd.DataFrame([_nginx_row(ts, "9.9.9.9", "/api")])
    auth_df = pd.DataFrame([_auth_row(ts, "9.9.9.9", "eve", "login_fail")])

    extractor = FeatureExtractor(window_minutes=5)
    nginx_features = extractor.extract_from_nginx(nginx_df)
    auth_features = extractor.extract_from_auth(auth_df)

    merged = extractor.merge_features(nginx_features, auth_features, [])
    assert len(merged) == 1
    fw = merged[0]
    assert fw.request_rate > 0
    assert fw.login_fail_count == 1


def test_merge_features_source_priority_firewall_wins():
    """When firewall + auth + nginx all contribute to one window → source=firewall."""
    ts = "2026-01-01T00:01:00+00:00"
    nginx_df = pd.DataFrame([_nginx_row(ts, "1.1.1.1", "/")])
    auth_df = pd.DataFrame([_auth_row(ts, "1.1.1.1", "alice", "login_fail")])
    fw_df = pd.DataFrame([_fw_row(ts, "1.1.1.1", 443)])

    extractor = FeatureExtractor(window_minutes=5)
    merged = extractor.merge_features(
        extractor.extract_from_nginx(nginx_df),
        extractor.extract_from_auth(auth_df),
        extractor.extract_from_firewall(fw_df),
    )
    assert len(merged) == 1
    assert merged[0].source == "firewall"


def test_merge_features_source_single_source_preserved():
    """Only nginx contributes → source=nginx (no merge with other sources)."""
    ts = "2026-01-01T00:01:00+00:00"
    nginx_df = pd.DataFrame([_nginx_row(ts, "2.2.2.2", "/x")])

    extractor = FeatureExtractor(window_minutes=5)
    merged = extractor.merge_features(
        extractor.extract_from_nginx(nginx_df), [], []
    )
    assert len(merged) == 1
    assert merged[0].source == "nginx"


# ---------------------------------------------------------------------------
# Window boundary
# ---------------------------------------------------------------------------


def test_window_boundary_separates_into_two_windows():
    """Records at t=00:00 and t=00:05 (5-min window) must produce 2 FeatureWindows."""
    rows = [
        _nginx_row("2026-01-01T00:01:00+00:00", "7.7.7.7", "/a"),  # bucket 00:00
        _nginx_row("2026-01-01T00:05:00+00:00", "7.7.7.7", "/b"),  # bucket 00:05
    ]
    df = pd.DataFrame(rows)
    extractor = FeatureExtractor(window_minutes=5)
    features = extractor.extract_from_nginx(df)

    assert len(features) == 2
    starts = {fw.window_start for fw in features}
    assert len(starts) == 2


def test_window_boundary_same_bucket_merged():
    """Records within the same 5-min bucket for the same IP → 1 FeatureWindow."""
    rows = [
        _nginx_row("2026-01-01T00:01:00+00:00", "8.8.8.8", "/c"),
        _nginx_row("2026-01-01T00:03:30+00:00", "8.8.8.8", "/d"),
    ]
    df = pd.DataFrame(rows)
    extractor = FeatureExtractor(window_minutes=5)
    features = extractor.extract_from_nginx(df)

    assert len(features) == 1
    assert abs(features[0].request_rate - 2 / 5) < 1e-9
