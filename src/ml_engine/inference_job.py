"""ML inference bridge job: Normalized logs in, alerts out.

This script is a runnable skeleton for model inference integration.
It fetches recent normalized logs, builds features, runs a placeholder
prediction step, and writes anomaly alerts to PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from src.api.database import engine
from src.api.models.alert import AlertDB
from src.feature_engine.extractor import FeatureExtractor
from src.normalizer.db import NormalizedLogDB
from src.risk_scorer.scorer import RiskScorer


# Feature order must match training (see ML_FEATURE_REFERENCE.md).
# ip_entropy is intentionally absent — dropped due to r=0.85 with request_rate.
FEATURE_COLS = [
    "request_rate",
    "login_fail_count",
    "user_agent_entropy",
    "bytes_per_request",  # log1p applied before scaling
    "unique_users",
    "port_entropy",
    "src_count",  # derived at runtime
]

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"


def fetch_recent_logs(session: Session, minutes: int = 15) -> pd.DataFrame:
    """Fetch logs from the last `minutes` and return a DataFrame.

    Note: NormalizedLogDB.timestamp is stored as ISO8601 string in current schema,
    so lexical comparison is used with an ISO cutoff.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    cutoff_iso = cutoff.isoformat()

    rows = (
        session.query(NormalizedLogDB)
        .filter(NormalizedLogDB.timestamp >= cutoff_iso)
        .order_by(NormalizedLogDB.timestamp.asc())
        .all()
    )

    records = [
        {
            "log_id": r.log_id,
            "timestamp": r.timestamp,
            "source": r.source,
            "ip": r.ip,
            "user": r.user,
            "event_type": r.event_type,
            "raw": r.raw,
            "metadata": r.log_metadata or {},
        }
        for r in rows
    ]
    return pd.DataFrame(records)


def build_features(logs_df: pd.DataFrame, window_minutes: int = 15) -> pd.DataFrame:
    """Run FeatureExtractor and return merged features as DataFrame."""
    if logs_df.empty:
        return pd.DataFrame()

    extractor = FeatureExtractor(window_minutes=window_minutes)

    nginx_df = logs_df[logs_df["source"] == "nginx"].copy()
    auth_df = logs_df[logs_df["source"] == "auth"].copy()
    firewall_df = logs_df[logs_df["source"] == "firewall"].copy()

    nginx_features = extractor.extract_from_nginx(nginx_df) if not nginx_df.empty else []
    auth_features = extractor.extract_from_auth(auth_df) if not auth_df.empty else []
    firewall_features = extractor.extract_from_firewall(firewall_df) if not firewall_df.empty else []

    merged = extractor.merge_features(nginx_features, auth_features, firewall_features)
    if not merged:
        return pd.DataFrame()

    return pd.DataFrame([f.model_dump() for f in merged])


def _load_latest_artifacts(window: str = "15min") -> tuple[object, object]:
    """Load the most recent scaler bundle and IsolationForest model for `window`."""
    scaler_files = sorted(MODELS_DIR.glob(f"scaler_{window}_*.joblib"), reverse=True)
    model_files = sorted(MODELS_DIR.glob(f"isolation_forest_{window}_*.joblib"), reverse=True)
    if not scaler_files or not model_files:
        raise FileNotFoundError(
            f"Missing scaler_{window}_*.joblib or isolation_forest_{window}_*.joblib in {MODELS_DIR}"
        )
    scaler_bundle = joblib.load(scaler_files[0])
    model = joblib.load(model_files[0])
    return scaler_bundle["scaler"], model


def _classify_event_type(login_fail: float, port_ent: float) -> str:
    if login_fail > 10:
        return "bruteforce"
    if port_ent > 2.0:
        return "recon"
    return "anomaly"


def run_inference(features_df: pd.DataFrame) -> pd.DataFrame:
    """Run IsolationForest on the feature window batch.

    Pipeline (order matters — see ML_FEATURE_REFERENCE.md):
      1) Derive `src_count` before any imputation.
      2) Impute missing values with 0.
      3) Apply `log1p` to `bytes_per_request` BEFORE scaling.
      4) Transform with the trained scaler (never `fit`).
      5) `predict` + negate `decision_function` (higher = more anomalous).
      6) Map heuristic event_type from feature thresholds.
      7) Compute risk_score per row via RiskScorer.
    """
    if features_df.empty:
        return pd.DataFrame()

    scaler_obj, model = _load_latest_artifacts(window="15min")

    df = features_df.copy()

    # Step 1 — derive src_count from raw features (before fillna so we use real signals).
    df["src_count"] = (
        (df["request_rate"].fillna(0) > 0).astype(int)
        + (df["login_fail_count"].fillna(0) > 0).astype(int)
        + (df["port_entropy"].fillna(0) > 0).astype(int)
    )

    # Step 2-3 — impute then log-transform bytes_per_request.
    X_raw = df[FEATURE_COLS].fillna(0).copy()
    X_raw["bytes_per_request"] = np.log1p(X_raw["bytes_per_request"])

    # Step 4 — transform with trained scaler. Never call fit/fit_transform here.
    X_scaled = scaler_obj.transform(X_raw)

    # Step 5 — predict and negate decision_function.
    pred = model.predict(X_scaled)
    raw_score = -model.decision_function(X_scaled)
    is_anomaly = pred == -1

    # Step 6 — heuristic event_type per row.
    event_types = [
        _classify_event_type(lf, pe)
        for lf, pe in zip(df["login_fail_count"].fillna(0), df["port_entropy"].fillna(0))
    ]

    # source isn't a feature column (windows are merged across sources by ip+window),
    # so fall back to "unknown" unless a source column was carried in upstream.
    if "source" in df.columns:
        df["source"] = df["source"].fillna("unknown").astype(str)
    else:
        df["source"] = "unknown"

    df["is_anomaly"] = is_anomaly
    df["anomaly_score"] = raw_score
    df["event_type"] = event_types

    # Step 7 — risk score per row, using batch-max as the normalization reference.
    scorer = RiskScorer(alert_threshold=70)
    batch_max = float(raw_score.max()) if raw_score.size and raw_score.max() > 0 else 1.0
    df["risk_score"] = [
        scorer.calculate(
            raw_anomaly_score=float(raw_score[i]),
            source=str(df.iloc[i]["source"]),
            event_type=str(df.iloc[i]["event_type"]),
            score_max=batch_max,
        )
        for i in range(len(df))
    ]

    return df


def persist_alerts(session: Session, predictions_df: pd.DataFrame) -> int:
    """Persist anomaly rows as AlertDB records. Returns inserted count."""
    if predictions_df.empty:
        return 0

    anomalies = predictions_df[predictions_df["is_anomaly"] == True]
    if anomalies.empty:
        return 0

    alerts: list[AlertDB] = []
    for _, row in anomalies.iterrows():
        ts = pd.to_datetime(row["window_end"], utc=True).to_pydatetime()
        risk = int(row["risk_score"])
        if risk >= 90:
            severity = "critical"
        elif risk >= 70:
            severity = "high"
        else:
            severity = "medium"

        alerts.append(
            AlertDB(
                timestamp=ts,
                source=str(row.get("source", "ml_inference")),
                event_type=str(row.get("event_type", "anomaly_detected")),
                severity=severity,
                ip_address=row.get("ip"),
                user_identifier=None,
                evidence={
                    "model_triggered": "IsolationForest",
                    "anomaly_score": float(row["anomaly_score"]),
                    "raw_anomaly_score": float(row["anomaly_score"]),
                    "is_anomaly": bool(row["is_anomaly"]),
                    "event_type": row.get("event_type", "anomaly"),
                    "feature_id": row.get("feature_id"),
                    "window_start": str(row.get("window_start", "")),
                    "window_end": str(row.get("window_end", "")),
                    "request_rate": float(row.get("request_rate", 0.0)),
                    "login_fail_count": int(row.get("login_fail_count", 0)),
                    "port_entropy": float(row.get("port_entropy", 0.0)),
                    "user_agent_entropy": float(row.get("user_agent_entropy", 0.0)),
                    "bytes_per_request": float(row.get("bytes_per_request", 0.0)),
                    "unique_users": int(row.get("unique_users", 0)),
                    "src_count": int(row.get("src_count", 0)),
                },
                risk_score=risk,
            )
        )

    session.add_all(alerts)
    session.commit()
    return len(alerts)


def run_inference_job(minutes: int = 15) -> int:
    """Execute one inference cycle. Returns number of alerts written."""
    with Session(engine) as session:
        logs_df = fetch_recent_logs(session, minutes=minutes)
        features_df = build_features(logs_df, window_minutes=minutes)
        predictions_df = run_inference(features_df)
        written = persist_alerts(session, predictions_df)
        return written


if __name__ == "__main__":
    inserted = run_inference_job(minutes=15)
    print(f"Inference job complete. Inserted {inserted} alerts.")
