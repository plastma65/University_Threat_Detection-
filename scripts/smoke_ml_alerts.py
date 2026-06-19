"""Smoke test: inject ML-generated alerts into the alerts table.

Usage:
    python scripts/smoke_ml_alerts.py

What it does:
    1. Build a 3-row synthetic feature DataFrame (bruteforce / recon / benign).
    2. Run real run_inference() — loads latest IsolationForest model.
    3. Persist anomalies via persist_alerts() — writes to alerts table.
    4. Print summary.

Verify in Grafana right after: refresh dashboard, set "Last 5 minutes",
new ML alerts (model_triggered=IsolationForest) should appear.
"""

from datetime import datetime, timedelta, timezone

import pandas as pd
from sqlalchemy.orm import Session

from src.api.database import engine
from src.ml_engine.inference_job import run_inference, persist_alerts


def main() -> None:
    now = datetime.now(timezone.utc)
    window_end = now.isoformat()
    window_start = (now - timedelta(minutes=15)).isoformat()

    features_df = pd.DataFrame([
        # Row 1 — bruteforce pattern (auth source)
        {
            "feature_id": f"smoke-bf-{now.timestamp():.0f}",
            "window_start": window_start, "window_end": window_end,
            "ip": "203.0.113.10", "source": "auth",
            "request_rate": 50.0, "login_fail_count": 30,
            "user_agent_entropy": 1.2, "bytes_per_request": 400.0,
            "unique_users": 5, "port_entropy": 3.5,
        },
        # Row 2 — recon pattern (firewall source)
        {
            "feature_id": f"smoke-rc-{now.timestamp():.0f}",
            "window_start": window_start, "window_end": window_end,
            "ip": "198.51.100.20", "source": "firewall",
            "request_rate": 120.0, "login_fail_count": 0,
            "user_agent_entropy": 0.0, "bytes_per_request": 60.0,
            "unique_users": 0, "port_entropy": 4.2,
        },
        # Row 3 — benign (will likely not flag)
        {
            "feature_id": f"smoke-bn-{now.timestamp():.0f}",
            "window_start": window_start, "window_end": window_end,
            "ip": "10.0.0.1", "source": "nginx",
            "request_rate": 1.0, "login_fail_count": 0,
            "user_agent_entropy": 0.5, "bytes_per_request": 200.0,
            "unique_users": 1, "port_entropy": 0.0,
        },
    ])

    print(f"[input] {len(features_df)} feature windows")
    predictions = run_inference(features_df)
    print(predictions[["ip", "source", "event_type", "is_anomaly",
                       "anomaly_score", "risk_score", "src_count"]].to_string())

    with Session(engine) as session:
        inserted = persist_alerts(session, predictions)
    print(f"[persist] {inserted} alerts written to DB")


if __name__ == "__main__":
    main()
