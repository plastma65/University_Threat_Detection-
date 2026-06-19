"""Unit tests for src.ml_engine.inference_job.

Mock strategy:
  - `_load_latest_artifacts` is monkeypatched to avoid joblib disk I/O.
  - `scaler.transform` and `model.predict` / `model.decision_function`
    are MagicMocks so we control the anomaly verdict per test.
  - PostgreSQL is never touched — `persist_alerts` receives a mocked Session.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

from src.ml_engine import inference_job
from src.ml_engine.inference_job import (
    FEATURE_COLS,
    persist_alerts,
    run_inference,
)


# ---------- Helpers ---------------------------------------------------------


def _make_feature_row(**overrides) -> dict:
    """One valid feature window row with sane defaults."""
    base = {
        "feature_id": "test-fid-1",
        "window_start": "2026-05-25T12:00:00+00:00",
        "window_end": "2026-05-25T12:15:00+00:00",
        "ip": "10.0.0.1",
        "source": "auth",
        "request_rate": 1.0,
        "login_fail_count": 0,
        "user_agent_entropy": 0.0,
        "bytes_per_request": 100.0,
        "unique_users": 0,
        "port_entropy": 0.0,
    }
    base.update(overrides)
    return base


def _patch_artifacts(monkeypatch, predict_value: int = -1, decision_value: float = 0.5):
    """Replace _load_latest_artifacts with mocks. predict=-1 => anomaly."""
    scaler = MagicMock(name="scaler")
    scaler.transform.side_effect = lambda X: np.asarray(X, dtype=float)

    model = MagicMock(name="model")
    model.predict.return_value = np.array([predict_value])
    model.decision_function.return_value = np.array([-decision_value])  # negated downstream

    monkeypatch.setattr(
        inference_job, "_load_latest_artifacts", lambda window="15min": (scaler, model)
    )
    return scaler, model


# ---------- run_inference tests --------------------------------------------


def test_run_inference_returns_empty_on_empty_input():
    out = run_inference(pd.DataFrame())
    assert out.empty


def test_run_inference_flags_bruteforce(monkeypatch):
    _patch_artifacts(monkeypatch, predict_value=-1, decision_value=0.7)
    df = pd.DataFrame([_make_feature_row(login_fail_count=30, port_entropy=0.5)])

    out = run_inference(df)

    assert len(out) == 1
    assert isinstance(out.iloc[0]["risk_score"], (int, np.integer))
    assert isinstance(out.iloc[0]["event_type"], str)
    assert out.iloc[0]["event_type"] == "bruteforce"  # login_fail > 10


def test_run_inference_preprocessing_order(monkeypatch):
    """bytes_per_request must be log1p-transformed BEFORE scaler.transform."""
    scaler, _ = _patch_artifacts(monkeypatch)
    raw_bytes = 999.0
    df = pd.DataFrame([_make_feature_row(bytes_per_request=raw_bytes)])

    run_inference(df)

    # Capture the array passed to scaler.transform (first positional arg).
    transform_input = scaler.transform.call_args[0][0]
    bytes_col_idx = FEATURE_COLS.index("bytes_per_request")
    transformed_value = float(np.asarray(transform_input)[0, bytes_col_idx])
    assert transformed_value == pytest.approx(np.log1p(raw_bytes))


def test_run_inference_src_count_derived_correctly(monkeypatch):
    _patch_artifacts(monkeypatch)
    # model returns single value — call separately for 2 rows.
    df1 = pd.DataFrame([_make_feature_row(request_rate=5, login_fail_count=0, port_entropy=0)])
    df2 = pd.DataFrame([_make_feature_row(request_rate=5, login_fail_count=3, port_entropy=2)])

    out1 = run_inference(df1)
    out2 = run_inference(df2)

    assert int(out1.iloc[0]["src_count"]) == 1  # only request_rate > 0
    assert int(out2.iloc[0]["src_count"]) == 3  # all three > 0


def test_run_inference_risk_score_is_int(monkeypatch):
    _patch_artifacts(monkeypatch, predict_value=-1, decision_value=0.4)
    df = pd.DataFrame([_make_feature_row(login_fail_count=15, port_entropy=3.0)])

    out = run_inference(df)

    risk = out.iloc[0]["risk_score"]
    assert isinstance(risk, (int, np.integer)), f"risk_score must be int, got {type(risk)}"
    assert 0 <= int(risk) <= 100


# ---------- persist_alerts tests -------------------------------------------


def _make_prediction_row(**overrides) -> dict:
    base = {
        "feature_id": "test-fid-1",
        "window_start": "2026-05-25T12:00:00+00:00",
        "window_end": "2026-05-25T12:15:00+00:00",
        "ip": "10.0.0.1",
        "source": "auth",
        "event_type": "anomaly",
        "request_rate": 1.0,
        "login_fail_count": 0,
        "user_agent_entropy": 0.0,
        "bytes_per_request": 100.0,
        "unique_users": 0,
        "port_entropy": 0.0,
        "src_count": 1,
        "is_anomaly": True,
        "anomaly_score": 0.5,
        "risk_score": 75,
    }
    base.update(overrides)
    return base


def test_persist_alerts_skips_non_anomalies():
    session = MagicMock()
    df = pd.DataFrame([_make_prediction_row(is_anomaly=False)])

    inserted = persist_alerts(session, df)

    assert inserted == 0
    session.add_all.assert_not_called()


def test_persist_alerts_inserts_anomaly_rows():
    session = MagicMock()
    df = pd.DataFrame([
        _make_prediction_row(is_anomaly=True, risk_score=80),
        _make_prediction_row(is_anomaly=False, risk_score=10),
    ])

    inserted = persist_alerts(session, df)

    assert inserted == 1
    session.add_all.assert_called_once()
    alerts_arg = session.add_all.call_args[0][0]
    assert len(alerts_arg) == 1
    assert isinstance(alerts_arg[0].risk_score, int)
    assert alerts_arg[0].risk_score == 80


@pytest.mark.parametrize(
    "risk_score,expected_severity",
    [(95, "critical"), (75, "high"), (50, "medium")],
)
def test_persist_alerts_severity_mapping(risk_score, expected_severity):
    session = MagicMock()
    df = pd.DataFrame([_make_prediction_row(is_anomaly=True, risk_score=risk_score)])

    persist_alerts(session, df)

    alert = session.add_all.call_args[0][0][0]
    assert alert.severity == expected_severity
