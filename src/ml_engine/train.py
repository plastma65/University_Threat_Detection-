"""
ML Engine -- Anomaly Detection Training
Models: IsolationForest, LocalOutlierFactor, OneClassSVM
Contamination derived from actual attack rate in synthetic data.
"""

import json
import time
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix,
)

warnings.filterwarnings("ignore")

ATTACK_IPS = {
    "45.33.32.156",
    "185.220.101.45",
    "192.241.175.65",
    "117.21.191.136",
    "198.199.83.42",
}

# Features to use for training (ip_entropy dropped: r=0.85 with request_rate)
FEATURE_COLS = [
    "request_rate",
    "login_fail_count",
    "user_agent_entropy",
    "bytes_per_request",   # log-transformed before scaling
    "unique_users",
    "port_entropy",
    # src_count derived below
]

# Contamination from actual attack window rates (EDA week5-06)
CONTAMINATION = {5: 0.073, 15: 0.026}


def load_and_prepare(parquet_path: str, test_ratio: float = 0.2):
    df = pd.read_parquet(parquet_path)

    # src_count: number of log sources with non-zero signal for this IP+window.
    # NOTE: firewall with port_entropy=0 (single port scan) is not counted.
    # This is a known limitation — may undercount fw-only attackers.
    df["src_count"] = (
        (df["request_rate"] > 0).astype(int)
        + (df["login_fail_count"] > 0).astype(int)
        + (df["port_entropy"] > 0).astype(int)
    )

    cols = FEATURE_COLS + ["src_count"]
    X_raw = df[cols].fillna(0).copy()

    # Log-transform to compress ~47 MB outliers in bytes_per_request
    X_raw["bytes_per_request"] = np.log1p(X_raw["bytes_per_request"])

    # Temporal split — sort by window_start, 80% earliest -> train, 20% latest -> test
    df_sorted = df.sort_values("window_start").reset_index(drop=True)
    X_raw_sorted = X_raw.loc[df.sort_values("window_start").index].reset_index(drop=True)

    split_idx = int(len(df_sorted) * (1 - test_ratio))

    X_train_raw = X_raw_sorted.iloc[:split_idx]
    X_test_raw = X_raw_sorted.iloc[split_idx:]

    # Fit scaler ONLY on train set to avoid leakage
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    y_true_train = df_sorted["ip"].iloc[:split_idx].isin(ATTACK_IPS).astype(int).values
    y_true_test = df_sorted["ip"].iloc[split_idx:].isin(ATTACK_IPS).astype(int).values

    return X_train, X_test, y_true_train, y_true_test, scaler, cols, df_sorted, split_idx


def _build_models(contamination: float) -> dict:
    return {
        "isolation_forest": IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        ),
        "lof": LocalOutlierFactor(
            n_neighbors=20,
            contamination=contamination,
            novelty=True,
            n_jobs=-1,
        ),
        "ocsvm": OneClassSVM(
            kernel="rbf",
            nu=contamination,
            gamma="scale",
        ),
    }


def train_and_evaluate(
    X_train: np.ndarray, X_test: np.ndarray,
    y_train: np.ndarray, y_test: np.ndarray,
    contamination: float,
) -> dict:
    results = {}

    for name, model in _build_models(contamination).items():
        t0 = time.time()
        model.fit(X_train)
        elapsed = time.time() - t0

        pred = model.predict(X_test)          # -1 = anomaly, 1 = normal
        y_pred = (pred == -1).astype(int)
        scores = -model.decision_function(X_test)  # higher = more anomalous

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

        results[name] = {
            "model": model,
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall":    float(recall_score(y_test, y_pred, zero_division=0)),
            "f1":        float(f1_score(y_test, y_pred, zero_division=0)),
            "roc_auc":   float(roc_auc_score(y_test, scores)),
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "n_flagged": int(y_pred.sum()),
            "train_sec": round(elapsed, 2),
        }

    return results


def save_artifacts(
    results: dict, scaler, feature_cols: list,
    output_dir: str, window_min: int,
) -> dict:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    paths = {}
    scaler_path = out / f"scaler_{window_min}min_{ts}.joblib"
    joblib.dump({
        "scaler": scaler,
        "feature_cols": feature_cols,
        "transforms": {"bytes_per_request": "log1p"},  # Apply log1p BEFORE scaler
    }, str(scaler_path))
    paths["scaler"] = str(scaler_path)

    for name, res in results.items():
        model_path = out / f"{name}_{window_min}min_{ts}.joblib"
        joblib.dump(res["model"], str(model_path))
        paths[name] = str(model_path)

    return paths


def save_metrics_history(all_metrics: dict, output_dir: str) -> str:
    history_path = Path(output_dir) / "metrics_history.json"
    history = []
    if history_path.exists():
        with open(history_path) as f:
            history = json.load(f)

    history.append({
        "timestamp": datetime.now().isoformat(),
        "runs": all_metrics,
    })

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)

    return str(history_path)


def run_training(
    features_dir: str = "data/features",
    output_dir: str = "models",
    window_sizes: list = None,
) -> dict:
    if window_sizes is None:
        window_sizes = [5, 15]

    all_metrics = {}

    for w in window_sizes:
        parquet = Path(features_dir) / f"features_{w}min.parquet"
        if not parquet.exists():
            print(f"  [SKIP] {parquet} not found")
            continue

        cont = CONTAMINATION[w]
        X_train, X_test, y_true_train, y_true_test, scaler, feature_cols, df_sorted, split_idx = \
            load_and_prepare(str(parquet), test_ratio=0.2)

        n_total = len(X_train) + len(X_test)
        n_attack_test = int(y_true_test.sum())
        n_attack_train = int(y_true_train.sum())

        print(f"\n{'='*62}")
        print(f"Window : {w}-min  |  Total: {n_total:,}  |  Contamination: {cont}")
        print(f"Train  : {len(X_train):,} samples  |  Attack: {n_attack_train:,}"
              f" ({n_attack_train/max(len(X_train),1)*100:.1f}%)")
        print(f"Test   : {len(X_test):,} samples  |  Attack: {n_attack_test:,}"
              f" ({n_attack_test/max(len(X_test),1)*100:.1f}%)")
        print(f"Features ({len(feature_cols)}): {feature_cols}")
        print(f"{'='*62}")

        results = train_and_evaluate(X_train, X_test, y_true_train, y_true_test, cont)

        print(f"\n  {'Model':<22} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6}"
              f" {'TP':>6} {'FP':>6} {'FN':>6} {'Flagged':>8} {'Time':>6}")
        print(f"  {'-'*82}")
        for name, res in results.items():
            print(
                f"  {name:<22} {res['precision']:>6.3f} {res['recall']:>6.3f}"
                f" {res['f1']:>6.3f} {res['roc_auc']:>6.3f}"
                f" {res['tp']:>6} {res['fp']:>6} {res['fn']:>6}"
                f" {res['n_flagged']:>8,} {res['train_sec']:>5.1f}s"
            )

        paths = save_artifacts(results, scaler, feature_cols, output_dir, w)
        print(f"\n  Saved -> {output_dir}/")

        all_metrics[f"{w}min"] = {
            "contamination": cont,
            "split": "temporal_80_20",
            "n_total": n_total,
            "n_train": len(X_train),
            "n_test": len(X_test),
            "n_attack_train": n_attack_train,
            "n_attack_test": n_attack_test,
            "feature_cols": feature_cols,
            "metrics": {
                name: {k: v for k, v in res.items() if k != "model"}
                for name, res in results.items()
            },
            "model_paths": paths,
        }

    history_path = save_metrics_history(all_metrics, output_dir)
    print(f"\nMetrics history -> {history_path}")
    return all_metrics


if __name__ == "__main__":
    run_training()
