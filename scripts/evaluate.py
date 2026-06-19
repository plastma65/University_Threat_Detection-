"""Evaluate trained models on synthetic held-out + CICIDS2017 port_scan subset.

Usage:
    python scripts/evaluate.py --dataset synthetic --window 15min
    python scripts/evaluate.py --dataset cicids    --window 15min
    python scripts/evaluate.py --dataset all       --window 15min \
        --output docs/reports/metrics_week11.json

Models are NOT retrained — loaded from latest joblib in `models/`.
Preprocessing follows ML_FEATURE_REFERENCE.md exactly:
    src_count → fillna(0) → log1p(bytes_per_request) → scaler.transform
"""

from __future__ import annotations

import argparse
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.feature_engine.extractor import FeatureExtractor

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"
FEATURES_DIR = ROOT / "data" / "features"
CICIDS_PATH = (
    ROOT / "data" / "raw" / "benchmarks" / "cicids2017"
    / "Network-Flows" / "normalized_cicids2017-flow.parquet"
)

ATTACK_IPS = {"45.33.32.156", "192.241.175.65", "198.199.83.42"}
FEATURE_COLS = [
    "request_rate", "login_fail_count", "user_agent_entropy",
    "bytes_per_request", "unique_users", "port_entropy", "src_count",
]


# ---------- Model loading -------------------------------------------------


def _load_latest(window: str) -> dict:
    """Load scaler + 3 models for given window. Returns dict keyed by model name."""
    def latest(prefix: str) -> Path:
        files = sorted(MODELS_DIR.glob(f"{prefix}_{window}_*.joblib"), reverse=True)
        if not files:
            raise FileNotFoundError(f"No {prefix}_{window}_*.joblib in {MODELS_DIR}")
        return files[0]

    bundle = joblib.load(latest("scaler"))
    return {
        "scaler": bundle["scaler"] if isinstance(bundle, dict) else bundle,
        "isolation_forest": joblib.load(latest("isolation_forest")),
        "lof": joblib.load(latest("lof")),
        "ocsvm": joblib.load(latest("ocsvm")),
    }


# ---------- Preprocessing -------------------------------------------------


def _preprocess(features_df: pd.DataFrame, scaler) -> np.ndarray:
    """Match production inference: src_count → fillna(0) → log1p → scaler.transform."""
    df = features_df.copy()
    df["src_count"] = (
        (df["request_rate"].fillna(0) > 0).astype(int)
        + (df["login_fail_count"].fillna(0) > 0).astype(int)
        + (df["port_entropy"].fillna(0) > 0).astype(int)
    )
    X_raw = df[FEATURE_COLS].fillna(0).copy()
    X_raw["bytes_per_request"] = np.log1p(X_raw["bytes_per_request"])
    return scaler.transform(X_raw)


# ---------- Dataset loaders -----------------------------------------------


def load_synthetic(window: str) -> Tuple[pd.DataFrame, np.ndarray]:
    """Load pre-computed feature windows; y_true = ip ∈ ATTACK_IPS."""
    parquet = FEATURES_DIR / f"features_{window}.parquet"
    df = pd.read_parquet(parquet)
    y = df["ip"].isin(ATTACK_IPS).astype(int).to_numpy()
    print(f"[synthetic-{window}] {len(df):,} windows, "
          f"{int(y.sum()):,} attack ({y.mean()*100:.1f}%)")
    return df, y


def load_cicids_subset(window: str, sample_size: int = 50_000,
                       random_state: int = 42) -> Tuple[pd.DataFrame, np.ndarray]:
    """CICIDS2017 BENIGN + PortScan only — feature-extract via firewall flow.

    Notes
    -----
    * 2.43M rows stratified-sample down to `sample_size` to fit memory.
    * Only firewall-relevant features have signal (request_rate, port_entropy).
      Other 5 features will be near 0 — this is the dataset mismatch documented
      in week11-01-evaluation.md §Limitations.
    """
    if not CICIDS_PATH.exists():
        raise FileNotFoundError(f"CICIDS parquet missing: {CICIDS_PATH}")

    df = pd.read_parquet(CICIDS_PATH)
    sub = df[df["event_type"].isin(["normal", "port_scan"])].copy()
    if len(sub) > sample_size:
        per_class = sample_size // 2
        parts = [
            sub[sub["event_type"] == cls].sample(
                n=min(len(sub[sub["event_type"] == cls]), per_class),
                random_state=random_state,
            )
            for cls in ["normal", "port_scan"]
        ]
        sub = pd.concat(parts, ignore_index=True)
    print(f"[cicids-{window}] sampled {len(sub):,} rows "
          f"(normal={(sub.event_type=='normal').sum():,}, "
          f"port_scan={(sub.event_type=='port_scan').sum():,})")

    # Flatten nested metadata so extract_from_firewall finds dst_port at top level.
    def _flatten(meta_str: str) -> dict:
        try:
            md = json.loads(meta_str) if isinstance(meta_str, str) else meta_str
            return {"dst_port": str(md.get("Connection_Info", {}).get("destination_port", ""))}
        except Exception:
            return {"dst_port": ""}

    sub["metadata"] = sub["metadata"].apply(_flatten).apply(str)

    minutes = int(window.replace("min", ""))
    extractor = FeatureExtractor(window_minutes=minutes)
    fw_windows = extractor.extract_from_firewall(sub)
    if not fw_windows:
        raise RuntimeError("CICIDS feature extraction produced 0 windows")
    feat_df = pd.DataFrame([f.model_dump() for f in fw_windows])

    # Window-level y_true: any port_scan log in (ip, bucket) → attack
    sub["timestamp"] = pd.to_datetime(sub["timestamp"], utc=True)
    sub["_bucket"] = sub["timestamp"].dt.floor(f"{minutes}min")
    window_labels = (
        sub.groupby(["ip", "_bucket"])["event_type"]
        .apply(lambda v: int((v == "port_scan").any()))
        .reset_index(name="y")
    )
    window_labels["window_start"] = window_labels["_bucket"].dt.strftime(
        "%Y-%m-%dT%H:%M:%S+00:00"
    )
    merged = feat_df.merge(
        window_labels[["ip", "window_start", "y"]],
        on=["ip", "window_start"], how="left",
    )
    merged["y"] = merged["y"].fillna(0).astype(int)
    y = merged["y"].to_numpy()
    print(f"  -> {len(merged):,} feature windows, "
          f"{int(y.sum()):,} attack windows ({y.mean()*100:.1f}%)")
    return merged.drop(columns=["y"]), y


# ---------- Metrics -------------------------------------------------------


def _metrics_one_model(name: str, X: np.ndarray, y_true: np.ndarray, model) -> dict:
    """Run a model, compute Precision/Recall/F1/AUC, return dict."""
    pred = model.predict(X)
    y_pred = (pred == -1).astype(int)
    raw = -model.decision_function(X)  # higher = more anomalous
    out = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc":   float(roc_auc_score(y_true, raw)) if len(set(y_true)) > 1 else None,
        "n_flagged": int(y_pred.sum()),
        "n_true_positive":  int(((y_pred == 1) & (y_true == 1)).sum()),
        "n_false_positive": int(((y_pred == 1) & (y_true == 0)).sum()),
    }
    print(f"  {name:20s}  P={out['precision']:.3f}  R={out['recall']:.3f}  "
          f"F1={out['f1']:.3f}  AUC={out['roc_auc']:.3f}  "
          f"flagged={out['n_flagged']}")
    return out


def evaluate_dataset(features_df: pd.DataFrame, y_true: np.ndarray,
                     window: str, dataset_name: str) -> dict:
    artifacts = _load_latest(window)
    X = _preprocess(features_df, artifacts["scaler"])
    print(f"\n[{dataset_name}-{window}] predicting on {X.shape[0]:,} windows...")
    return {
        "dataset": dataset_name,
        "window": window,
        "n_windows": int(len(X)),
        "n_attack": int(y_true.sum()),
        "n_normal": int((y_true == 0).sum()),
        "metrics": {
            "isolation_forest":
                _metrics_one_model("IsolationForest", X, y_true, artifacts["isolation_forest"]),
            "lof":
                _metrics_one_model("LOF",             X, y_true, artifacts["lof"]),
            "ocsvm":
                _metrics_one_model("OneClassSVM",     X, y_true, artifacts["ocsvm"]),
        },
    }


# ---------- CLI -----------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dataset", choices=["synthetic", "cicids", "all"],
                        default="all")
    parser.add_argument("--window", choices=["5min", "15min"], default="15min")
    parser.add_argument("--output", default="docs/reports/metrics_week11.json",
                        help="Where to write JSON (set '' to skip)")
    parser.add_argument("--cicids-sample", type=int, default=50_000,
                        help="Rows to stratified-sample from CICIDS (default: 50000)")
    args = parser.parse_args()

    results = {"generated_at": datetime.now(timezone.utc).isoformat(), "runs": []}

    if args.dataset in {"synthetic", "all"}:
        df, y = load_synthetic(args.window)
        results["runs"].append(evaluate_dataset(df, y, args.window, "synthetic_heldout"))

    if args.dataset in {"cicids", "all"}:
        df, y = load_cicids_subset(args.window, sample_size=args.cicids_sample)
        results["runs"].append(evaluate_dataset(df, y, args.window, "cicids2017_portscan"))

    if args.output:
        out_path = ROOT / args.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2))
        print(f"\n[json] written {out_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
