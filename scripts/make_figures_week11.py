"""Generate paper figures from metrics_week11.json + held-out predictions.

Outputs (saved to docs/reports/):
    fig_roc_curves.png         — ROC curves of 3 models on synthetic held-out
    fig_metrics_comparison.png — grouped bar of Precision/Recall/F1 on synthetic
    fig_feature_importance.png — permutation importance of IForest features

Re-runs the same load + preprocess pipeline as evaluate.py to get raw scores
(metrics_week11.json only stores summary stats, not per-sample scores).
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_curve, roc_auc_score

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "docs" / "reports"
MODELS = ROOT / "models"
FEATURES_DIR = ROOT / "data" / "features"

ATTACK_IPS = {"45.33.32.156", "192.241.175.65", "198.199.83.42"}
FEATURE_COLS = [
    "request_rate", "login_fail_count", "user_agent_entropy",
    "bytes_per_request", "unique_users", "port_entropy", "src_count",
]

COLORS = {"IsolationForest": "#1f77b4", "LOF": "#ff7f0e", "OneClassSVM": "#2ca02c"}


def _latest(prefix: str, window: str) -> Path:
    return sorted(MODELS.glob(f"{prefix}_{window}_*.joblib"), reverse=True)[0]


def _prep_synthetic(window: str = "15min"):
    df = pd.read_parquet(FEATURES_DIR / f"features_{window}.parquet")
    y = df["ip"].isin(ATTACK_IPS).astype(int).to_numpy()

    bundle = joblib.load(_latest("scaler", window))
    scaler = bundle["scaler"] if isinstance(bundle, dict) else bundle

    df = df.copy()
    df["src_count"] = (
        (df["request_rate"].fillna(0) > 0).astype(int)
        + (df["login_fail_count"].fillna(0) > 0).astype(int)
        + (df["port_entropy"].fillna(0) > 0).astype(int)
    )
    X_raw = df[FEATURE_COLS].fillna(0).copy()
    X_raw["bytes_per_request"] = np.log1p(X_raw["bytes_per_request"])
    X = scaler.transform(X_raw)
    return X, y


def fig_roc_curves(X: np.ndarray, y: np.ndarray, window: str) -> None:
    models = {
        "IsolationForest": joblib.load(_latest("isolation_forest", window)),
        "LOF":             joblib.load(_latest("lof", window)),
        "OneClassSVM":     joblib.load(_latest("ocsvm", window)),
    }
    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    for name, m in models.items():
        score = -m.decision_function(X)  # higher = more anomalous
        fpr, tpr, _ = roc_curve(y, score)
        auc = roc_auc_score(y, score)
        ax.plot(fpr, tpr, label=f"{name} (AUC = {auc:.3f})",
                color=COLORS[name], linewidth=2)
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray",
            linewidth=1, label="Random baseline")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(f"ROC Curves — Synthetic Held-out ({window} windows)")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    out = REPORTS / "fig_roc_curves.png"
    plt.savefig(out)
    plt.close()
    print(f"[fig] {out.name}")


def fig_metrics_comparison() -> None:
    metrics = json.loads((REPORTS / "metrics_week11.json").read_text())
    syn = next(r for r in metrics["runs"] if r["dataset"] == "synthetic_heldout")
    labels = ["IsolationForest", "LOF", "OneClassSVM"]
    keys = ["isolation_forest", "lof", "ocsvm"]
    bars = ["precision", "recall", "f1"]

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    x = np.arange(len(bars))
    width = 0.25
    for i, (label, key) in enumerate(zip(labels, keys)):
        vals = [syn["metrics"][key][b] for b in bars]
        ax.bar(x + i * width, vals, width, label=label, color=COLORS[label])
    ax.set_xticks(x + width)
    ax.set_xticklabels([b.capitalize() for b in bars])
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.set_title("Detection Performance — Synthetic Held-out (15-min windows)")
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    out = REPORTS / "fig_metrics_comparison.png"
    plt.savefig(out)
    plt.close()
    print(f"[fig] {out.name}")


def fig_feature_importance(X: np.ndarray, y: np.ndarray, window: str) -> None:
    """Permutation importance for IForest — drop in AUC when feature is shuffled."""
    model = joblib.load(_latest("isolation_forest", window))

    def scorer(estimator, X_in, y_in):
        return roc_auc_score(y_in, -estimator.decision_function(X_in))

    # Sample to keep runtime reasonable.
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X), size=min(5_000, len(X)), replace=False)
    result = permutation_importance(
        model, X[idx], y[idx], scoring=scorer,
        n_repeats=5, random_state=42, n_jobs=-1,
    )
    order = np.argsort(result.importances_mean)
    feat_sorted = [FEATURE_COLS[i] for i in order]
    means = result.importances_mean[order]

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    ax.barh(feat_sorted, means, color="#1f77b4", alpha=0.85)
    ax.set_xlabel("Permutation importance (drop in ROC-AUC)")
    ax.set_title(f"IsolationForest Feature Importance ({window} windows)")
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    out = REPORTS / "fig_feature_importance.png"
    plt.savefig(out)
    plt.close()
    print(f"[fig] {out.name}  (top 3: {[f'{n}={v:.3f}' for n, v in zip(reversed(feat_sorted), reversed(means))][:3]})")


def main() -> None:
    print(f"Generating figures into {REPORTS}/\n")
    X, y = _prep_synthetic(window="15min")
    fig_roc_curves(X, y, window="15min")
    fig_metrics_comparison()
    fig_feature_importance(X, y, window="15min")


if __name__ == "__main__":
    main()
