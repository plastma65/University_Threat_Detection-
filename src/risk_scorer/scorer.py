"""Risk Scoring Engine.

Formula
-------
    risk_score = anomaly_norm * 0.6 + severity_w * 0.3 + source_w * 0.1

All three components are on a 0-100 scale, so the weighted sum is also 0-100.
The final value is rounded to ``int`` because ``AlertCreate.risk_score`` is
typed as an integer in the API schema.

This module deliberately avoids importing anything from ``src/api/`` to keep
the scoring layer free of HTTP/DB concerns and to prevent circular imports
when the API later wants to use ``RiskScorer`` for ad-hoc scoring.
"""

from __future__ import annotations


_SEVERITY_WEIGHTS: dict[str, int] = {
    "bruteforce": 100,
    "recon": 75,
    "port_scan": 75,
    "scanning": 75,
    "anomaly": 40,
    "single_anomaly": 40,
}
_DEFAULT_SEVERITY_WEIGHT = 40

_SOURCE_WEIGHTS: dict[str, int] = {
    "firewall": 100,
    "auth": 80,
    "nginx": 60,
    "api": 40,
    "db": 20,
}
_DEFAULT_SOURCE_WEIGHT = 30


class RiskScorer:
    """Combine model output, source, and event type into a 0-100 risk score."""

    def __init__(self, alert_threshold: int = 70) -> None:
        self.alert_threshold = alert_threshold

    def normalize_anomaly_score(self, raw_score: float, score_max: float = 1.0) -> float:
        """Scale a raw anomaly score into the 0-100 range.

        ``raw_score`` is the (already negated) IsolationForest decision-function
        value — higher means more anomalous. ``score_max`` is the maximum raw
        score observed in the current batch, used as the upper reference.

        Edge case: ``score_max <= 0`` (degenerate batch with no positive scores)
        returns ``0.0`` instead of raising — callers should not have to guard.
        """
        if score_max <= 0:
            return 0.0
        clipped = max(0.0, min(float(raw_score), float(score_max)))
        return clipped / float(score_max) * 100.0

    def get_severity_weight(self, event_type: str) -> int:
        key = (event_type or "").strip().lower()
        return _SEVERITY_WEIGHTS.get(key, _DEFAULT_SEVERITY_WEIGHT)

    def get_source_weight(self, source: str) -> int:
        key = (source or "").strip().lower()
        return _SOURCE_WEIGHTS.get(key, _DEFAULT_SOURCE_WEIGHT)

    def calculate(
        self,
        raw_anomaly_score: float,
        source: str,
        event_type: str,
        score_max: float = 1.0,
    ) -> int:
        anomaly_norm = self.normalize_anomaly_score(raw_anomaly_score, score_max)
        severity_w = self.get_severity_weight(event_type)
        source_w = self.get_source_weight(source)

        raw = anomaly_norm * 0.6 + severity_w * 0.3 + source_w * 0.1
        risk = int(round(raw))
        return max(0, min(100, risk))

    def should_alert(self, risk_score: int) -> bool:
        return risk_score >= self.alert_threshold
