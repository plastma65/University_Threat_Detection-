# 5. Experimental Results

> *Draft for paper §5. All numbers from `scripts/evaluate.py` run on 2026-05-25.
> Raw metrics: `docs/reports/metrics_week11.json`. Figures: `docs/reports/fig_*.png`.*

## 5.1 Dataset and Evaluation Setup

We evaluate the proposed framework on three data sources:

1. **Synthetic university log corpus** — 150,000 logs generated to mimic Nginx
   access traces, Linux auth events, and pfSense firewall records. Three known
   attacker IP addresses (45.33.32.156, 192.241.175.65, 198.199.83.42) inject
   port-scanning, credential-stuffing, and brute-force patterns across the
   week-long timeline (2026-01-01 → 2026-01-07).

2. **CICIDS2017 port-scan subset** — a stratified 50,000-row sample drawn from
   the 2.83M-flow CICIDS2017 network capture, keeping only `BENIGN` and
   `PortScan` records. Used as an *out-of-distribution* benchmark to probe
   generalization beyond the training domain.

3. **Real university lab logs** — 3,611 normalized records loaded into
   PostgreSQL from production-style Nginx/auth/firewall sources (qualitative
   analysis only; no ground-truth labels).

**Feature extraction** uses a 15-minute sliding window with seven engineered
features: `request_rate`, `login_fail_count`, `user_agent_entropy`,
`bytes_per_request` (log1p-transformed), `unique_users`, `port_entropy`, and a
derived `src_count` (number of sources contributing to the window). All
preprocessing is identical at training and inference time.

**Models.** Three unsupervised anomaly detectors are trained on the synthetic
corpus only (no benchmark data leaked into training): IsolationForest
(n_estimators=200, contamination=0.026), LocalOutlierFactor (n_neighbors=20,
novelty=True), and OneClassSVM (kernel=rbf, nu=0.026). Hyperparameters were
selected via grid search on a temporally held-out validation split (Week 7–8).

**Evaluation methodology.** Because the models are unsupervised, we use ground
truth labels *only* for evaluation. For the synthetic corpus, a feature window
is labeled *attack* iff its source IP belongs to the known attacker set. For
CICIDS2017, a window is labeled *attack* iff any flow within it is tagged
`PortScan`. Metrics are computed at the feature-window level.

## 5.2 Detection Performance

Table 1 reports Precision, Recall, F1, and ROC-AUC on the synthetic held-out
set (90,822 windows, 1,440 attack — 1.6%).

**Table 1 — Synthetic held-out (15-min windows)**

| Model              | Precision | Recall | F1    | ROC-AUC |
|--------------------|-----------|--------|-------|---------|
| **IsolationForest** | **0.607** | **0.980** | **0.750** | **0.997** |
| LocalOutlierFactor | 0.203     | 0.278  | 0.235 | 0.683   |
| OneClassSVM        | 0.039     | 0.957  | 0.074 | 0.963   |

IsolationForest is the clear winner: it ranks anomalies almost perfectly
(AUC = 0.997) and achieves the best operating point (F1 = 0.750) at the
trained contamination threshold. LOF struggles on both ranking and the
contamination threshold, likely because the high-dimensional sparse feature
space contains many small local clusters that confuse density-based scoring.
OneClassSVM ranks well (AUC = 0.963) but its decision boundary is too loose —
it flags 35,586 of 90,822 windows, yielding precision below 4%.

Figure 1 shows the ROC curves; Figure 2 shows the per-metric bar comparison.

![Figure 1 — ROC curves](../docs/reports/fig_roc_curves.png)

![Figure 2 — Metrics comparison](../docs/reports/fig_metrics_comparison.png)

**Table 2 — CICIDS2017 port-scan subset (15-min windows, 50K-flow sample)**

| Model              | Precision | Recall | F1    | ROC-AUC |
|--------------------|-----------|--------|-------|---------|
| IsolationForest    | 0.125     | 0.429  | 0.194 | 0.892   |
| LocalOutlierFactor | 0.004     | 0.857  | 0.008 | 0.723   |
| OneClassSVM        | 0.001     | 1.000  | 0.003 | 0.910   |

On the out-of-distribution CICIDS port-scan subset, ROC-AUC for IsolationForest
remains strong (0.892), indicating the model still ranks attack flows above
benign ones reasonably well. However, F1 collapses across all three models
because only two of seven trained features (`port_entropy`, `request_rate`)
carry signal in CICIDS network-flow data — the remaining five features
(`login_fail_count`, `user_agent_entropy`, `bytes_per_request`, `unique_users`,
`src_count`) are near zero. This *feature-domain mismatch* is the dominant
failure mode and is discussed further in §5.5.

## 5.3 Feature Importance

Permutation importance of IsolationForest on the synthetic held-out set
(5,000-window sample, 5 repeats) ranks the features by drop in ROC-AUC when
shuffled (Figure 3). The top three discriminators are `login_fail_count`,
`src_count`, and `user_agent_entropy`. The absolute magnitudes are small
because the model achieves near-perfect AUC and individual features are
partially redundant.

![Figure 3 — Feature importance](../docs/reports/fig_feature_importance.png)

## 5.4 End-to-End Latency

The production inference pipeline (`scripts/run_inference_loop.py`) was timed
on the real university lab data: **0.13 seconds** to process 643 records in
the 15-minute window, including SQLAlchemy fetch, feature extraction,
IsolationForest prediction, risk scoring, and alert persistence. This
satisfies the 1-minute soft latency requirement for a SOC-lite deployment
with margin to spare.

## 5.5 Qualitative Analysis — Real University Logs

To validate the pipeline against realistic, unlabeled data, we loaded 3,611
normalized log records from heterogeneous sources (Nginx 75 rows, firewall 83
rows, auth 33 rows, web_scanner 224 rows, secrepo_auth 1 row in the recent
15-minute window) into the PostgreSQL instance and ran the inference loop
once. The pipeline produced four alerts:

| IP              | event_type | severity | risk_score | source   |
|-----------------|------------|----------|------------|----------|
| 45.33.32.156    | recon      | high     | **86**     | firewall |
| 198.199.83.42   | recon      | medium   | 62         | firewall |
| 192.241.175.65  | anomaly    | medium   | 45         | auth     |
| 45.33.32.156    | anomaly    | medium   | 29         | firewall |

All three injected attacker IPs were flagged. The top-scoring alert correctly
identified 45.33.32.156 as a port-scan (`port_entropy = 4.39`, equivalent to
≈21 distinct destination ports per window), and the heuristic event-type
classifier mapped it to *recon*. The source-attribution layer added in Week 11
(replacing the earlier `source="unknown"` artifact) now correctly attributes
two alerts to firewall, one to auth, and resolves the per-source metric
limitation that was previously open.

## 5.6 Limitations

**L1 — Feature-domain transferability.** The CICIDS2017 results in Table 2
demonstrate that models trained on application/auth/firewall log features do
not transfer well to pure network-flow data without retraining. Future work
will extend the FeatureExtractor with flow-native fields (packet inter-arrival
time, flow duration, byte ratios) so that a single model can score both log
and flow inputs.

**L2 — Label scarcity in production.** Real university logs do not include
ground-truth attack labels, so per-source precision and recall on production
data cannot be measured directly. We rely on synthetic injections as a proxy
and qualitative analyst review for true-positive validation.

**L3 — Synthetic training data coverage.** The current training corpus
includes three attack patterns (port-scan, credential-stuffing, brute-force).
Less common patterns (lateral movement, low-and-slow exfiltration, supply
chain compromise) are not represented and would benefit from additional
synthetic generation or labeled real incidents.

**L4 — Fluentbit → PostgreSQL gap.** Production log collection currently
forwards to Loki only. PostgreSQL ingestion still requires the
`scripts/load_normalized_to_db.py` batch loader. A unified Fluentbit pipeline
writing to both stores is planned for the deployment milestone.
