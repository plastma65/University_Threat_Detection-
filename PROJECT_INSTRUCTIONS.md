# PROJECT INSTRUCTIONS
## AI-assisted Threat Detection — University Systems
**Dành cho:** Tuan Anh & team · Claude Pro + Claude Code  
**Cập nhật:** 2026-05-03

---

## 1. Mục tiêu & Phạm vi

Xây dựng hệ thống phát hiện mối đe dọa an ninh mạng cho môi trường đại học bằng cách:
- Thu thập và chuẩn hóa log từ nhiều nguồn dị thể (firewall, web, auth, db, api)
- Trích xuất features theo time-window (sliding window)
- Áp dụng ML unsupervised để phát hiện anomaly
- Tính risk score và hiển thị trên SOC-lite dashboard (Grafana)

**Không trong phạm vi (v1):** Real-time streaming dưới 1 giây, SOAR automation, online learning

---

## 2. Cách Dùng Claude Pro + Claude Code

### Trong Cowork (Claude Desktop) — dùng cho:
- Thiết kế kiến trúc, brainstorm
- Viết và review tài liệu, báo cáo, paper
- Phân tích dataset, giải thích kết quả
- Lập kế hoạch sprint / task breakdown

### Trong Claude Code (Terminal) — dùng cho:
```bash
cd C:\Users\Administrator\OneDrive\Desktop\University_Threat_Detection
claude   # Mở Claude Code trong thư mục project
```
Claude Code tự đọc `CLAUDE.md` → đã có đủ context!  
Dùng cho: viết code, debug, refactor, chạy tests, git commits

### Workflow kết hợp tối ưu:
```
1. Cowork: Thiết kế module mới (hỏi Claude, thống nhất approach)
2. Claude Code: Implement (/ trong terminal, tham chiếu CLAUDE.md)
3. Cowork: Review kết quả, chuẩn bị paper section
```

---

## 3. Roadmap Chi Tiết 12 Tuần

### PHASE 1: Foundation (Tuần 1–2) — Literature & Setup
**Tuần 1 — Literature Review:**
- [ ] Đọc ít nhất 10 paper liên quan (CICIDS, anomaly detection in logs, university security)
- [ ] Ghi chú gap analysis: điểm khác biệt của hệ thống này
- [ ] Tìm datasets benchmark: CICIDS2017, UNSW-NB15, KDD Cup 99
- [ ] Setup môi trường: Ubuntu VM hoặc WSL2, Python venv, Git repo

**Tuần 2 — Architecture Finalization:**
- [ ] Quyết định: **Loki vs Elasticsearch** (hỏi Tuan Anh)
- [ ] Setup Docker Compose cơ bản (PostgreSQL + Grafana)
- [ ] Tạo cấu trúc thư mục theo `CLAUDE.md`
- [ ] Viết ERD cho data model

---

### PHASE 2: Data Collection (Tuần 3–4)
**Tuần 3 — Log Parsers:**
- [ ] Parser cho Nginx access log (Combined Log Format)
- [ ] Parser cho Linux auth log (`/var/log/auth.log`, syslog)
- [ ] Parser cho pfSense firewall log
- [ ] Unit tests cho từng parser

**Tuần 4 — Fluentbit Pipeline:**
- [ ] Cài Fluentbit, viết config cho từng nguồn
- [ ] Forward vào Loki/ES + PostgreSQL metadata
- [ ] Test end-to-end với sample logs
- [ ] Parser cho FastAPI log + PostgreSQL log

**Key deliverable:** Pipeline chạy được với sample logs từ 3+ nguồn

---

### PHASE 3: Feature Engineering (Tuần 5–6)
**Tuần 5 — Feature Design:**
- [ ] Implement sliding window (configurable, mặc định 5 phút)
- [ ] Feature: `request_rate` (requests/window/IP)
- [ ] Feature: `login_fail_count` (failed auth attempts/window/IP)
- [ ] Feature: `ip_entropy` (Shannon entropy of IPs in window)
- [ ] Feature: `endpoint_frequency` (distribution of endpoints hit)

**Tuần 6 — EDA & Validation:**
- [ ] Jupyter notebook EDA trên real/synthetic logs
- [ ] Visualize feature distributions
- [ ] Detect và handle outliers trong features
- [ ] Normalize features (StandardScaler)

**Key deliverable:** `src/feature_engine/` module + EDA notebook

---

### PHASE 4: ML Models (Tuần 7–8)
**Tuần 7 — Baseline Models:**
- [ ] Implement Isolation Forest (`sklearn.ensemble.IsolationForest`)
- [ ] Implement LOF (`sklearn.neighbors.LocalOutlierFactor`)
- [ ] Implement One-Class SVM (`sklearn.svm.OneClassSVM`)
- [ ] Per-source training (model riêng cho mỗi log source)

**Tuần 8 — Ensemble & Evaluation:**
- [ ] Implement ensemble voting (majority / weighted average)
- [ ] Tạo synthetic attack dataset (SSH brute force, endpoint scan)
- [ ] Evaluate: Precision, Recall, F1, ROC-AUC
- [ ] So sánh per-source vs multi-source fusion
- [ ] Hyperparameter tuning (contamination, n_estimators)

**Key deliverable:** `src/ml_engine/` + evaluation notebook + metrics table

---

### PHASE 5: Risk Scoring & API (Tuần 9)
**Công thức risk score:**
```python
risk_score = (anomaly_score_normalized * 0.6) + (severity_weight * 0.3) + (source_weight * 0.1)

# severity_weight: brute force > scanning > single anomaly
# source_weight: firewall > auth > nginx > api > db
```
- [ ] Implement `RiskScorer` class
- [ ] Configurable thresholds per source
- [ ] Alert generation khi risk_score > threshold
- [ ] FastAPI endpoints: `/api/anomalies`, `/api/risk`, `/api/alerts`
- [ ] JWT auth cho API

**Key deliverable:** `src/risk_scorer/` + `src/api/` + API docs (Swagger)

---

### PHASE 6: Dashboard (Tuần 10)
- [ ] Grafana setup + PostgreSQL datasource
- [ ] Panel: Anomaly Timeline (time series)
- [ ] Panel: Top 10 Suspicious IPs (bar chart)
- [ ] Panel: Risk Score Heatmap (per source × time)
- [ ] Panel: Alert Feed (table với status)
- [ ] Panel: System Health (log pipeline status)
- [ ] Export dashboard JSON vào `src/dashboard/`

**Key deliverable:** Grafana dashboard hoạt động + screenshots cho paper

---

### PHASE 7: Evaluation (Tuần 11)
- [ ] Full experiment với 3 models × 5 log sources
- [ ] So sánh single-source vs multi-source
- [ ] False positive rate analysis
- [ ] Latency benchmarking (< 1 phút requirement)
- [ ] Ablation study: feature importance
- [ ] Viết Results section của paper

---

### PHASE 8: Paper Writing (Tuần 12)
**Cấu trúc paper (IEEE format khuyên dùng):**
1. Abstract
2. Introduction (problem, contributions)
3. Related Work
4. System Architecture
5. Feature Engineering
6. Anomaly Detection Models
7. Experimental Setup & Results
8. Discussion & Limitations
9. Conclusion & Future Work
10. References

- [ ] Hỏi Tuan Anh: target venue (workshop/conference/journal)?
- [ ] Draft toàn bộ paper
- [ ] Review + proofread
- [ ] Submit

---

## 4. Synthetic Attack Data Generation

Để evaluate models khi thiếu labeled data:

```python
# SSH Brute Force signature:
# - login_fail_count > 20 trong 5 phút
# - từ 1 IP cố định
# - target: nhiều usernames khác nhau

# Endpoint Scanning:
# - request_rate > 100 req/phút
# - endpoint_frequency: uniform distribution (scanner thử nhiều endpoint)
# - status_codes: nhiều 404

# Credential Stuffing:
# - login_fail_count > 50 trong 30 phút
# - từ nhiều IPs (distributed)
# - target: 1 username cố định
```

---

## 5. Benchmark Datasets (nếu thiếu real data)

| Dataset | Size | Attacks | Link |
|---------|------|---------|------|
| CICIDS2017 | 80GB | DoS, PortScan, BruteForce, Web | UNB |
| UNSW-NB15 | ~100MB features | 9 attack types | UNSW |
| KDD Cup 99 | Classic | DoS, Probe, R2L, U2R | UCI |

Dùng cho **supplementary evaluation** nếu real logs bị hạn chế privacy.

---

## 6. Privacy & Ethics

- Real logs phải được **ẩn danh hóa** trước khi dùng (hash IP, xóa username thật)
- Không commit log files thật lên Git
- Dataset thật: chỉ lưu trong `data/raw/` (gitignored)
- Paper: báo cáo rõ ethical considerations (IRB nếu cần)

---

## 7. Git Workflow

```bash
# Branch strategy
main          ← stable, paper-ready code
develop       ← integration branch
feat/week-3   ← weekly feature branches
feat/ml-iforest
fix/nginx-parser

# Commit convention
feat: add Nginx log parser
fix: handle malformed syslog timestamps  
data: add synthetic SSH brute force generator
model: tune IsolationForest contamination=0.05
docs: update architecture diagram
eval: add ROC-AUC comparison table
```

---

## 8. Environment Setup

```bash
# 1. Clone / init
git init University_Threat_Detection
cd University_Threat_Detection

# 2. Python environment
python3 -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate       # Windows

# 3. Core dependencies
pip install fastapi uvicorn sqlalchemy psycopg2-binary \
            scikit-learn pandas numpy scipy \
            python-jose[cryptography] passlib[bcrypt] \
            python-dotenv pydantic pytest httpx

# 4. Dev dependencies
pip install jupyter black isort mypy pytest-cov

# 5. Docker services
docker compose up -d   # PostgreSQL + Grafana + Loki/ES
```

---

## 9. Các Quyết Định Chưa Chốt (cần hỏi Tuan Anh)

| # | Quyết định | Options | Deadline |
|---|-----------|---------|----------|
| 1 | Log storage engine | **Loki** (nhẹ, label-based) vs **Elasticsearch** (mạnh, full-text) | Tuần 2 |
| 2 | Ensemble strategy | Majority voting vs Weighted average vs Stacking | Tuần 8 |
| 3 | Target publication venue | IEEE workshop / RIVF / journal | Tuần 2 |
| 4 | Real data source | Lab server logs vs request từ IT department? | Tuần 3 |
| 5 | Deployment mode | Docker Compose vs bare metal | Tuần 4 |

---

## 10. Quick Reference — Key Commands

```bash
# Run tests
pytest tests/ -v --cov=src

# Start dev server
uvicorn src.api.main:app --reload

# Run feature extraction
python -m src.feature_engine.pipeline --input data/raw/ --output data/processed/

# Train models
python -m src.ml_engine.train --features data/processed/features.csv

# Start dashboard
docker compose up grafana

# Claude Code (trong project folder)
claude
```
