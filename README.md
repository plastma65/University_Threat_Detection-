## 📈 Roadmap (12 Weeks)
1.  **Weeks 1-4**: Log collection & Normalization ✅ **COMPLETED**
2.  **Weeks 5-8**: Feature extraction & ML Model training.
3.  **Weeks 9-12**: Risk scoring, Dashboarding & Paper writing.

## 👥 Contributors
*   **Tuấn Anh**: ML/AI Engine Lead & Lead Author.
*   **Khánh Duy**: Infrastructure, Backend & SOC Dashboard.

---



# AI-assisted Threat Detection using Multi-Source Log Analytics

[![Research Status](https://img.shields.io/badge/Research-In--Progress-orange)](#)
[![Target](https://img.shields.io/badge/Target-Q3--Publication-blue)](#)
[![License](https://img.shields.io/badge/License-Private-red)](#)

## 📌 Project Overview
This research focuses on developing an intelligent **SOC-lite framework** tailored for university IT infrastructures[cite: 1]. By leveraging Machine Learning (ML) on multi-source logs, the system provides real-time anomaly detection and risk scoring to enhance security monitoring in academic environments[cite: 1].

## 🚀 Key Features
*   **Multi-Source Log Ingestion**: Seamlessly collects logs from Nginx, SSH, PostgreSQL, and pfSense[cite: 1].
*   **Log Normalization**: Standardizes diverse log formats into a unified schema for efficient processing[cite: 1].
*   **AI-Powered Analytics**: Implements Unsupervised Learning models, including **Isolation Forest**, **Local Outlier Factor (LOF)**, and **One-class SVM**[cite: 1].
*   **Risk Scoring Engine**: Dynamically calculates threat levels based on anomaly scores and event severity[cite: 1].
*   **SOC-lite Dashboard**: Interactive visualization using **Grafana** for real-time monitoring and alert management[cite: 1].

## 🛠 Tech Stack
*   **Language**: Python 3.11+[cite: 1]
*   **Backend**: FastAPI[cite: 1]
*   **Database**: PostgreSQL[cite: 1]
*   **AI/ML**: Scikit-learn[cite: 1]
*   **Infrastructure**: Docker, Fluentbit, Grafana[cite: 1]

## 📁 Project Structure
```
University_Threat_Detection/
├── docs/
│   ├── HANDOFF_NORMALIZATION.md       # Normalization module handoff
│   ├── NORMALIZATION_STATUS_REPORT.md # Status report
│   └── DATA_SCHEMA_REFERENCE.md       # Complete schema documentation
├── src/
│   ├── normalizer/                     # ✅ Log normalization module (COMPLETED)
│   ├── collector/                     # (Pending)
│   ├── feature_engine/                # (Pending)
│   ├── ml_engine/                     # (Pending)
│   ├── risk_scorer/                   # (Pending)
│   └── api/                           # (Pending)
├── data/
│   ├── raw/                           # Raw log files
│   │   ├── benchmarks/
│   │   │   ├── cicids2017/            # CICIDS2017 dataset (2.8M rows normalized)
│   │   │   └── unsw-nb15/             # UNSW-NB15 dataset
│   │   ├── nginx-logs/                # Nginx logs
│   │   ├── firewall-logs/             # Firewall logs
│   │   └── secrepo-auth.log           # Auth logs
│   ├── processed/                     # Normalized logs
│   └── synthetic/                     # Synthetic attack data
└── tests/                             # Unit tests
```

## ✅ Current Status

### Completed (Weeks 1-4)
- **Log Normalization Module**: ✅ Full implementation
  - Unified Log Model (ULM) schema with Pydantic validation
  - 5 normalizers implemented: Nginx, Auth, Firewall, CICIDS2017, UNSW-NB15
  - CICIDS2017: 2,827,677 rows normalized with nested metadata structure (10 categories)
  - Streaming support for large files (chunk_size=10000)
  - Parquet export for efficient storage
  - Unit tests for all normalizers

### In Progress (Weeks 5-8)
- **Feature Extraction**: Next phase
- **ML Engine Training**: Next phase

### Pending (Weeks 9-12)
- Risk scoring engine
- Grafana dashboard
- Paper writing

## 📚 Documentation
- **Handoff Document**: `docs/HANDOFF_NORMALIZATION.md` - Complete guide for Tuan Anh
- **Status Report**: `docs/NORMALIZATION_STATUS_REPORT.md` - Detailed status and metrics
- **Schema Reference**: `docs/DATA_SCHEMA_REFERENCE.md` - Complete data schema documentation
- **Project Context**: `CLAUDE.md` - Claude AI context and guidelines
- **Roadmap**: `PROJECT_INSTRUCTIONS.md` - 12-week detailed roadmap

## 🚀 Quick Start

### Setup Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Normalization via CLI
```bash
# Normalize all real-world logs in raw directory
python src/manage.py normalize --input docs/docsNew/data/raw/realworld --no-db

# Check database/processing status
python src/manage.py db-status
```

### Run Normalization via Python
```python
from src.normalizer.pipeline import run_normalization, export_to_parquet

# Normalize logs
logs_by_source = run_normalization("data/raw/", "data/processed/")
output_files = export_to_parquet(logs_by_source, "data/processed/")
```

### Query Normalized Data
```python
import duckdb

# Query CICIDS2017 data
result = duckdb.sql("""
    SELECT * FROM 'data/raw/benchmarks/cicids2017/Network-Flows/normalized_cicids2017-flow.parquet'
    WHERE event_type = 'dos'
    LIMIT 100
""").df()
```

## 📊 Data Statistics

### CICIDS2017 Dataset
- **Original Size**: 353 MB
- **Normalized Size**: 2.4 GB
- **Rows**: 2,827,677
- **Processing Time**: ~1 hour
- **Metadata Structure**: Nested JSON with 10 categories (85 fields total)

### Supported Log Sources
- Nginx (Combined Log Format)
- Linux Auth (/var/log/auth.log)
- pfSense Firewall
- PostgreSQL
- FastAPI
- CICIDS2017 (Benchmark)
- UNSW-NB15 (Benchmark)
