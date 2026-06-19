"""Export parquet samples + summary statistics to CSV/Excel for review.

Outputs:
    data/exports/sample_*.csv               — first 500 rows of each dataset
    data/exports/dataset_summary.xlsx       — multi-sheet Excel: counts, distributions, samples
"""

from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"
FEATURES = ROOT / "data" / "features"
EXPORTS = ROOT / "data" / "exports"
EXPORTS.mkdir(parents=True, exist_ok=True)


PARQUET_SOURCES = [
    ("normalized_auth", PROCESSED / "normalized_auth.parquet"),
    ("normalized_nginx", PROCESSED / "normalized_nginx.parquet"),
    ("normalized_firewall", PROCESSED / "normalized_firewall.parquet"),
    ("normalized_firewall_realworld", PROCESSED / "normalized_firewall_realworld.parquet"),
    ("normalized_secrepo_auth", PROCESSED / "normalized_secrepo_auth.parquet"),
    ("normalized_unsw_nb15", PROCESSED / "normalized_unsw-nb15.parquet"),
    ("normalized_web_scanner", PROCESSED / "normalized_web_scanner.parquet"),
    ("normalized_cicids2017", ROOT / "data" / "raw" / "benchmarks" / "cicids2017"
                                  / "Network-Flows" / "normalized_cicids2017-flow.parquet"),
    ("features_5min", FEATURES / "features_5min.parquet"),
    ("features_15min", FEATURES / "features_15min.parquet"),
]


def export_csv_samples(n: int = 500) -> dict:
    """Write first N rows of each parquet to CSV. Return stats dict."""
    stats = {}
    for name, path in PARQUET_SOURCES:
        if not path.exists():
            print(f"[skip] {path.name} missing")
            continue
        df = pd.read_parquet(path)
        sample = df.head(n)
        csv_path = EXPORTS / f"sample_{name}.csv"
        sample.to_csv(csv_path, index=False, encoding="utf-8-sig")
        stats[name] = {
            "total_rows": len(df),
            "sample_rows": len(sample),
            "columns": list(df.columns),
            "csv_path": str(csv_path.relative_to(ROOT)),
        }
        print(f"[ok] {name:35} {len(df):>10,} total -> "
              f"{len(sample)} rows -> {csv_path.name}")
    return stats


def build_summary_xlsx(stats: dict) -> Path:
    """Multi-sheet Excel: 1 overview, 1 per source with distributions."""
    xlsx_path = EXPORTS / "dataset_summary.xlsx"
    with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:

        # Sheet 1 — Overview
        overview = pd.DataFrame([
            {
                "dataset": name,
                "total_rows": s["total_rows"],
                "n_columns": len(s["columns"]),
                "csv_sample": s["csv_path"],
                "columns": ", ".join(s["columns"]),
            }
            for name, s in stats.items()
        ])
        overview.to_excel(writer, sheet_name="overview", index=False)

        # Per-source sheets with key distributions
        for name, path in PARQUET_SOURCES:
            if not path.exists() or name.startswith("features"):
                continue
            df = pd.read_parquet(path)

            sheet_rows = []
            sheet_rows.append({"metric": "total_rows", "value": len(df)})
            sheet_rows.append({"metric": "unique_ips",
                               "value": df["ip"].nunique() if "ip" in df.columns else 0})
            sheet_rows.append({"metric": "unique_users",
                               "value": df["user"].nunique() if "user" in df.columns else 0})
            sheet_rows.append({"metric": "date_min",
                               "value": str(df["timestamp"].min())})
            sheet_rows.append({"metric": "date_max",
                               "value": str(df["timestamp"].max())})

            if "event_type" in df.columns:
                for et, count in df["event_type"].value_counts().head(10).items():
                    sheet_rows.append({"metric": f"event_type:{et}", "value": int(count)})

            if "source" in df.columns:
                for s, count in df["source"].value_counts().head(5).items():
                    sheet_rows.append({"metric": f"source:{s}", "value": int(count)})

            sheet = name[:30]  # Excel sheet name 31-char limit
            pd.DataFrame(sheet_rows).to_excel(writer, sheet_name=sheet, index=False)

        # Features summary
        for name, path in [("features_5min", FEATURES / "features_5min.parquet"),
                           ("features_15min", FEATURES / "features_15min.parquet")]:
            if not path.exists():
                continue
            df = pd.read_parquet(path)
            numeric = df.select_dtypes(include="number")
            desc = numeric.describe().T.reset_index()
            desc.rename(columns={"index": "feature"}, inplace=True)
            desc.to_excel(writer, sheet_name=name[:30], index=False)

    print(f"\n[xlsx] {xlsx_path}")
    return xlsx_path


def main() -> None:
    print(f"Exporting to: {EXPORTS}\n")
    stats = export_csv_samples(n=500)
    build_summary_xlsx(stats)
    print(f"\nDone. {len(stats)} CSV files + 1 Excel summary in data/exports/")


if __name__ == "__main__":
    main()
