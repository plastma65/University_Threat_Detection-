"""Bulk-load normalized parquet logs into the `normalized_logs` Postgres table.

Why this exists
---------------
Fluentbit currently forwards logs only to Loki, not to Postgres. The
`inference_job.fetch_recent_logs()` query against `normalized_logs` therefore
returns 0 rows in production, so the background ML loop never sees real data.

This loader closes that gap for Week 9 demo / evaluation:

    parquet (data/processed/*.parquet)  ─►  normalized_logs (Postgres)
                                                 │
                                                 ▼
                                       inference_job.run_inference_job()
                                                 │
                                                 ▼
                                          alerts table  ─►  Grafana

Usage
-----
    # Load 5000 rows from all sources, shift timestamps to last 15 minutes
    python scripts/load_normalized_to_db.py

    # Load specific source, custom limit
    python scripts/load_normalized_to_db.py --source auth --limit 10000

    # Clear table first (fresh start)
    python scripts/load_normalized_to_db.py --truncate

    # Keep original timestamps (won't be picked up by inference_job's 15-min window)
    python scripts/load_normalized_to_db.py --no-shift
"""

from __future__ import annotations

import argparse
import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from src.api.database import engine
from src.normalizer.db import Base, NormalizedLogDB


ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = ROOT / "data" / "processed"
CICIDS_PATH = (
    ROOT / "data" / "raw" / "benchmarks" / "cicids2017"
    / "Network-Flows" / "normalized_cicids2017-flow.parquet"
)

SOURCE_FILES = {
    "auth": "normalized_auth.parquet",
    "nginx": "normalized_nginx.parquet",
    "firewall": "normalized_firewall.parquet",
    "firewall_realworld": "normalized_firewall_realworld.parquet",
    "secrepo_auth": "normalized_secrepo_auth.parquet",
    "unsw_nb15": "normalized_unsw-nb15.parquet",
    "web_scanner": "normalized_web_scanner.parquet",
    "cicids2017": None,  # special-case: see _load_cicids_df()
}


def _load_cicids_df(limit: int) -> pd.DataFrame:
    """Load + transform CICIDS2017 flows into the standard normalized schema.

    Steps:
      1. Read 2.83M-row parquet
      2. Filter to normal + port_scan + ddos (3 classes with port info)
      3. Stratified sample down to `limit` rows
      4. Re-label source -> "firewall" so extract_from_firewall picks them up
      5. Flatten metadata.Connection_Info.destination_port -> top-level dst_port
    """
    if not CICIDS_PATH.exists():
        raise FileNotFoundError(f"CICIDS parquet missing: {CICIDS_PATH}")

    df = pd.read_parquet(CICIDS_PATH)
    # Only port_scan carries signal for extract_from_firewall (diverse dst_port
    # → high port_entropy). DDoS targets one port → entropy=0 → no anomaly.
    keep_classes = ["normal", "port_scan"]
    df = df[df["event_type"].isin(keep_classes)].copy()

    if len(df) > limit:
        per_class = max(1, limit // len(keep_classes))
        parts = [
            df[df["event_type"] == cls].sample(
                n=min(len(df[df["event_type"] == cls]), per_class),
                random_state=42,
            )
            for cls in keep_classes
        ]
        df = pd.concat(parts, ignore_index=True)

    # Shuffle so port_scan + normal records interleave when we assign synthetic
    # timestamps below (otherwise concat order makes one class dominate the
    # tail of the timeline and only that class lands in the inference window).
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    df["source"] = "firewall"

    def _flatten(meta_raw) -> str:
        try:
            md = json.loads(meta_raw) if isinstance(meta_raw, str) else (meta_raw or {})
            port = md.get("Connection_Info", {}).get("destination_port", "")
            return str({"dst_port": str(port)})
        except (ValueError, TypeError):
            return "{}"

    df["metadata"] = df["metadata"].apply(_flatten)

    # Override timestamps: spread evenly across the last 14 min so every record
    # falls inside the inference job's 15-min recent window. CICIDS original
    # timestamps span ~7 days in 2017, which would scatter records across the
    # past week after the standard shift and starve the inference window.
    now = datetime.now(timezone.utc)
    n = len(df)
    synth = pd.date_range(
        end=now, periods=n, freq=pd.Timedelta(seconds=max(1, int(14 * 60 / n)))
    )
    df["timestamp"] = synth.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return df


def _parse_metadata(raw: object) -> dict:
    """Parquet stores metadata as a Python-repr string; convert to dict."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = ast.literal_eval(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, SyntaxError):
        return {}


def _shift_timestamps_to_now(timestamps: pd.Series) -> pd.Series:
    """Shift the series so its max value lands at "now", preserving spacing.

    inference_job.fetch_recent_logs() filters by `timestamp >= now - 15min`,
    so original Jan-2026 timestamps would never match. We slide the entire
    window so the most recent record is "now" and the rest stay relatively
    spaced — this keeps per-(ip, window) clustering intact for feature
    extraction.
    """
    parsed = pd.to_datetime(timestamps, utc=True, errors="coerce")
    valid = parsed.dropna()
    if valid.empty:
        return timestamps
    delta = datetime.now(timezone.utc) - valid.max().to_pydatetime()
    shifted = parsed + delta
    return shifted.dt.strftime("%Y-%m-%dT%H:%M:%S%z").str.replace(
        r"(\d{2})(\d{2})$", r"\1:\2", regex=True
    )


def load_source(
    session: Session,
    source_key: str,
    limit: int,
    shift: bool,
) -> int:
    """Load up to `limit` rows from one parquet file. Returns rows inserted."""
    if source_key == "cicids2017":
        try:
            df = _load_cicids_df(limit)
        except FileNotFoundError as exc:
            print(f"  [skip] cicids2017 — {exc}")
            return 0
        display_name = "cicids2017 (subset, source=firewall)"
    else:
        parquet_path = PROCESSED_DIR / SOURCE_FILES[source_key]
        if not parquet_path.exists():
            print(f"  [skip] {parquet_path.name} — file missing")
            return 0
        df = pd.read_parquet(parquet_path)
        display_name = parquet_path.name

    if len(df) == 0:
        print(f"  [skip] {display_name} — empty")
        return 0

    # Sample the tail (most recent records) to keep window clustering tight.
    # CICIDS already pre-sampled in _load_cicids_df, so skip the tail-trim.
    if source_key != "cicids2017" and len(df) > limit:
        df = df.tail(limit).copy()
    else:
        df = df.copy()

    # Drop rows with no IP — inference can't bucket them.
    df = df[df["ip"].notna() & (df["ip"].astype(str).str.len() > 0)]
    if df.empty:
        print(f"  [skip] {parquet_path.name} — no rows with ip")
        return 0

    # CICIDS already received synthetic recent timestamps in _load_cicids_df;
    # don't re-shift or we'd undo the per-record spread.
    if shift and source_key != "cicids2017":
        df["timestamp"] = _shift_timestamps_to_now(df["timestamp"])

    records = [
        {
            "log_id": str(row["log_id"]),
            "timestamp": str(row["timestamp"]),
            "source": str(row["source"]),
            "ip": str(row["ip"]) if pd.notna(row["ip"]) else None,
            "user": str(row["user"]) if pd.notna(row["user"]) else None,
            "event_type": str(row["event_type"]),
            "raw": str(row["raw"])[:5000],
            "log_metadata": _parse_metadata(row.get("metadata")),
        }
        for _, row in df.iterrows()
    ]

    # ON CONFLICT DO NOTHING — log_id is PK, idempotent re-runs.
    stmt = pg_insert(NormalizedLogDB).values(records)
    stmt = stmt.on_conflict_do_nothing(index_elements=["log_id"])
    result = session.execute(stmt)
    session.commit()

    inserted = result.rowcount if result.rowcount is not None else len(records)
    print(f"  [ok]   {display_name:42} {len(records):>6} rows queued, "
          f"{inserted:>6} inserted")
    return inserted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--source", default="all",
                        choices=["all", *SOURCE_FILES.keys()],
                        help="Which parquet file to load (default: all)")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max rows per source (default: 5000)")
    parser.add_argument("--truncate", action="store_true",
                        help="Truncate normalized_logs before loading")
    parser.add_argument("--no-shift", action="store_true",
                        help="Keep original timestamps (default: shift to now)")
    args = parser.parse_args()

    # Make sure the table exists (idempotent if API already provisioned it).
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        if args.truncate:
            print("[truncate] Clearing normalized_logs ...")
            session.execute(text("TRUNCATE TABLE normalized_logs;"))
            session.commit()

        before = session.execute(
            text("SELECT COUNT(*) FROM normalized_logs;")
        ).scalar_one()
        print(f"[before] normalized_logs has {before:,} rows")

        sources = list(SOURCE_FILES.keys()) if args.source == "all" else [args.source]
        print(f"[load] {len(sources)} source(s), limit={args.limit}, "
              f"shift_to_now={not args.no_shift}")

        total = 0
        for src in sources:
            total += load_source(session, src, args.limit, shift=not args.no_shift)

        after = session.execute(
            text("SELECT COUNT(*) FROM normalized_logs;")
        ).scalar_one()
        print(f"[after]  normalized_logs has {after:,} rows "
              f"(+{after - before:,} this run, {total} insert attempts)")

        # Show recent-window summary so user can confirm inference will pick them up.
        # Match the exact filter inference_job uses: ISO8601 string with 'T' separator.
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        recent = session.execute(
            text("""
                SELECT source, COUNT(*) AS n,
                       MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts
                FROM normalized_logs
                WHERE timestamp >= :cutoff
                GROUP BY source
                ORDER BY n DESC;
            """),
            {"cutoff": cutoff_iso},
        ).all()
        print()
        print("[recent-15min] rows visible to inference_job:")
        if not recent:
            print("  (none — inference_job will produce 0 alerts)")
        else:
            for row in recent:
                print(f"  {row.source:25} {row.n:>6} rows  "
                      f"[{row.first_ts} .. {row.last_ts}]")


if __name__ == "__main__":
    main()
