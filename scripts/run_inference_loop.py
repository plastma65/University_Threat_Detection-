"""Run ML inference periodically and persist alerts.

Usage:
    python scripts/run_inference_loop.py             # default: every 15 minutes
    python scripts/run_inference_loop.py --interval 5   # every 5 minutes
    python scripts/run_inference_loop.py --once         # run once then exit
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

from src.ml_engine.inference_job import run_inference_job


def _run_cycle(minutes: int) -> None:
    start = datetime.now(timezone.utc)
    print(f"[{start.isoformat(timespec='seconds')}] cycle start (window={minutes}min)")
    try:
        inserted = run_inference_job(minutes=minutes)
    except Exception as exc:
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        print(f"  [error] {exc.__class__.__name__}: {exc}  ({duration:.2f}s)")
        return
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    print(f"  [ok] inserted={inserted} alerts in {duration:.2f}s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--interval", type=int, default=15,
                        help="Minutes between cycles (default: 15)")
    parser.add_argument("--once", action="store_true",
                        help="Run one cycle and exit (default: loop forever)")
    args = parser.parse_args()

    if args.once:
        _run_cycle(args.interval)
        return

    print(f"[loop] inference every {args.interval} min. Ctrl+C to stop.")
    try:
        while True:
            _run_cycle(args.interval)
            time.sleep(args.interval * 60)
    except KeyboardInterrupt:
        print("\n[loop] stopped by user")


if __name__ == "__main__":
    main()
