import argparse
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.database import engine
from src.api.models.alert import AlertDB
from src.normalizer.db import Base


ATTACKERS = [
    {
        "ip": "45.33.32.156",
        "source_hint": "full_attack",
        "event_types": ["bruteforce", "sql_injection", "privilege_escalation", "rate_limit"],
        "login_fail_range": (70, 120),
        "request_rate_range": (180.0, 320.0),
        "port_entropy_range": (6.0, 8.5),
    },
    {
        "ip": "192.241.175.65",
        "source_hint": "ssh_web_attack",
        "event_types": ["bruteforce", "login_failure", "rate_limit"],
        "login_fail_range": (55, 100),
        "request_rate_range": (130.0, 260.0),
        "port_entropy_range": (4.8, 7.2),
    },
    {
        "ip": "185.220.101.45",
        "source_hint": "web_fw_attack",
        "event_types": ["sql_injection", "rate_limit", "privilege_escalation"],
        "login_fail_range": (35, 80),
        "request_rate_range": (120.0, 240.0),
        "port_entropy_range": (4.2, 7.0),
    },
    {
        "ip": "198.199.83.42",
        "source_hint": "recon_attack",
        "event_types": ["port_scan", "recon", "rate_limit"],
        "login_fail_range": (10, 45),
        "request_rate_range": (90.0, 180.0),
        "port_entropy_range": (7.2, 9.2),
    },
    {
        "ip": "117.21.191.136",
        "source_hint": "pure_ssh_attack",
        "event_types": ["bruteforce", "login_failure"],
        "login_fail_range": (65, 115),
        "request_rate_range": (70.0, 160.0),
        "port_entropy_range": (3.8, 6.2),
    },
]


def _random_timestamp_within_last_24h(now: datetime) -> datetime:
    return now - timedelta(seconds=random.randint(0, 24 * 60 * 60))


def _build_attacker_alert(now: datetime, attacker: dict) -> AlertDB:
    return AlertDB(
        timestamp=_random_timestamp_within_last_24h(now),
        source=random.choice(["nginx", "auth", "firewall", "fastapi"]),
        event_type=random.choice(attacker["event_types"]),
        severity=random.choice(["high", "critical"]),
        ip_address=attacker["ip"],
        user_identifier=f"target_user_{random.randint(1, 25)}",
        evidence={
            "model_triggered": "IsolationForest",
            "login_fail_count": random.randint(*attacker["login_fail_range"]),
            "request_rate": round(random.uniform(*attacker["request_rate_range"]), 2),
            "port_entropy": round(random.uniform(*attacker["port_entropy_range"]), 2),
            "profile": attacker["source_hint"],
        },
        risk_score=random.randint(80, 100),
    )


def _build_normal_alert(now: datetime) -> AlertDB:
    return AlertDB(
        timestamp=_random_timestamp_within_last_24h(now),
        source=random.choice(["nginx", "auth", "firewall", "fastapi"]),
        event_type=random.choice(["login_success", "normal_request", "scheduled_job", "healthcheck"]),
        severity=random.choice(["low", "medium"]),
        ip_address=f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
        user_identifier=f"user_{random.randint(1, 50)}",
        evidence={
            "model_triggered": "None",
            "login_fail_count": random.randint(0, 5),
            "request_rate": round(random.uniform(1.0, 50.0), 2),
            "port_entropy": round(random.uniform(1.0, 3.8), 2),
        },
        risk_score=random.randint(10, 45),
    )


def main(force: bool = False, min_rows: int = 50, batch_size: int = 60, reset: bool = False) -> None:
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        if reset:
            deleted = session.query(AlertDB).delete()
            session.commit()
            print(f"Reset alerts table: deleted {deleted} rows")

        existing = session.query(func.count(AlertDB.id)).scalar() or 0
        if existing >= min_rows and not force and not reset:
            print(f"Skipped seeding: existing alerts={existing} (>= {min_rows})")
            return

        rows: list[AlertDB] = []
        now = datetime.now(timezone.utc)

        for attacker in ATTACKERS:
            for _ in range(random.randint(15, 20)):
                rows.append(_build_attacker_alert(now, attacker))

        normal_count = random.randint(50, 70)
        for _ in range(normal_count):
            rows.append(_build_normal_alert(now))

        random.shuffle(rows)
        session.add_all(rows)
        session.commit()
        print(
            f"Inserted {len(rows)} alerts: "
            f"attacker={len(rows)-normal_count}, normal={normal_count}"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate mock alerts for dashboard testing.")
    parser.add_argument("--force", action="store_true", help="Insert new alerts even when threshold already met.")
    parser.add_argument("--min-rows", type=int, default=50, help="Skip seeding when alerts table already has this many rows.")
    parser.add_argument("--batch-size", type=int, default=60, help="Deprecated: kept for compatibility.")
    parser.add_argument("--reset", action="store_true", help="Delete existing alerts before inserting narrative-driven data.")
    args = parser.parse_args()
    main(force=args.force, min_rows=args.min_rows, batch_size=args.batch_size, reset=args.reset)
