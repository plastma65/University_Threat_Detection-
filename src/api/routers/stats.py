from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.core.security import require_roles
from src.api.database import get_db
from src.api.models.alert import AlertDB
from src.api.routers.utils import hours_cutoff
from src.api.schemas import EventTypePoint, SeverityPoint, StatsOverview, TimelinePoint, TopIpPoint


router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/overview", response_model=StatsOverview)
def stats_overview(
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    cutoff = hours_cutoff(hours)
    query = db.query(AlertDB)
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)

    total_alerts = query.with_entities(func.count(AlertDB.id)).scalar() or 0
    high_severity_alerts = (
        query.filter(AlertDB.severity.in_(["high", "critical"])).with_entities(func.count(AlertDB.id)).scalar() or 0
    )
    return StatsOverview(total_alerts=total_alerts, high_severity_alerts=high_severity_alerts)


@router.get("/timeline", response_model=list[TimelinePoint])
def stats_timeline(
    bucket: str = Query(default="hour", pattern="^(hour|day|week)$"),
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    cutoff = hours_cutoff(hours)
    bucket_expression = (
        func.strftime(
            "%Y-%m-%d %H:00:00" if bucket == "hour" else "%Y-%m-%d 00:00:00",
            AlertDB.timestamp,
        )
        if db.bind and db.bind.dialect.name == "sqlite"
        else func.date_trunc(bucket, AlertDB.timestamp)
    )

    query = db.query(
        bucket_expression.label("bucket"),
        func.count(AlertDB.id).label("count"),
    )
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)

    rows = query.group_by("bucket").order_by("bucket").all()
    return [TimelinePoint(bucket=row.bucket, count=row.count) for row in rows]


@router.get("/event-types", response_model=list[EventTypePoint])
def stats_by_event_type(
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    cutoff = hours_cutoff(hours)
    query = db.query(AlertDB.event_type, func.count(AlertDB.id).label("count"))
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)
    rows = query.group_by(AlertDB.event_type).order_by(func.count(AlertDB.id).desc()).all()
    return [EventTypePoint(event_type=row.event_type, count=row.count) for row in rows]


@router.get("/top-ips", response_model=list[TopIpPoint])
def stats_top_ips(
    limit: int = Query(default=10, ge=1, le=100),
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    cutoff = hours_cutoff(hours)
    query = (
        db.query(
            AlertDB.ip_address.label("ip_address"),
            func.max(AlertDB.risk_score).label("max_risk"),
            func.count(AlertDB.id).label("alert_count"),
        )
        .filter(AlertDB.ip_address.isnot(None))
        .filter(AlertDB.ip_address != "")
    )
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)
    rows = query.group_by(AlertDB.ip_address).order_by(
        func.max(AlertDB.risk_score).desc(),
        func.count(AlertDB.id).desc(),
    ).limit(limit).all()
    return [
        TopIpPoint(ip_address=row.ip_address, max_risk=row.max_risk, alert_count=row.alert_count)
        for row in rows
    ]


@router.get("/severity-distribution", response_model=list[SeverityPoint])
def stats_severity_distribution(
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    cutoff = hours_cutoff(hours)
    query = db.query(AlertDB.severity, func.count(AlertDB.id).label("count"))
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)
    rows = query.group_by(AlertDB.severity).order_by(func.count(AlertDB.id).desc()).all()
    return [SeverityPoint(severity=row.severity, count=row.count) for row in rows]
