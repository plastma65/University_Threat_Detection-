from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.core.security import require_roles
from src.api.database import get_db
from src.api.models.alert import AlertDB
from src.api.schemas import EventTypePoint, StatsOverview, TimelinePoint


router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/overview", response_model=StatsOverview)
def stats_overview(
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst"])),
):
    total_alerts = db.query(func.count(AlertDB.id)).scalar() or 0
    high_severity_alerts = (
        db.query(func.count(AlertDB.id)).filter(AlertDB.severity.in_(["high", "critical"])).scalar() or 0
    )
    return StatsOverview(total_alerts=total_alerts, high_severity_alerts=high_severity_alerts)


@router.get("/timeline", response_model=list[TimelinePoint])
def stats_timeline(
    bucket: str = Query(default="hour", pattern="^(hour|day|week)$"),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst"])),
):
    rows = (
        db.query(
            func.date_trunc(bucket, AlertDB.timestamp).label("bucket"),
            func.count(AlertDB.id).label("count"),
        )
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    return [TimelinePoint(bucket=row.bucket, count=row.count) for row in rows]


@router.get("/event-types", response_model=list[EventTypePoint])
def stats_by_event_type(
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst"])),
):
    rows = (
        db.query(AlertDB.event_type, func.count(AlertDB.id).label("count"))
        .group_by(AlertDB.event_type)
        .order_by(func.count(AlertDB.id).desc())
        .all()
    )
    return [EventTypePoint(event_type=row.event_type, count=row.count) for row in rows]
