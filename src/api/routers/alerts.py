from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.core.security import require_roles
from src.api.database import get_db
from src.api.models.alert import AlertDB
from src.api.schemas import AlertCreate, AlertResponse


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    severity: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst"])),
):
    query = db.query(AlertDB)
    if severity:
        query = query.filter(AlertDB.severity == severity)
    return query.order_by(AlertDB.timestamp.desc()).limit(limit).all()


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst"])),
):
    try:
        parsed_ts = datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ISO8601 timestamp") from exc

    record = AlertDB(
        timestamp=parsed_ts,
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity,
        ip_address=payload.ip_address,
        user_identifier=payload.user_identifier,
        evidence=payload.evidence,
        risk_score=payload.risk_score,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
