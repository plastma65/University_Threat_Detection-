from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.audit import record_audit_log
from src.api.core.security import require_roles
from src.api.database import get_db
from src.api.models.alert import AlertDB
from src.api.models.user import UserDB
from src.api.routers.utils import hours_cutoff
from src.api.schemas import AlertCreate, AlertResponse, AlertTriageUpdate


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    severity: str | None = Query(default=None),
    hours: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user=Depends(require_roles(["admin", "analyst", "viewer"])),
):
    query = db.query(AlertDB)
    cutoff = hours_cutoff(hours)
    if cutoff is not None:
        query = query.filter(AlertDB.timestamp >= cutoff)
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


@router.patch("/{alert_id}/triage", response_model=AlertResponse)
def update_alert_triage(
    alert_id: int,
    payload: AlertTriageUpdate,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin", "analyst"])),
):
    alert = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    old_status = alert.status
    status_changed = old_status != payload.status

    alert.status = payload.status
    alert.triage_note = payload.triage_note
    if not alert.assigned_to or status_changed:
        alert.assigned_to = current_user.username
    alert.updated_at = datetime.now(timezone.utc)

    record_audit_log(
        db,
        actor=current_user,
        action="alert_triage_update",
        target_type="alert",
        target_id=str(alert.id),
        details={
            "old_status": old_status,
            "new_status": alert.status,
            "assigned_to": alert.assigned_to,
            "triage_note": alert.triage_note,
        },
    )

    db.commit()
    db.refresh(alert)
    return alert
