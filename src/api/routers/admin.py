from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.api.audit import record_audit_log
from src.api.core.security import get_password_hash, require_roles
from src.api.database import get_db
from src.api.models import AuditLogDB, UserDB
from src.api.schemas import (
    AuditLogResponse,
    DashboardSettingsResponse,
    DashboardSettingsUpdateRequest,
    UserCreateRequest,
    UserPasswordUpdateRequest,
    UserResponse,
    UserRoleUpdateRequest,
)
from src.api.settings_store import get_dashboard_settings, update_dashboard_settings


router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_user_or_404(db: Session, user_id: int) -> UserDB:
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    _user: UserDB = Depends(require_roles(["admin"])),
):
    return db.query(UserDB).order_by(UserDB.username.asc()).all()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin"])),
):
    user = UserDB(
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
    )
    db.add(user)
    try:
        record_audit_log(
            db,
            actor=current_user,
            action="user_created",
            target_type="user",
            target_id=payload.username,
            details={"role": payload.role},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from exc

    db.refresh(user)
    return user


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin"])),
):
    user = get_user_or_404(db, user_id)
    if current_user.id == user_id and payload.role != "admin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current admin cannot demote itself")
    old_role = user.role
    user.role = payload.role
    record_audit_log(
        db,
        actor=current_user,
        action="user_role_updated",
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username, "old_role": old_role, "new_role": payload.role},
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def update_user_password(
    user_id: int,
    payload: UserPasswordUpdateRequest,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin"])),
):
    user = get_user_or_404(db, user_id)
    user.hashed_password = get_password_hash(payload.password)
    record_audit_log(
        db,
        actor=current_user,
        action="user_password_reset",
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username},
    )
    db.commit()


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin"])),
):
    user = get_user_or_404(db, user_id)
    if user.username == current_user.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current user cannot delete itself")

    record_audit_log(
        db,
        actor=current_user,
        action="user_deleted",
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username, "role": user.role},
    )
    db.delete(user)
    db.commit()


@router.get("/audit-logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: UserDB = Depends(require_roles(["admin"])),
):
    return db.query(AuditLogDB).order_by(AuditLogDB.timestamp.desc()).limit(limit).all()


@router.get("/dashboard-settings", response_model=DashboardSettingsResponse)
def read_admin_dashboard_settings(
    db: Session = Depends(get_db),
    _user: UserDB = Depends(require_roles(["admin"])),
):
    return get_dashboard_settings(db)


@router.put("/dashboard-settings", response_model=DashboardSettingsResponse)
def save_admin_dashboard_settings(
    payload: DashboardSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_roles(["admin"])),
):
    updated_settings = update_dashboard_settings(
        db,
        poll_interval_seconds=payload.poll_interval_seconds,
        default_time_range=payload.default_time_range,
    )
    record_audit_log(
        db,
        actor=current_user,
        action="dashboard_settings_updated",
        target_type="dashboard_settings",
        target_id="global",
        details=updated_settings,
    )
    db.commit()
    return updated_settings
