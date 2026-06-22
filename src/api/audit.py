from typing import Any

from sqlalchemy.orm import Session

from src.api.models import AuditLogDB, UserDB


def record_audit_log(
    db: Session,
    actor: UserDB,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLogDB(
            actor_username=actor.username,
            actor_role=actor.role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )
