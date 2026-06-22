from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.core.security import require_roles
from src.api.database import get_db
from src.api.models import UserDB
from src.api.schemas import DashboardSettingsResponse
from src.api.settings_store import get_dashboard_settings


router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/dashboard", response_model=DashboardSettingsResponse)
def read_dashboard_settings(
    db: Session = Depends(get_db),
    _user: UserDB = Depends(require_roles(["admin", "analyst", "viewer"])),
):
    return get_dashboard_settings(db)
