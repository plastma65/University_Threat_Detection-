from __future__ import annotations

from copy import deepcopy

from sqlalchemy.orm import Session

from src.api.models import AppSettingDB


DASHBOARD_SETTINGS_KEY = "dashboard_preferences"
DASHBOARD_SETTINGS_DEFAULTS = {
    "poll_interval_seconds": 15,
    "default_time_range": "24",
}
ALLOWED_POLL_INTERVALS = {15, 30, 60}
ALLOWED_TIME_RANGES = {"1", "6", "24", "168", "all"}


def get_dashboard_settings(db: Session) -> dict:
    record = db.query(AppSettingDB).filter(AppSettingDB.key == DASHBOARD_SETTINGS_KEY).first()
    settings = deepcopy(DASHBOARD_SETTINGS_DEFAULTS)
    if record and isinstance(record.value, dict):
        settings.update(record.value)
    return settings


def update_dashboard_settings(db: Session, *, poll_interval_seconds: int, default_time_range: str) -> dict:
    record = db.query(AppSettingDB).filter(AppSettingDB.key == DASHBOARD_SETTINGS_KEY).first()
    payload = {
        "poll_interval_seconds": poll_interval_seconds,
        "default_time_range": default_time_range,
    }
    if record is None:
        record = AppSettingDB(key=DASHBOARD_SETTINGS_KEY, value=payload)
        db.add(record)
    else:
        record.value = payload
    db.flush()
    return payload
