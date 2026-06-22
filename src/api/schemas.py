from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    created_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=255)
    role: Literal["admin", "analyst", "viewer"]

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username is required")
        return normalized


class UserRoleUpdateRequest(BaseModel):
    role: Literal["admin", "analyst", "viewer"]


class UserPasswordUpdateRequest(BaseModel):
    password: str = Field(min_length=8, max_length=255)


class AlertCreate(BaseModel):
    timestamp: str
    source: str
    event_type: str
    severity: str
    ip_address: str | None = None
    user_identifier: str | None = None
    evidence: dict[str, Any]
    risk_score: int = 0


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    ip_address: str | None
    user_identifier: str | None
    evidence: dict[str, Any]
    risk_score: int
    status: str
    assigned_to: str | None
    triage_note: str | None
    updated_at: datetime | None
    created_at: datetime


class AlertTriageUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved", "false_positive"]
    triage_note: str | None = Field(default=None, max_length=1000)

    @field_validator("triage_note")
    @classmethod
    def normalize_triage_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class StatsOverview(BaseModel):
    total_alerts: int
    high_severity_alerts: int


class TimelinePoint(BaseModel):
    bucket: datetime
    count: int


class EventTypePoint(BaseModel):
    event_type: str
    count: int


class TopIpPoint(BaseModel):
    ip_address: str
    max_risk: int
    alert_count: int


class SeverityPoint(BaseModel):
    severity: str
    count: int


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor_username: str
    actor_role: str
    action: str
    target_type: str
    target_id: str
    details: dict[str, Any]


class DashboardSettingsResponse(BaseModel):
    poll_interval_seconds: Literal[15, 30, 60]
    default_time_range: Literal["1", "6", "24", "168", "all"]


class DashboardSettingsUpdateRequest(BaseModel):
    poll_interval_seconds: Literal[15, 30, 60]
    default_time_range: Literal["1", "6", "24", "168", "all"]
