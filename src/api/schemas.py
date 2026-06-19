from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


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
    created_at: datetime


class StatsOverview(BaseModel):
    total_alerts: int
    high_severity_alerts: int


class TimelinePoint(BaseModel):
    bucket: datetime
    count: int


class EventTypePoint(BaseModel):
    event_type: str
    count: int
